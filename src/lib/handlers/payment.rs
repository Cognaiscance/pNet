//! Offer, accept, refuse, confirm, repair, and settlement between the two writers.
//!
//! A node that is not the writer drops the packet. The purse id never leaves
//! the payer. What you'll run starts at zero, so an offer is refused until
//! one is stored for that payer. On connect, the writers exchange the payment
//! ids and the settlement ids they hold for the pair, and copy any missing record.
//! An app does not settle. The owner proposes, and the other owner signs.

use std::net::SocketAddr;

use super::super::action_queue::WorkerContext;
use super::super::crypto::{build_encrypted_packet, decrypt_packet_body};
use super::super::data_models::{
    Settlement, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, Charge, Node, Owner,
    Uuid, unix_time_ms,
};
use super::super::payment::{
    body_from_line, claim_exceeds_run, settlement_body_matches, settlement_body_ok, settlement_for_pair,
    decode_accept, decode_settlement_proposal, decode_settlement, decode_confirm, decode_index,
    decode_offer, decode_refuse, encode_accept, encode_settlement_proposal, encode_settlement,
    encode_confirm, encode_offer, encode_refuse, index_plaintexts, line_covers, line_from,
    line_same_payment, normalize_payment_ids, offer_body_ok, ordered_users, pending_covers,
    pending_from, sign_accept, sign_settlement, sign_confirm, sign_offer, sign_refuse, users_are_pair,
    verify_accept, verify_settlement, verify_confirm, verify_offer, verify_refuse, SettlementBody,
    OfferBody, INDEX_END, INDEX_START, REFUSE_EXPIRED, REFUSE_MISMATCH, REFUSE_OVER_RUN,
};
use super::super::wire::{
    SETTLEMENT_INDEX_OP, SETTLEMENT_RECORD_OP, PAYMENT_ACCEPT_OP, SETTLEMENT_ACK_OP, SETTLEMENT_PROPOSE_OP,
    PAYMENT_CONFIRM_OP, PAYMENT_INDEX_OP, PAYMENT_OFFER_OP, PAYMENT_RECORD_OP, PAYMENT_REFUSE_OP,
};
use super::{find_writer_sg, request_change_idempotent, send, Change, PaymentReject, WriteError, WriterTarget};

/// After a reserve reply, tell the contact or resend a confirmation.
pub(crate) fn deliver_payment(ctx: &WorkerContext, payment_id: Uuid) {
    let prepared = {
        let node = ctx.node.read().unwrap();
        if node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        if let Some(line) = node.owner.charges.iter().find(|line| line.payment_id == payment_id) {
            let body = body_from_line(line);
            let plain = encode_confirm(&body, &line.payer_sig, &line.payee_sig, &line.confirm_sig);
            Some((line.payee, PAYMENT_CONFIRM_OP, plain))
        } else if let Some(reserve) = node.owner.reserves.iter().find(|reserve| reserve.payment_id == payment_id) {
            let body = OfferBody::from_reserve(reserve, node.owner.user.uuid);
            let sig = sign_offer(&node.owner.key_pair.private_key, &body);
            let plain = encode_offer(&body, &sig);
            Some((reserve.contact_uuid, PAYMENT_OFFER_OP, plain))
        } else {
            None
        }
    };
    if let Some((user, op, plain)) = prepared {
        send_to_user(ctx, user, op, &plain);
    }
}

pub fn payment_offer(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((body, payer_sig)) = decode_offer(&plain) else {
        eprintln!("[payment_offer] bad offer from {src}");
        return;
    };
    if !offer_body_ok(&body) {
        return;
    }
    let decision = {
        let node = ctx.node.read().unwrap();
        if body.payee != node.owner.user.uuid {
            return;
        }
        let Some(contact) = node.owner.contact_users.iter().find(|contact| contact.user.uuid == body.payer) else {
            return;
        };
        if !contact.user.devices.iter().any(|candidate| candidate.uuid == device) {
            return;
        }
        if !verify_offer(&contact.public_key, &body, &payer_sig) {
            eprintln!("[payment_offer] bad signature from {src}");
            return;
        }
        if node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        if body.expires_at_ms <= unix_time_ms() {
            Reply::Refuse(REFUSE_EXPIRED)
        } else if let Some(line) = node.owner.charges.iter().find(|line| line.payment_id == body.payment_id) {
            if line_covers(line, &body, &payer_sig) {
                Reply::Accept(line.payee_sig)
            } else {
                Reply::Refuse(REFUSE_MISMATCH)
            }
        } else if let Some(pending) = node.owner.pending_accepts.iter().find(|pending| pending.payment_id == body.payment_id) {
            if pending_covers(pending, &body, &payer_sig) {
                Reply::Accept(pending.payee_sig)
            } else {
                Reply::Refuse(REFUSE_MISMATCH)
            }
        } else if claim_exceeds_run(&node.owner, body.payer, body.amount_nanodollars, Some(body.payment_id)) {
            Reply::Refuse(REFUSE_OVER_RUN)
        } else {
            Reply::Stage(sign_accept(&node.owner.key_pair.private_key, &body, &payer_sig))
        }
    };
    match decision {
        Reply::Accept(payee_sig) => {
            let plain = encode_accept(&body, &payer_sig, &payee_sig);
            send_to_user(ctx, body.payer, PAYMENT_ACCEPT_OP, &plain);
        }
        Reply::Refuse(reason) => send_refuse(ctx, &body, &payer_sig, reason),
        Reply::Stage(payee_sig) => {
            let pending = pending_from(&body, payer_sig, payee_sig);
            match request_change_idempotent(Change::StageAccept { pending: pending.clone() }, ctx) {
                Ok(()) => {
                    let sig = {
                        let node = ctx.node.read().unwrap();
                        node.owner.pending_accepts.iter()
                            .find(|stored| stored.payment_id == body.payment_id)
                            .map(|stored| stored.payee_sig)
                            .unwrap_or(payee_sig)
                    };
                    let plain = encode_accept(&body, &payer_sig, &sig);
                    send_to_user(ctx, body.payer, PAYMENT_ACCEPT_OP, &plain);
                }
                Err(WriteError::PaymentRejected(PaymentReject::OverCeiling)) => {
                    send_refuse(ctx, &body, &payer_sig, REFUSE_OVER_RUN);
                }
                Err(WriteError::PaymentRejected(PaymentReject::Mismatch)) => {
                    send_refuse(ctx, &body, &payer_sig, REFUSE_MISMATCH);
                }
                Err(err) => eprintln!("[payment_offer] stage failed from {src}: {err:?}"),
            }
        }
    }
}

pub fn payment_accept(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((body, payer_sig, payee_sig)) = decode_accept(&plain) else {
        eprintln!("[payment_accept] bad accept from {src}");
        return;
    };
    let confirm = {
        let node = ctx.node.read().unwrap();
        if body.payer != node.owner.user.uuid || node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        let Some(contact) = node.owner.contact_users.iter().find(|contact| contact.user.uuid == body.payee) else {
            return;
        };
        if !contact.user.devices.iter().any(|candidate| candidate.uuid == device) {
            return;
        }
        if !verify_offer(&node.owner.key_pair.public_key, &body, &payer_sig)
            || !verify_accept(&contact.public_key, &body, &payer_sig, &payee_sig)
        {
            eprintln!("[payment_accept] bad signature from {src}");
            return;
        }
        if let Some(line) = node.owner.charges.iter().find(|line| line.payment_id == body.payment_id) {
            if line_covers(line, &body, &payer_sig) {
                AcceptChoice::Resend
            } else {
                AcceptChoice::Ignore
            }
        } else if let Some(reserve) = node.owner.reserves.iter().find(|reserve| reserve.payment_id == body.payment_id) {
            if !body.matches_reserve(reserve, node.owner.user.uuid) || reserve.expires_at_ms <= unix_time_ms() {
                AcceptChoice::Ignore
            } else {
                let purse_id = reserve.purse_id;
                let confirm_sig = sign_confirm(&node.owner.key_pair.private_key, &body, &payer_sig, &payee_sig);
                AcceptChoice::Confirm(line_from(&body, purse_id, payer_sig, payee_sig, confirm_sig))
            }
        } else {
            AcceptChoice::Ignore
        }
    };
    let confirm = match confirm {
        AcceptChoice::Resend => return deliver_payment(ctx, body.payment_id),
        AcceptChoice::Ignore => return,
        AcceptChoice::Confirm(line) => line,
    };
    if request_change_idempotent(Change::RecordCharge { line: confirm.clone() }, ctx).is_err() {
        return;
    }
    let stored = {
        let node = ctx.node.read().unwrap();
        node.owner.charges.iter().any(|line| {
            line.payment_id == confirm.payment_id && line.confirm_sig == confirm.confirm_sig
        })
    };
    if stored {
        let plain = encode_confirm(&body, &confirm.payer_sig, &confirm.payee_sig, &confirm.confirm_sig);
        send_to_user(ctx, body.payee, PAYMENT_CONFIRM_OP, &plain);
    }
}

pub fn payment_refuse(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((body, payer_sig, reason, payee_sig)) = decode_refuse(&plain) else {
        eprintln!("[payment_refuse] bad refusal from {src}");
        return;
    };
    let payment_id = {
        let node = ctx.node.read().unwrap();
        if body.payer != node.owner.user.uuid {
            return;
        }
        let Some(contact) = node.owner.contact_users.iter().find(|contact| contact.user.uuid == body.payee) else {
            return;
        };
        if !contact.user.devices.iter().any(|candidate| candidate.uuid == device) {
            return;
        }
        if !verify_offer(&node.owner.key_pair.public_key, &body, &payer_sig)
            || !verify_refuse(&contact.public_key, &body, &payer_sig, reason, &payee_sig)
        {
            eprintln!("[payment_refuse] bad signature from {src}");
            return;
        }
        if node.owner.charges.iter().any(|line| line.payment_id == body.payment_id) {
            return;
        }
        let Some(reserve) = node.owner.reserves.iter().find(|reserve| reserve.payment_id == body.payment_id) else {
            return;
        };
        if !body.matches_reserve(reserve, node.owner.user.uuid) {
            return;
        }
        reserve.payment_id
    };
    if let Err(err) = request_change_idempotent(Change::ReleaseReserve { payment_id }, ctx) {
        eprintln!("[payment_refuse] release failed for {payment_id:?}: {err:?}");
    }
}

pub fn payment_confirm(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((body, payer_sig, payee_sig, confirm_sig)) = decode_confirm(&plain) else {
        eprintln!("[payment_confirm] bad confirmation from {src}");
        return;
    };
    let line = {
        let node = ctx.node.read().unwrap();
        if body.payee != node.owner.user.uuid {
            return;
        }
        let Some(contact) = node.owner.contact_users.iter().find(|contact| contact.user.uuid == body.payer) else {
            return;
        };
        if !contact.user.devices.iter().any(|candidate| candidate.uuid == device) {
            return;
        }
        if !verify_offer(&contact.public_key, &body, &payer_sig)
            || !verify_accept(&node.owner.key_pair.public_key, &body, &payer_sig, &payee_sig)
            || !verify_confirm(&contact.public_key, &body, &payer_sig, &payee_sig, &confirm_sig)
        {
            eprintln!("[payment_confirm] bad signature from {src}");
            return;
        }
        if let Some(stored) = node.owner.charges.iter().find(|line| line.payment_id == body.payment_id) {
            if line_covers(stored, &body, &payer_sig) && stored.confirm_sig == confirm_sig {
                return;
            }
            return;
        }
        line_from(&body, [0u8; 16], payer_sig, payee_sig, confirm_sig)
    };
    if let Err(err) = request_change_idempotent(Change::RecordCharge { line }, ctx) {
        eprintln!("[payment_confirm] record failed from {src}: {err:?}");
    }
}

enum Reply {
    Accept(Ed25519Signature),
    Refuse(u8),
    Stage(Ed25519Signature),
}

enum AcceptChoice {
    Resend,
    Ignore,
    Confirm(super::super::data_models::Charge),
}

fn send_refuse(ctx: &WorkerContext, body: &OfferBody, payer_sig: &Ed25519Signature, reason: u8) {
    let sig = {
        let node = ctx.node.read().unwrap();
        if node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        sign_refuse(&node.owner.key_pair.private_key, body, payer_sig, reason)
    };
    let plain = encode_refuse(body, payer_sig, reason, &sig);
    send_to_user(ctx, body.payer, PAYMENT_REFUSE_OP, &plain);
}

fn open_session(ctx: &WorkerContext, buf: &[u8]) -> Option<(Vec<u8>, Uuid, u16)> {
    if buf.len() < 2 {
        return None;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let node = ctx.node.read().unwrap();
    if !matches!(find_writer_sg(&node), WriterTarget::Local) {
        return None;
    }
    let plain = decrypt_packet_body(&node, buf)?;
    let device = node.owner.active_connections.get(&conn_id)?.device_uuid;
    Some((plain, device, conn_id))
}

/// When a session to a contact comes up, send the payment ids and settlement ids for that pair.
pub(crate) fn exchange_payment_records(conn_id: u16, ctx: &WorkerContext) {
    let outbound = {
        let node = ctx.node.read().unwrap();
        if !matches!(find_writer_sg(&node), WriterTarget::Local) {
            return;
        }
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            return;
        };
        let Some(contact) = contact_user_for_device(&node, conn.device_uuid) else {
            return;
        };
        let our = node.owner.user.uuid;
        let mut entries: Vec<(Uuid, Ed25519Signature)> = node
            .owner
            .charges
            .iter()
            .filter(|line| users_are_pair(line.payer, line.payee, our, contact))
            .map(|line| (line.payment_id, line.confirm_sig))
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.0.cmp(&right.1.0)));
        let mut settlements: Vec<(Uuid, Ed25519Signature)> = Vec::new();
        if let Some((lo, hi)) = ordered_users(our, contact) {
            settlements = node
                .owner
                .settlements
                .iter()
                .filter(|record| record.user_lo == lo && record.user_hi == hi)
                .map(|record| (record.settlement_id, record.sig_lo))
                .collect();
            settlements.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.0.cmp(&right.1.0)));
        }
        let dest = conn.peer_addr;
        let mut packets: Vec<Vec<u8>> = index_plaintexts(&entries)
            .into_iter()
            .map(|plain| build_encrypted_packet(PAYMENT_INDEX_OP, conn, &plain))
            .collect();
        packets.extend(index_plaintexts(&settlements).into_iter().map(|plain| {
            build_encrypted_packet(SETTLEMENT_INDEX_OP, conn, &plain)
        }));
        (dest, packets)
    };
    for packet in outbound.1 {
        send(ctx, outbound.0, &packet);
    }
}

/// The writer signs a settlement for `contact` and sends it. Tests and the contact
/// tab call this. There is no app opcode. A missing charge is not proposed.
/// A record this node already holds for the same body is sent again as the ack.
pub(crate) fn propose_settlement(ctx: &WorkerContext, contact: Uuid, settlement_id: Uuid, payment_ids: &[Uuid]) {
    let prepared = {
        let node = ctx.node.read().unwrap();
        if !matches!(find_writer_sg(&node), WriterTarget::Local) {
            return;
        }
        if node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        if !node.owner.contact_users.iter().any(|row| row.user.uuid == contact) {
            return;
        }
        let Some(ids) = normalize_payment_ids(payment_ids) else {
            return;
        };
        let Some((user_lo, user_hi)) = ordered_users(node.owner.user.uuid, contact) else {
            return;
        };
        if !ids.iter().all(|id| pair_has_line(&node.owner, contact, *id)) {
            return;
        }
        let body = SettlementBody { settlement_id, user_lo, user_hi, payment_ids: ids };
        if let Some(stored) = node.owner.settlements.iter().find(|record| settlement_body_matches(record, &body)) {
            Some((SETTLEMENT_ACK_OP, encode_settlement(stored)))
        } else {
            let sig = sign_settlement(&node.owner.key_pair.private_key, &body);
            Some((SETTLEMENT_PROPOSE_OP, encode_settlement_proposal(&body, &sig)))
        }
    };
    if let Some((op, plain)) = prepared {
        send_to_user(ctx, contact, op, &plain);
    }
}

pub fn settlement_propose(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((body, sig)) = decode_settlement_proposal(&plain) else {
        eprintln!("[settlement_propose] bad proposal from {src}");
        return;
    };
    if !settlement_body_ok(&body) {
        return;
    }
    let decision = {
        let node = ctx.node.read().unwrap();
        let Some(contact) = contact_user_for_device(&node, device) else {
            return;
        };
        if !settlement_for_pair(&body, node.owner.user.uuid, contact) {
            return;
        }
        let Some(row) = node.owner.contact_users.iter().find(|row| row.user.uuid == contact) else {
            return;
        };
        if node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        if !verify_settlement(&row.public_key, &body, &sig) {
            eprintln!("[settlement_propose] bad signature from {src}");
            return;
        }
        if let Some(stored) = node.owner.settlements.iter().find(|record| settlement_body_matches(record, &body)) {
            SettleChoice::Resend(encode_settlement(stored))
        } else if body.payment_ids.iter().all(|id| pair_has_line(&node.owner, contact, *id)) {
            let ours = sign_settlement(&node.owner.key_pair.private_key, &body);
            let (sig_lo, sig_hi) = if node.owner.user.uuid == body.user_lo {
                (ours, sig)
            } else {
                (sig, ours)
            };
            SettleChoice::Store(Settlement {
                settlement_id: body.settlement_id,
                user_lo: body.user_lo,
                user_hi: body.user_hi,
                payment_ids: body.payment_ids.clone(),
                sig_lo,
                sig_hi,
            })
        } else {
            SettleChoice::Wait
        }
    };
    match decision {
        SettleChoice::Wait => {}
        SettleChoice::Resend(plain) => send_to_user(ctx, peer_of_settlement(&body, ctx), SETTLEMENT_ACK_OP, &plain),
        SettleChoice::Store(record) => {
            if store_settlement(ctx, record.clone(), src) {
                let contact = other_user(&record, ctx);
                let plain = encode_settlement(&record);
                send_to_user(ctx, contact, SETTLEMENT_ACK_OP, &plain);
            }
        }
    }
}

pub fn settlement_ack(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    accept_signed_settlement(src, buf, ctx, "settlement_ack");
}

pub fn settlement_index(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, conn_id)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((flags, entries)) = decode_index(&plain) else {
        eprintln!("[settlement_index] bad index from {src}");
        return;
    };
    let replies = {
        let mut node = ctx.node.write().unwrap();
        let Some(contact) = contact_user_for_device(&node, device) else {
            return;
        };
        let Some((lo, hi)) = ordered_users(node.owner.user.uuid, contact) else {
            return;
        };
        let finished = {
            let slot = node.owner.settlement_index.entry(contact).or_default();
            if (flags & INDEX_START) != 0 {
                slot.open = true;
                slot.seen.clear();
            }
            if !slot.open {
                None
            } else {
                slot.seen.extend(entries);
                if (flags & INDEX_END) == 0 {
                    None
                } else {
                    let seen = std::mem::take(&mut slot.seen);
                    slot.open = false;
                    Some(seen)
                }
            }
        };
        let Some(seen) = finished else {
            return;
        };
        let mut replies = Vec::new();
        for record in &node.owner.settlements {
            if record.user_lo != lo || record.user_hi != hi {
                continue;
            }
            if seen.iter().any(|(id, sig)| *id == record.settlement_id && *sig == record.sig_lo) {
                continue;
            }
            replies.push(encode_settlement(record));
        }
        replies
    };
    for plain in replies {
        send_on_conn(ctx, conn_id, SETTLEMENT_RECORD_OP, &plain);
    }
}

pub fn settlement_record(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    accept_signed_settlement(src, buf, ctx, "settlement_record");
}

enum SettleChoice {
    Wait,
    Resend(Vec<u8>),
    Store(Settlement),
}

fn accept_signed_settlement(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext, label: &str) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some(record) = decode_settlement(&plain) else {
        eprintln!("[{label}] bad settlement from {src}");
        return;
    };
    if !settlement_body_ok(&SettlementBody::from_record(&record)) {
        return;
    }
    let accept = {
        let node = ctx.node.read().unwrap();
        let Some(contact) = contact_user_for_device(&node, device) else {
            return;
        };
        if !settlement_for_pair(&SettlementBody::from_record(&record), node.owner.user.uuid, contact) {
            return;
        }
        let Some(row) = node.owner.contact_users.iter().find(|row| row.user.uuid == contact) else {
            return;
        };
        if !both_settlement_sigs_ok(&node.owner.key_pair.public_key, &row.public_key, &node.owner.user.uuid, &record) {
            eprintln!("[{label}] bad signature from {src}");
            return;
        }
        !node.owner.settlements.iter().any(|stored| stored == &record)
    };
    if accept {
        store_settlement(ctx, record, src);
    }
}

fn both_settlement_sigs_ok(
    our_key: &Ed25519PublicKey,
    contact_key: &Ed25519PublicKey,
    our: &Uuid,
    record: &Settlement,
) -> bool {
    let body = SettlementBody::from_record(record);
    let (lo_key, hi_key) = if *our == record.user_lo {
        (our_key, contact_key)
    } else {
        (contact_key, our_key)
    };
    verify_settlement(lo_key, &body, &record.sig_lo) && verify_settlement(hi_key, &body, &record.sig_hi)
}

fn store_settlement(ctx: &WorkerContext, record: Settlement, src: SocketAddr) -> bool {
    match request_change_idempotent(Change::RecordSettlement { record }, ctx) {
        Ok(_) => true,
        Err(err) => {
            eprintln!("[settlement_propose] record failed from {src}: {err:?}");
            false
        }
    }
}

fn other_user(record: &Settlement, ctx: &WorkerContext) -> Uuid {
    let node = ctx.node.read().unwrap();
    if node.owner.user.uuid == record.user_lo {
        record.user_hi
    } else {
        record.user_lo
    }
}

fn peer_of_settlement(body: &SettlementBody, ctx: &WorkerContext) -> Uuid {
    let node = ctx.node.read().unwrap();
    if node.owner.user.uuid == body.user_lo {
        body.user_hi
    } else {
        body.user_lo
    }
}

fn pair_has_line(owner: &Owner, contact: Uuid, payment_id: Uuid) -> bool {
    owner.charges.iter().any(|line| {
        line.payment_id == payment_id && users_are_pair(line.payer, line.payee, owner.user.uuid, contact)
    })
}

pub fn payment_index(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, conn_id)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((flags, entries)) = decode_index(&plain) else {
        eprintln!("[payment_index] bad index from {src}");
        return;
    };
    let replies = {
        let mut node = ctx.node.write().unwrap();
        let Some(contact) = contact_user_for_device(&node, device) else {
            return;
        };
        let finished = {
            let slot = node.owner.payment_index.entry(contact).or_default();
            if (flags & INDEX_START) != 0 {
                slot.open = true;
                slot.seen.clear();
            }
            if !slot.open {
                None
            } else {
                slot.seen.extend(entries);
                if (flags & INDEX_END) == 0 {
                    None
                } else {
                    let seen = std::mem::take(&mut slot.seen);
                    slot.open = false;
                    Some(seen)
                }
            }
        };
        let Some(seen) = finished else {
            return;
        };
        let our = node.owner.user.uuid;
        let mut replies = Vec::new();
        for line in &node.owner.charges {
            if !users_are_pair(line.payer, line.payee, our, contact) {
                continue;
            }
            if seen.iter().any(|(id, sig)| *id == line.payment_id && *sig == line.confirm_sig) {
                continue;
            }
            let body = body_from_line(line);
            replies.push(encode_confirm(&body, &line.payer_sig, &line.payee_sig, &line.confirm_sig));
        }
        replies
    };
    for plain in replies {
        send_on_conn(ctx, conn_id, PAYMENT_RECORD_OP, &plain);
    }
}

pub fn payment_record(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device, _)) = open_session(ctx, &buf) else {
        return;
    };
    let Some((body, payer_sig, payee_sig, confirm_sig)) = decode_confirm(&plain) else {
        eprintln!("[payment_record] bad record from {src}");
        return;
    };
    if !offer_body_ok(&body) {
        return;
    }
    let line = {
        let node = ctx.node.read().unwrap();
        let Some(contact_uuid) = contact_user_for_device(&node, device) else {
            return;
        };
        let Some(contact) = node.owner.contact_users.iter().find(|contact| contact.user.uuid == contact_uuid) else {
            return;
        };
        if !users_are_pair(body.payer, body.payee, node.owner.user.uuid, contact_uuid) {
            return;
        }
        let our_key = node.owner.key_pair.public_key;
        let contact_key = contact.public_key;
        let (payer_key, payee_key) = if body.payer == node.owner.user.uuid {
            (our_key, contact_key)
        } else {
            (contact_key, our_key)
        };
        if !verify_offer(&payer_key, &body, &payer_sig)
            || !verify_accept(&payee_key, &body, &payer_sig, &payee_sig)
            || !verify_confirm(&payer_key, &body, &payer_sig, &payee_sig, &confirm_sig)
        {
            eprintln!("[payment_record] bad signature from {src}");
            return;
        }
        let mut line = line_from(&body, [0u8; 16], payer_sig, payee_sig, confirm_sig);
        assign_copied_purse(&node.owner, &mut line);
        line
    };
    if let Err(err) = request_change_idempotent(Change::RecordCharge { line }, ctx) {
        eprintln!("[payment_record] record failed from {src}: {err:?}");
    }
}

fn contact_user_for_device(node: &Node, device: Uuid) -> Option<Uuid> {
    if node.owner.user.devices.iter().any(|candidate| candidate.uuid == device) {
        return None;
    }
    node.owner.contact_users.iter().find_map(|contact| {
        contact
            .user
            .devices
            .iter()
            .any(|candidate| candidate.uuid == device)
            .then_some(contact.user.uuid)
    })
}

fn same_signed(left: &Charge, right: &Charge) -> bool {
    body_from_line(left) == body_from_line(right)
        && left.payer_sig == right.payer_sig
        && left.payee_sig == right.payee_sig
        && left.confirm_sig == right.confirm_sig
}

/// Choose the purse id written into the log. Apply and replay use that id.
fn assign_copied_purse(owner: &Owner, line: &mut Charge) {
    if owner.charges.iter().any(|stored| same_signed(stored, line)) {
        return;
    }
    if owner.charges.iter().any(|stored| stored.payment_id == line.payment_id) || line.payer != owner.user.uuid {
        line.purse_id = [0u8; 16];
        return;
    }
    if let Some(reserve) = owner.reserves.iter().find(|reserve| line_same_payment(line, reserve, owner.user.uuid)) {
        line.purse_id = reserve.purse_id;
        return;
    }
    let mut matches = owner.purses.iter().filter(|purse| {
        purse.aliases.iter().any(|alias| alias == &line.paying_alias)
    });
    match (matches.next(), matches.next()) {
        (Some(purse), None) => line.purse_id = purse.id,
        _ => line.purse_id = [0u8; 16],
    }
}

fn send_on_conn(ctx: &WorkerContext, conn_id: u16, op: u8, plaintext: &[u8]) {
    let packet = {
        let node = ctx.node.read().unwrap();
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            return;
        };
        (build_encrypted_packet(op, conn, plaintext), conn.peer_addr)
    };
    send(ctx, packet.1, &packet.0);
}

fn send_to_user(ctx: &WorkerContext, user: Uuid, op: u8, plaintext: &[u8]) {
    let packet = {
        let node = ctx.node.read().unwrap();
        let Some(contact) = node.owner.contact_users.iter().find(|contact| contact.user.uuid == user) else {
            return;
        };
        let mut devices: Vec<&super::super::data_models::Device> = contact.user.devices.iter().collect();
        devices.sort_by_key(|device| (device.sg_rank.unwrap_or(u32::MAX), device.uuid));
        let Some(conn) = devices.iter().find_map(|device| {
            node.owner.active_connections.values().find(|conn| conn.device_uuid == device.uuid)
        }) else {
            return;
        };
        (build_encrypted_packet(op, conn, plaintext), conn.peer_addr)
    };
    send(ctx, packet.1, &packet.0);
}
