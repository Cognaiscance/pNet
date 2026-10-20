//! Offer, accept, refuse, and confirm between the two writers.
//!
//! A node that is not the writer drops the packet. The purse id never leaves
//! the payer. A missing receive ceiling is zero, so an offer is refused until
//! one is stored for that payer.

use std::net::SocketAddr;

use super::super::action_queue::WorkerContext;
use super::super::crypto::{build_encrypted_packet, decrypt_packet_body};
use super::super::data_models::{Ed25519SecretKey, Ed25519Signature, Uuid, unix_time_ms};
use super::super::payment::{
    body_from_line, claim_exceeds_ceiling, decode_accept, decode_confirm, decode_offer,
    decode_refuse, encode_accept, encode_confirm, encode_offer, encode_refuse, line_covers,
    line_from, offer_body_ok, pending_covers, pending_from, sign_accept, sign_confirm, sign_offer,
    sign_refuse, verify_accept, verify_confirm, verify_offer, verify_refuse, OfferBody,
    REFUSE_EXPIRED, REFUSE_MISMATCH, REFUSE_OVER_CEILING,
};
use super::super::wire::{
    PAYMENT_ACCEPT_OP, PAYMENT_CONFIRM_OP, PAYMENT_OFFER_OP, PAYMENT_REFUSE_OP,
};
use super::{find_writer_sg, request_change_idempotent, send, Change, PaymentReject, WriteError, WriterTarget};

/// After a reserve reply, tell the contact or resend a confirmation.
pub(crate) fn deliver_payment(ctx: &WorkerContext, payment_id: Uuid) {
    let prepared = {
        let node = ctx.node.read().unwrap();
        if node.owner.key_pair.private_key == Ed25519SecretKey::ZERO {
            return;
        }
        if let Some(line) = node.owner.ledger.iter().find(|line| line.payment_id == payment_id) {
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
    let Some((plain, device)) = open_session(ctx, &buf) else {
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
        } else if let Some(line) = node.owner.ledger.iter().find(|line| line.payment_id == body.payment_id) {
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
        } else if claim_exceeds_ceiling(&node.owner, body.payer, body.amount_nanodollars, Some(body.payment_id)) {
            Reply::Refuse(REFUSE_OVER_CEILING)
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
                    send_refuse(ctx, &body, &payer_sig, REFUSE_OVER_CEILING);
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
    let Some((plain, device)) = open_session(ctx, &buf) else {
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
        if let Some(line) = node.owner.ledger.iter().find(|line| line.payment_id == body.payment_id) {
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
    if request_change_idempotent(Change::RecordLedger { line: confirm.clone() }, ctx).is_err() {
        return;
    }
    let stored = {
        let node = ctx.node.read().unwrap();
        node.owner.ledger.iter().any(|line| {
            line.payment_id == confirm.payment_id && line.confirm_sig == confirm.confirm_sig
        })
    };
    if stored {
        let plain = encode_confirm(&body, &confirm.payer_sig, &confirm.payee_sig, &confirm.confirm_sig);
        send_to_user(ctx, body.payee, PAYMENT_CONFIRM_OP, &plain);
    }
}

pub fn payment_refuse(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let Some((plain, device)) = open_session(ctx, &buf) else {
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
        if node.owner.ledger.iter().any(|line| line.payment_id == body.payment_id) {
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
    let Some((plain, device)) = open_session(ctx, &buf) else {
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
        if let Some(stored) = node.owner.ledger.iter().find(|line| line.payment_id == body.payment_id) {
            if line_covers(stored, &body, &payer_sig) && stored.confirm_sig == confirm_sig {
                return;
            }
            return;
        }
        line_from(&body, [0u8; 16], payer_sig, payee_sig, confirm_sig)
    };
    if let Err(err) = request_change_idempotent(Change::RecordLedger { line }, ctx) {
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
    Confirm(super::super::data_models::LedgerLine),
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

fn open_session(ctx: &WorkerContext, buf: &[u8]) -> Option<(Vec<u8>, Uuid)> {
    if buf.len() < 2 {
        return None;
    }
    let node = ctx.node.read().unwrap();
    if !matches!(find_writer_sg(&node), WriterTarget::Local) {
        return None;
    }
    let plain = decrypt_packet_body(&node, buf)?;
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let device = node.owner.active_connections.get(&conn_id)?.device_uuid;
    Some((plain, device))
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
