//! Signed payment offer, accept, refusal, and confirmation.
//!
//! The offer does not name a purse. The payer's user key signs it, the payee's
//! user key signs the accept or the refusal, and the payer signs once more to
//! confirm the accepted record is stored.

use super::crypto::{ed25519_sign, ed25519_verify};
use super::data_models::{
    Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, LedgerLine, Owner, PaymentReserve,
    PendingAccept, Uuid,
};
use super::wire::{push_str, read_arr, read_str};

const OFFER_DOMAIN: &[u8] = b"pnet-payment-offer-v1";
const ACCEPT_DOMAIN: &[u8] = b"pnet-payment-accept-v1";
const CONFIRM_DOMAIN: &[u8] = b"pnet-payment-confirm-v1";
const REFUSE_DOMAIN: &[u8] = b"pnet-payment-refuse-v1";

pub(crate) const REFUSE_OVER_CEILING: u8 = 0x01;
pub(crate) const REFUSE_EXPIRED: u8 = 0x02;
pub(crate) const REFUSE_MISMATCH: u8 = 0x03;

/// The fields both user keys sign. The purse id is not one of them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct OfferBody {
    pub payment_id: Uuid,
    pub amount_nanodollars: i64,
    pub payer: Uuid,
    pub payee: Uuid,
    pub paying_alias: String,
    pub destination_alias: String,
    pub note: String,
    pub expires_at_ms: u64,
}

impl OfferBody {
    pub(crate) fn from_reserve(reserve: &PaymentReserve, payer: Uuid) -> Self {
        Self {
            payment_id: reserve.payment_id,
            amount_nanodollars: reserve.amount_nanodollars,
            payer,
            payee: reserve.contact_uuid,
            paying_alias: reserve.paying_alias.clone(),
            destination_alias: reserve.destination_alias.clone(),
            note: reserve.note.clone(),
            expires_at_ms: reserve.expires_at_ms,
        }
    }

    pub(crate) fn matches_reserve(&self, reserve: &PaymentReserve, payer: Uuid) -> bool {
        self == &Self::from_reserve(reserve, payer)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.payment_id);
        buf.extend_from_slice(&self.amount_nanodollars.to_be_bytes());
        buf.extend_from_slice(&self.payer);
        buf.extend_from_slice(&self.payee);
        push_str(&mut buf, &self.paying_alias);
        push_str(&mut buf, &self.destination_alias);
        push_str(&mut buf, &self.note);
        buf.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        buf
    }
}

pub(crate) fn offer_body_ok(body: &OfferBody) -> bool {
    body.amount_nanodollars > 0
        && alias_ok(&body.paying_alias)
        && alias_ok(&body.destination_alias)
        && body.note.len() <= 255
}

fn alias_ok(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 255
        && alias.trim() == alias
        && !alias.chars().any(|c| c.is_control())
}

pub(crate) fn decode_body(data: &[u8], pos: &mut usize) -> Option<OfferBody> {
    let payment_id: Uuid = read_arr(data, pos)?;
    let amount_nanodollars = read_i64(data, pos)?;
    let payer: Uuid = read_arr(data, pos)?;
    let payee: Uuid = read_arr(data, pos)?;
    let paying_alias = read_str(data, pos)?;
    let destination_alias = read_str(data, pos)?;
    let note = read_str(data, pos)?;
    let expires_at_ms = read_u64(data, pos)?;
    Some(OfferBody {
        payment_id,
        amount_nanodollars,
        payer,
        payee,
        paying_alias,
        destination_alias,
        note,
        expires_at_ms,
    })
}

fn read_sig(data: &[u8], pos: &mut usize) -> Option<Ed25519Signature> {
    Some(Ed25519Signature(read_arr(data, pos)?))
}

fn push_sig(buf: &mut Vec<u8>, sig: &Ed25519Signature) {
    buf.extend_from_slice(&sig.0);
}

fn tagged(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::from(domain);
    for part in parts {
        message.extend_from_slice(part);
    }
    message
}

pub(crate) fn sign_offer(secret: &Ed25519SecretKey, body: &OfferBody) -> Ed25519Signature {
    let bytes = body.encode();
    Ed25519Signature(ed25519_sign(secret, &tagged(OFFER_DOMAIN, &[&bytes])))
}

pub(crate) fn verify_offer(public_key: &Ed25519PublicKey, body: &OfferBody, sig: &Ed25519Signature) -> bool {
    let bytes = body.encode();
    ed25519_verify(public_key, &tagged(OFFER_DOMAIN, &[&bytes]), &sig.0)
}

pub(crate) fn sign_accept(
    secret: &Ed25519SecretKey,
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
) -> Ed25519Signature {
    let bytes = body.encode();
    Ed25519Signature(ed25519_sign(secret, &tagged(ACCEPT_DOMAIN, &[&bytes, &payer_sig.0])))
}

pub(crate) fn verify_accept(
    public_key: &Ed25519PublicKey,
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    payee_sig: &Ed25519Signature,
) -> bool {
    let bytes = body.encode();
    ed25519_verify(public_key, &tagged(ACCEPT_DOMAIN, &[&bytes, &payer_sig.0]), &payee_sig.0)
}

pub(crate) fn sign_confirm(
    secret: &Ed25519SecretKey,
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    payee_sig: &Ed25519Signature,
) -> Ed25519Signature {
    let bytes = body.encode();
    Ed25519Signature(ed25519_sign(
        secret,
        &tagged(CONFIRM_DOMAIN, &[&bytes, &payer_sig.0, &payee_sig.0]),
    ))
}

pub(crate) fn verify_confirm(
    public_key: &Ed25519PublicKey,
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    payee_sig: &Ed25519Signature,
    confirm_sig: &Ed25519Signature,
) -> bool {
    let bytes = body.encode();
    ed25519_verify(
        public_key,
        &tagged(CONFIRM_DOMAIN, &[&bytes, &payer_sig.0, &payee_sig.0]),
        &confirm_sig.0,
    )
}

pub(crate) fn sign_refuse(
    secret: &Ed25519SecretKey,
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    reason: u8,
) -> Ed25519Signature {
    let bytes = body.encode();
    Ed25519Signature(ed25519_sign(
        secret,
        &tagged(REFUSE_DOMAIN, &[&bytes, &payer_sig.0, &[reason]]),
    ))
}

pub(crate) fn verify_refuse(
    public_key: &Ed25519PublicKey,
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    reason: u8,
    payee_sig: &Ed25519Signature,
) -> bool {
    let bytes = body.encode();
    ed25519_verify(
        public_key,
        &tagged(REFUSE_DOMAIN, &[&bytes, &payer_sig.0, &[reason]]),
        &payee_sig.0,
    )
}

pub(crate) fn encode_offer(body: &OfferBody, payer_sig: &Ed25519Signature) -> Vec<u8> {
    let mut buf = body.encode();
    push_sig(&mut buf, payer_sig);
    buf
}

pub(crate) fn decode_offer(data: &[u8]) -> Option<(OfferBody, Ed25519Signature)> {
    let mut pos = 0usize;
    let body = decode_body(data, &mut pos)?;
    let payer_sig = read_sig(data, &mut pos)?;
    if pos != data.len() {
        return None;
    }
    Some((body, payer_sig))
}

pub(crate) fn encode_accept(
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    payee_sig: &Ed25519Signature,
) -> Vec<u8> {
    let mut buf = body.encode();
    push_sig(&mut buf, payer_sig);
    push_sig(&mut buf, payee_sig);
    buf
}

pub(crate) fn decode_accept_at(
    data: &[u8],
    pos: &mut usize,
) -> Option<(OfferBody, Ed25519Signature, Ed25519Signature)> {
    let body = decode_body(data, pos)?;
    let payer_sig = read_sig(data, pos)?;
    let payee_sig = read_sig(data, pos)?;
    Some((body, payer_sig, payee_sig))
}

pub(crate) fn decode_accept(data: &[u8]) -> Option<(OfferBody, Ed25519Signature, Ed25519Signature)> {
    let mut pos = 0usize;
    let parsed = decode_accept_at(data, &mut pos)?;
    if pos != data.len() {
        return None;
    }
    Some(parsed)
}

pub(crate) fn encode_refuse(
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    reason: u8,
    payee_sig: &Ed25519Signature,
) -> Vec<u8> {
    let mut buf = body.encode();
    push_sig(&mut buf, payer_sig);
    buf.push(reason);
    push_sig(&mut buf, payee_sig);
    buf
}

pub(crate) fn decode_refuse(data: &[u8]) -> Option<(OfferBody, Ed25519Signature, u8, Ed25519Signature)> {
    let mut pos = 0usize;
    let body = decode_body(data, &mut pos)?;
    let payer_sig = read_sig(data, &mut pos)?;
    let reason = *data.get(pos)?;
    pos += 1;
    let payee_sig = read_sig(data, &mut pos)?;
    if pos != data.len() {
        return None;
    }
    Some((body, payer_sig, reason, payee_sig))
}

pub(crate) fn encode_confirm(
    body: &OfferBody,
    payer_sig: &Ed25519Signature,
    payee_sig: &Ed25519Signature,
    confirm_sig: &Ed25519Signature,
) -> Vec<u8> {
    let mut buf = encode_accept(body, payer_sig, payee_sig);
    push_sig(&mut buf, confirm_sig);
    buf
}

pub(crate) fn decode_confirm_at(
    data: &[u8],
    pos: &mut usize,
) -> Option<(OfferBody, Ed25519Signature, Ed25519Signature, Ed25519Signature)> {
    let (body, payer_sig, payee_sig) = decode_accept_at(data, pos)?;
    let confirm_sig = read_sig(data, pos)?;
    Some((body, payer_sig, payee_sig, confirm_sig))
}

pub(crate) fn decode_confirm(
    data: &[u8],
) -> Option<(OfferBody, Ed25519Signature, Ed25519Signature, Ed25519Signature)> {
    let mut pos = 0usize;
    let parsed = decode_confirm_at(data, &mut pos)?;
    if pos != data.len() {
        return None;
    }
    Some(parsed)
}

pub(crate) fn pending_from(
    body: &OfferBody,
    payer_sig: Ed25519Signature,
    payee_sig: Ed25519Signature,
) -> PendingAccept {
    PendingAccept {
        payment_id: body.payment_id,
        amount_nanodollars: body.amount_nanodollars,
        payer: body.payer,
        payee: body.payee,
        paying_alias: body.paying_alias.clone(),
        destination_alias: body.destination_alias.clone(),
        note: body.note.clone(),
        expires_at_ms: body.expires_at_ms,
        payer_sig,
        payee_sig,
    }
}

pub(crate) fn line_from(
    body: &OfferBody,
    purse_id: Uuid,
    payer_sig: Ed25519Signature,
    payee_sig: Ed25519Signature,
    confirm_sig: Ed25519Signature,
) -> LedgerLine {
    LedgerLine {
        payment_id: body.payment_id,
        amount_nanodollars: body.amount_nanodollars,
        payer: body.payer,
        payee: body.payee,
        paying_alias: body.paying_alias.clone(),
        destination_alias: body.destination_alias.clone(),
        note: body.note.clone(),
        expires_at_ms: body.expires_at_ms,
        purse_id,
        payer_sig,
        payee_sig,
        confirm_sig,
    }
}

pub(crate) fn body_from_line(line: &LedgerLine) -> OfferBody {
    OfferBody {
        payment_id: line.payment_id,
        amount_nanodollars: line.amount_nanodollars,
        payer: line.payer,
        payee: line.payee,
        paying_alias: line.paying_alias.clone(),
        destination_alias: line.destination_alias.clone(),
        note: line.note.clone(),
        expires_at_ms: line.expires_at_ms,
    }
}

pub(crate) fn body_from_pending(pending: &PendingAccept) -> OfferBody {
    OfferBody {
        payment_id: pending.payment_id,
        amount_nanodollars: pending.amount_nanodollars,
        payer: pending.payer,
        payee: pending.payee,
        paying_alias: pending.paying_alias.clone(),
        destination_alias: pending.destination_alias.clone(),
        note: pending.note.clone(),
        expires_at_ms: pending.expires_at_ms,
    }
}

/// The offer fields match. The payee signature may differ on a raced retry.
pub(crate) fn pending_covers(pending: &PendingAccept, body: &OfferBody, payer_sig: &Ed25519Signature) -> bool {
    &body_from_pending(pending) == body && pending.payer_sig == *payer_sig
}

pub(crate) fn line_covers(line: &LedgerLine, body: &OfferBody, payer_sig: &Ed25519Signature) -> bool {
    &body_from_line(line) == body && line.payer_sig == *payer_sig
}

/// Same charge as the hold. The expiry and the purse id are local stamps.
pub(crate) fn line_same_payment(line: &LedgerLine, reserve: &PaymentReserve, payer: Uuid) -> bool {
    line.payment_id == reserve.payment_id
        && line.amount_nanodollars == reserve.amount_nanodollars
        && line.payer == payer
        && line.payee == reserve.contact_uuid
        && line.paying_alias == reserve.paying_alias
        && line.destination_alias == reserve.destination_alias
        && line.note == reserve.note
}

/// True when this amount would put the payer's open claims above the ceiling.
/// A missing ceiling is zero. `except` is left out of the sum so a retry of
/// that payment id is not counted twice.
pub(crate) fn claim_exceeds_ceiling(
    owner: &Owner,
    payer: Uuid,
    amount: i64,
    except: Option<Uuid>,
) -> bool {
    let max = owner
        .receive_ceilings
        .iter()
        .find(|ceiling| ceiling.payer == payer)
        .map(|ceiling| ceiling.max_nanodollars.max(0))
        .unwrap_or(0);
    let mut used = 0i64;
    for line in &owner.ledger {
        if line.payer == payer && line.payee == owner.user.uuid && Some(line.payment_id) != except {
            used = used.saturating_add(line.amount_nanodollars);
        }
    }
    for pending in &owner.pending_accepts {
        if pending.payer == payer && pending.payee == owner.user.uuid && Some(pending.payment_id) != except {
            used = used.saturating_add(pending.amount_nanodollars);
        }
    }
    used.saturating_add(amount) > max
}

fn read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    Some(i64::from_be_bytes(read_arr(data, pos)?))
}

fn read_u64(data: &[u8], pos: &mut usize) -> Option<u64> {
    Some(u64::from_be_bytes(read_arr(data, pos)?))
}
