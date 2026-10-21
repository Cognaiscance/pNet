//! Signed payment offer, accept, refusal, and confirmation.
//!
//! The offer does not name a purse. The payer's user key signs it, the payee's
//! user key signs the accept or the refusal, and the payer signs once more to
//! confirm the accepted record is stored.

use super::crypto::{ed25519_sign, ed25519_verify};
use super::data_models::{
    ClearingRecord, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, LedgerLine, Owner,
    PaymentReserve, PendingAccept, Uuid,
};
use super::wire::{push_str, read_arr, read_str};

const OFFER_DOMAIN: &[u8] = b"pnet-payment-offer-v1";
const ACCEPT_DOMAIN: &[u8] = b"pnet-payment-accept-v1";
const CONFIRM_DOMAIN: &[u8] = b"pnet-payment-confirm-v1";
const REFUSE_DOMAIN: &[u8] = b"pnet-payment-refuse-v1";
const CLEARING_DOMAIN: &[u8] = b"pnet-payment-clearing-v1";

/// One clearing names at most this many payment ids, so the record fits one datagram.
pub(crate) const CLEARING_MAX_IDS: usize = 64;

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

/// The first packet of an index sets this bit and replaces any list in progress.
pub(crate) const INDEX_START: u8 = 0x01;
/// The last packet of an index sets this bit. The receiver then copies what it lacks.
pub(crate) const INDEX_END: u8 = 0x02;
const INDEX_ENTRY_LEN: usize = 16 + 64;
/// Entries per packet. Forty fit under a 4096-byte datagram with the session seal.
pub(crate) const INDEX_MAX_ENTRIES: usize = 40;

pub(crate) fn encode_index(flags: u8, entries: &[(Uuid, Ed25519Signature)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + entries.len() * INDEX_ENTRY_LEN);
    buf.push(flags);
    buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (id, sig) in entries {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&sig.0);
    }
    buf
}

pub(crate) fn decode_index(data: &[u8]) -> Option<(u8, Vec<(Uuid, Ed25519Signature)>)> {
    if data.len() < 3 {
        return None;
    }
    let flags = data[0];
    let count = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() != 3 + count * INDEX_ENTRY_LEN {
        return None;
    }
    let mut pos = 3usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id: Uuid = read_arr(data, &mut pos)?;
        let sig = read_sig(data, &mut pos)?;
        entries.push((id, sig));
    }
    Some((flags, entries))
}

/// One plaintext per packet. An empty list is one packet with both flags set.
pub(crate) fn index_plaintexts(entries: &[(Uuid, Ed25519Signature)]) -> Vec<Vec<u8>> {
    if entries.is_empty() {
        return vec![encode_index(INDEX_START | INDEX_END, &[])];
    }
    let chunks: Vec<&[(Uuid, Ed25519Signature)]> = entries.chunks(INDEX_MAX_ENTRIES).collect();
    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let mut flags = 0u8;
            if index == 0 {
                flags |= INDEX_START;
            }
            if index == last {
                flags |= INDEX_END;
            }
            encode_index(flags, chunk)
        })
        .collect()
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
        if line.payer == payer
            && line.payee == owner.user.uuid
            && Some(line.payment_id) != except
            && !payment_is_cleared(owner, payer, line.payment_id)
        {
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

/// The two user ids in byte order. The same user twice is not a pair.
pub(crate) fn ordered_users(a: Uuid, b: Uuid) -> Option<(Uuid, Uuid)> {
    if a < b {
        Some((a, b))
    } else if b < a {
        Some((b, a))
    } else {
        None
    }
}

pub(crate) fn users_are_pair(payer: Uuid, payee: Uuid, our: Uuid, contact: Uuid) -> bool {
    (payer == our && payee == contact) || (payer == contact && payee == our)
}

/// Sort and drop duplicates. Empty, or more than [`CLEARING_MAX_IDS`] distinct ids, is refused.
pub(crate) fn normalize_payment_ids(ids: &[Uuid]) -> Option<Vec<Uuid>> {
    if ids.is_empty() {
        return None;
    }
    let mut out = ids.to_vec();
    out.sort();
    out.dedup();
    if out.is_empty() || out.len() > CLEARING_MAX_IDS {
        None
    } else {
        Some(out)
    }
}

/// The bytes both user keys sign. No amount, purse, note, or expiry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct ClearingBody {
    pub clearing_id: Uuid,
    pub user_lo: Uuid,
    pub user_hi: Uuid,
    pub payment_ids: Vec<Uuid>,
}

impl ClearingBody {
    pub(crate) fn from_record(record: &ClearingRecord) -> Self {
        Self {
            clearing_id: record.clearing_id,
            user_lo: record.user_lo,
            user_hi: record.user_hi,
            payment_ids: record.payment_ids.clone(),
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(50 + self.payment_ids.len() * 16);
        buf.extend_from_slice(&self.clearing_id);
        buf.extend_from_slice(&self.user_lo);
        buf.extend_from_slice(&self.user_hi);
        buf.extend_from_slice(&(self.payment_ids.len() as u16).to_be_bytes());
        for id in &self.payment_ids {
            buf.extend_from_slice(id);
        }
        buf
    }
}

pub(crate) fn clearing_body_ok(body: &ClearingBody) -> bool {
    body.user_lo < body.user_hi
        && !body.payment_ids.is_empty()
        && body.payment_ids.len() <= CLEARING_MAX_IDS
        && body.payment_ids.windows(2).all(|pair| pair[0] < pair[1])
}

pub(crate) fn clearing_record_ok(record: &ClearingRecord) -> bool {
    clearing_body_ok(&ClearingBody::from_record(record))
}

pub(crate) fn clearing_for_pair(body: &ClearingBody, our: Uuid, contact: Uuid) -> bool {
    match ordered_users(our, contact) {
        Some((lo, hi)) => body.user_lo == lo && body.user_hi == hi,
        None => false,
    }
}

fn decode_clearing_body_at(data: &[u8], pos: &mut usize) -> Option<ClearingBody> {
    let clearing_id: Uuid = read_arr(data, pos)?;
    let user_lo: Uuid = read_arr(data, pos)?;
    let user_hi: Uuid = read_arr(data, pos)?;
    let count = read_u16(data, pos)? as usize;
    if count == 0 || count > CLEARING_MAX_IDS {
        return None;
    }
    let mut payment_ids = Vec::with_capacity(count);
    for _ in 0..count {
        payment_ids.push(read_arr(data, pos)?);
    }
    Some(ClearingBody { clearing_id, user_lo, user_hi, payment_ids })
}

pub(crate) fn sign_clearing(secret: &Ed25519SecretKey, body: &ClearingBody) -> Ed25519Signature {
    let bytes = body.encode();
    Ed25519Signature(ed25519_sign(secret, &tagged(CLEARING_DOMAIN, &[&bytes])))
}

pub(crate) fn verify_clearing(
    public_key: &Ed25519PublicKey,
    body: &ClearingBody,
    sig: &Ed25519Signature,
) -> bool {
    let bytes = body.encode();
    ed25519_verify(public_key, &tagged(CLEARING_DOMAIN, &[&bytes]), &sig.0)
}

pub(crate) fn encode_clearing_proposal(body: &ClearingBody, sig: &Ed25519Signature) -> Vec<u8> {
    let mut buf = body.encode();
    push_sig(&mut buf, sig);
    buf
}

pub(crate) fn decode_clearing_proposal(data: &[u8]) -> Option<(ClearingBody, Ed25519Signature)> {
    let mut pos = 0usize;
    let body = decode_clearing_body_at(data, &mut pos)?;
    let sig = read_sig(data, &mut pos)?;
    if pos != data.len() {
        return None;
    }
    Some((body, sig))
}

pub(crate) fn encode_clearing_record(record: &ClearingRecord) -> Vec<u8> {
    let mut buf = ClearingBody::from_record(record).encode();
    push_sig(&mut buf, &record.sig_lo);
    push_sig(&mut buf, &record.sig_hi);
    buf
}

pub(crate) fn decode_clearing_record_at(data: &[u8], pos: &mut usize) -> Option<ClearingRecord> {
    let body = decode_clearing_body_at(data, pos)?;
    let sig_lo = read_sig(data, pos)?;
    let sig_hi = read_sig(data, pos)?;
    Some(ClearingRecord {
        clearing_id: body.clearing_id,
        user_lo: body.user_lo,
        user_hi: body.user_hi,
        payment_ids: body.payment_ids,
        sig_lo,
        sig_hi,
    })
}

pub(crate) fn decode_clearing_record(data: &[u8]) -> Option<ClearingRecord> {
    let mut pos = 0usize;
    let record = decode_clearing_record_at(data, &mut pos)?;
    if pos != data.len() {
        return None;
    }
    Some(record)
}

pub(crate) fn clearing_body_matches(record: &ClearingRecord, body: &ClearingBody) -> bool {
    record.clearing_id == body.clearing_id
        && record.user_lo == body.user_lo
        && record.user_hi == body.user_hi
        && record.payment_ids == body.payment_ids
}

/// True when any stored clearing for this pair names `payment_id`.
pub(crate) fn payment_is_cleared(owner: &Owner, contact: Uuid, payment_id: Uuid) -> bool {
    let Some((lo, hi)) = ordered_users(owner.user.uuid, contact) else {
        return false;
    };
    owner.clearings.iter().any(|record| {
        record.user_lo == lo
            && record.user_hi == hi
            && record.payment_ids.binary_search(&payment_id).is_ok()
    })
}

/// Incoming uncleared amounts minus outgoing ones. Positive means `contact` owes this user.
/// A cleared id drops every body of that payment. Pending accepts are not lines.
pub(crate) fn net_nanodollars(owner: &Owner, contact: Uuid) -> i64 {
    let mut net = 0i64;
    for line in &owner.ledger {
        if !users_are_pair(line.payer, line.payee, owner.user.uuid, contact) {
            continue;
        }
        if payment_is_cleared(owner, contact, line.payment_id) {
            continue;
        }
        if line.payee == owner.user.uuid {
            net = net.saturating_add(line.amount_nanodollars);
        } else {
            net = net.saturating_sub(line.amount_nanodollars);
        }
    }
    net
}

fn read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    Some(i64::from_be_bytes(read_arr(data, pos)?))
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    Some(u16::from_be_bytes(read_arr(data, pos)?))
}

fn read_u64(data: &[u8], pos: &mut usize) -> Option<u64> {
    Some(u64::from_be_bytes(read_arr(data, pos)?))
}
