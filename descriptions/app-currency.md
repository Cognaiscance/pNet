# App currency

**Status:** steps 1 through 12 are in the node. A settlement contact and outside payment stay unbuilt.

An approved app will be able to spend a small amount with another pNet node. The node keeps a tab with each contact. A purse is only a limit on how much an app may add to a tab. pNet rejects a send that would pass the limit.

Each user issues their own credit. The rank-1 server keeps that user's books, the same way it orders the directory. A charge is an obligation from the paying user to a contact. The two of them may settle the tab later. A tab can also stay open.

Read opcodes `0x05`, `0x06`, and `0x07` are assigned. `0x06` and `0x07` return confirmed lines for the caller's alias. Reserve is opcode `0x08`. After a reserve, the two writers finish the payment on fabric ops `0x60` through `0x63`. A note is at most 255 bytes. `/purses` creates purses, sets the kind and the allotment, and assigns app aliases.

## Who issues

The issuer is the user. The user key signs each obligation, so the claim still means something after a device is replaced. Removing a device drops that device's certificate. It does not erase obligations the user key already signed.

Each device does not issue a currency of its own. Sanosuke and n64 are one user. A contact trusts that user, not each device separately.

A device that cannot reach a server does not create new debt while it is partitioned. The writer server orders spends. Two devices of the same user cannot both spend the same available amount.

## The unit

The unit is the US dollar. Every amount is a signed 64-bit count of nanodollars. One nanodollar is $0.000000001. The amount 0.005 is exactly 5,000,000. One cent is exactly 10,000,000. Nine decimal places is the smallest fraction this word holds, and the largest magnitude is about $9.22 billion. A payment amount is zero or greater.

The claim stays personal. An amount of one user's credit is that user's obligation in dollars. It is not the same instrument as the other user's credit, and it is not a coin a stranger can spend.

Bitcoin can appear as a price on a settlement entry. It is not the unit a purse is counted in.

## The tab

Each contact has a tab, stored by the rank-1 server. That user's devices read the writer's copy. There is no master purse beside the tabs.

A charge is a confirmed signed record. It names the amount, the payer, the payee, the paying app, the destination app alias, the note, and the payment id. Both contacts store that record. The payee can sum the charges later.

Incoming lines credit the user. They do not raise a purse. The destination app does not hold a balance it can spend.

The note is the sending app's own reference, such as a transaction number for a video or another purchase. The node carries the note and does not interpret it. The payment id is the node's key for charging a purse once. The same id is the same payment. The note and the payment id are two fields.

Contacts do not learn purse names, allotments, or available amounts. Another app does not see this app's notes.

## Purses

A purse belongs to the user. Every device sees the same purses. Membership is by app alias, so `discordium-client` on the phone and on the laptop share it. `discordium-client` and `discordium-server` are different aliases, so each is assigned on its own. Any other alias is its own member.

The owner sets the allotment. Two kinds exist.

**Monthly budget.** The purse allows a set amount in a month. Each confirmed send reduces what is left of that month's amount. A new month starts the purse again at the allotted amount. The month is the UTC calendar month on the rank-1 writer's clock. Unspent amount does not carry over. A reserve still open at the boundary stays a hold, and releasing it does not add the amount to the new month. Confirming it while the hold remains stores the line and does not change the new month's available amount. A confirmation that arrives after the hold is already gone can still charge the purse. A device that is not the writer does not roll the month. Own devices learn the new available amount from the private purse record.

**Fixed purse.** The owner puts a fixed amount on the purse, and sending reduces it until nothing is left. For example, a purse of 0.005 with discordium as a member. When the available amount is gone, further sends are rejected. The purse does not refill on its own.

The owner can raise the allotment, lower it, or switch the purse between fixed and monthly. The available amount moves by that same difference and may go negative. Signed lines stay as they are. The switch does not refill the purse. A hold from an earlier month is dropped without a refund when a monthly purse becomes fixed. A hold from the current month, and a hold taken while the purse was fixed, is still returned if it is released.

One purse can have several member apps. One app alias can belong to several purses. Every member may spend the whole available amount, so two apps on one purse share it. An app that belongs to no purse cannot send. An app does not set or raise an allotment. An app that is compromised can use up the purses it belongs to. It does not receive the keys that pay a contact in actual money.

The available amount is local bookkeeping. A signed obligation still stands if that bookkeeping is wrong. The purse then shows an overrun.

## The /purses page

The owner creates purses on `/purses`. Creating one sets its name, whether it is fixed or monthly, and its allotment. The owner can later change that allotment and that kind on the same page. Saving the same kind and allotment changes nothing. The owner adds and removes app aliases there. Removing an alias stops that app's new sends from that purse. Incoming lines for the alias stay visible.

The page shows each purse's allotment and available amount. The same purses appear on every device, because the writer holds them and own devices pull that private record. A reserve lowers the available amount on the writer. Own devices see that amount on the next private pull.

## What you'll run

The owner sets what you'll run on `/what-youll-run`. Each contact has one amount: the most of that payer's tab this user will still accept. Nothing is accepted until the owner stores one. An amount equal to that limit is accepted. Zero refuses new credit. A later amount replaces that contact's row. Own devices see the same amounts. The contact is not told the number, and the change does not move a purse.

## What an app can ask

An assigned app can ask the local node for three things.

- The purses it belongs to, with the kind, the allotment, and the available amount of each. The reply also names each purse so the app can tell them apart.
- Charges sent to this user for this app alias. Each charge has the payment id, the amount, the payer, the payee, the paying app, the destination app, and the note. Every device running that alias can read them.
- Charges this app itself sent. The fields are the same.

Those questions are local ops `0x05`, `0x06`, and `0x07`. Kind 0 is a fixed purse. Kind 1 is a monthly purse. `0x06` lists lines whose payee is this user and whose destination alias is the caller's alias. `0x07` lists lines whose payer is this user and whose paying alias is the caller's alias. A reserve is local op `0x08`. It lowers the available amount. Once the contact accepts and the payer confirms, both writers store the line, and those two lists return it.

A send names the contact, the amount, the destination app alias, the note, and the payment id. An app that belongs to one purse draws on that purse. An app that belongs to several names which purse covers the send. That name chooses the limit. The payment goes to the user.

## One payment

1. The app asks its local node to pay a contact.
2. The node checks that this app is approved, that it belongs to the named purse, and that the amount is within what that purse still allows. If it is not, the node rejects the send and the available amount stays as it is.
3. If it fits, the writer reserves that amount and signs an offer. The offer includes the amount, the contact, both app aliases, the note, the payment id, and an expiry.
4. The contact's node accepts only while the new claim is under what that contact will run for the payer. Past that, it refuses. On accept, the contact signs the offer.
5. The payer signs again to confirm that the accepted record is stored. That confirmation is the charge on both sides. The reserve becomes a charge. The contact counts the payment once it has the confirmation.
6. A proposal with no confirmation expires. The payer releases the reserve, and neither tab keeps the proposal as a debt.
7. On refusal, the payer releases the reserve.
8. The same payment id returns the same outcome. A retry does not reduce the available amount again.

A send equal to the available amount is accepted and leaves zero.

What you'll run is what keeps self-issued credit from arriving unwanted. The sanction for someone who will not settle is local: set that person's amount to zero and stop accepting their credit.

Today the node carries app bytes without reading them. A spend is a separate action the node does read, including its amount and its note, because the node is what accepts or rejects it. Chat, files, and other app bytes stay unread.

## When the books differ

A charge counts only as a copy of a record both user keys have signed, including the payer's confirmation that it is stored. The two contacts repair a difference by copying those records. They do not edit amounts to force the books to match.

When the contacts connect, each sends the list of payment ids it holds for the pair. A missing id is answered with the signed record. A record whose signatures verify is stored and becomes a line. A record that does not verify is discarded. The same id with the same signed bytes is the same payment. If one id arrives as two different signed bodies, both are kept and shown to the owners. The node does not pick a winner.

A settlement is another record signed by both user keys. It names the payment ids it settles. The owner who did not start it signs only after each named id is already a line between the pair. The same compare-and-copy step fills in a missing settlement, including one that arrives before a named line. Once the line is stored, that id no longer counts toward the tab.

A contact cannot invent a debt, because that contact cannot sign with the other user key. A lost confirmation is copied across on a later connection. If the payer has already spent the purse again, the debt still stands and the purse shows an overrun.

## Reconciliation

Settlement is a different event from an app payment. The two owners can pay the tab and then both sign a settlement. The named lines no longer count toward the tab. Incoming payments and a settlement do not raise a purse.

Some pairs can leave the tab open. The lines stay on the tab, and the purse limit has still done its job.

Settlement between two people is the first version. Passing one person's obligation along a chain of contacts, or netting a triangle of debts, waits until bilateral tabs are actually being settled.

The dollars, when any are paid, stay outside pNet. Only the owner holds keys for a priced digital currency, if one is ever used to pay a tab. An app purse does not hold those keys.

## Still open

- What you'll run starts at zero until an amount for that payer is stored. `/what-youll-run` is the page that sets it.
- The owner reads one contact's tab, sees what is on it, and settles charges on `/contacts/<id>/tab`. The other owner still has to sign. `/purses` stays the page for the limits. Dollars paid stay outside pNet.
- Whether many small receivables can be gathered into one balance with a settlement contact, and which outside payment, if any, pays a settled tab. No chain is chosen.


## Implementation plan

The steps below are the build order. A step that is not marked done stays unbuilt.

1. **Fixed purses. Done.** The writer stores a named purse, its nanodollar allotment, its available amount, and its member app aliases. `/purses` lets the owner create one, add or remove aliases, and see both amounts. Own devices receive the purses through a private-scope pull. Contacts do not. No payment exists yet, so the available amount stays equal to the allotment.
2. **App reads. Done.** An approved app asks the local node with three loopback ops. `0x05` returns the purses whose member aliases include the caller's alias, ordered by name then id. Each entry has the id, the name, the kind (fixed), the allotment, and the available amount. Another app's purses are absent. `0x06` (incoming) and `0x07` (sent) succeed with an empty list. An unknown token and an unapproved app are rejected. No payment is stored.
3. **Reserve. Done.** Opcode `0x08`. The body names the purse, the amount, the contact, the destination alias, the note, and the payment id. The note is at most 255 bytes. The node rejects an app that is not a member (`0x08`) or an amount over what is available (`0x09`), and the available amount stays put. The same payment id with a different body is `0x0A`. A fitting amount is reserved once for that payment id. The hold lasts 24 hours on the writer's clock, and the writer then adds the amount back. The contact is not told. A device that is not the writer carries the reserve to the writer in step 12.
4. **Offer, accept, confirm. Done.** After a reserve, the writer signs an offer when it holds the user key and has a session to that contact. The offer is the amount, the contact, both app aliases, the note, the payment id, and the reserve's expiry. It does not name the purse. Fabric op `0x60` carries it. A missing session leaves the hold until a retry, a refusal, or expiry. A user key that is absent skips the offer, and the reserve still succeeds.

   The contact accepts on `0x61` only while the new claim stays at or under what you'll run for that payer. A missing amount is zero, so nothing is accepted until one is stored. An amount equal to that limit is accepted. Past it, the contact signs a refusal (`0x62`) and the payer releases the reserve. A bad offer signature is dropped, and the reserve stays. A node that is not the writer drops the offer.

   The payer signs again on `0x63` to confirm the accepted record is stored. That confirmation is the charge on both sides. The reserve becomes a charge: the available amount stays reduced, and the hold is removed so expiry does not add it back. The payee's copy of the line has an empty purse id. The same payment id returns the same outcome, and a retry does not reduce the available amount again. No confirmation before expiry releases the reserve. An accepted offer that expires is dropped, and expiry itself does not create a line. Ops `0x06` and `0x07` stay empty.
5. **Repair. Done.** On connect, each writer sends the payment ids it holds for that pair, together with the payer's confirmation signature, so two bodies of one id stay distinct. Ops are `0x64` (the list) and `0x65` (one signed record). A node that is not the writer drops both. An own device is not a contact, so the exchange does not run for it.

   A record whose signatures fail is dropped. The same signed bytes are the same payment. A different signed body for an id that is already stored is kept beside the first. The purse is not charged again, and the node does not pick a winner.

   The payee stores a copied record with an empty purse id and does not change a purse. The payer keeps the purse from the matching hold and does not subtract again. If that hold is already gone and exactly one purse lists the paying alias, the available amount is reduced and may go negative. That negative amount is the overrun. If no purse or several purses list the alias, the line is stored and no purse is chosen.

   A confirmation that arrives after the staged accept expired is stored. Expiry itself still drops the staged accept and does not create a line. Ops `0x06` and `0x07` stay empty.
6. **App payment lists. Done.** Ops `0x06` and `0x07` return confirmed lines. `0x06` is lines whose payee is this user and whose destination alias is the caller's alias. `0x07` is lines whose payer is this user and whose paying alias is the caller's alias. Each line is the payment id, the amount, the payer, the payee, the paying alias, the destination alias, and the note. The purse id, the expiry, and the signatures are absent. Order is the payment id, then the payer's confirmation signature, so two bodies of one id both appear and the order is the same on every device. A hold that is not confirmed is absent. Another alias's lines are absent, including the note. Count 0 is success. The read does not change a purse or the tab. An unknown token and an unapproved app are rejected.
7. **Settlement. Done.** Both owners sign a record that names payment ids. The lines stay on the tab and on ops `0x06` and `0x07`. They no longer count toward the tab between that pair, and they no longer count against what you'll run. A purse's available amount does not change. No bank, chain, or settlement contact is attached. The page that shows the tab is step 9. A test calls the writer to propose a settlement. An app cannot.

   Fabric op `0x66` is the proposal: the body and the proposer's signature. The body is `[settlement id:16][user lo:16][user hi:16][count:u16 be][payment id:16…]`. The two user ids are in byte order, and the payment ids are strictly increasing. At most 64 ids. An empty list is not a record. The signature domain is `pnet-payment-clearing-v1` over that body. Each user signs the same bytes.

   The other owner answers on `0x67` only when every named id is already a line between this pair. A missing id gets no reply. A bad signature is dropped. The plaintext is the body plus both signatures. The same body is stored once. A different body for the same settlement id is kept beside the first, and the tab is the union of the named ids. Naming an id drops every body of that payment. A pending accept is not a charge, so it is not settled and still counts toward what you'll run.

   On connect, `0x68` lists settlement ids and the lower user's signature, in the same packet shape as `0x64`. `0x69` copies one dual-signed record. A node that is not the writer drops these packets. A copied record is stored even when a named line is briefly missing, and that id leaves the tab once the line is there. The copy does not change a purse. A private snapshot writes the settlement count after the staged accepts. A blob that ends at the staged accepts still loads, with no settlements. Own devices learn a settlement through the private scope.
8. **What you'll run. Done.** `/what-youll-run` lists each contact and the amount stored for that payer, or zero when no row is stored. The owner posts a dollar amount with at most nine decimal places. Zero is allowed. A bad amount, or a user who is not a contact, is not stored. Private change `0x15` replaces that payer's row. The same payer and amount does not append a second row and does not bump the private version. Own devices apply it from the private log. A purse's available amount, a reserve, and the tab do not change. There is no app opcode and no fabric session op. The contact tab page is step 9.
9. **Tab. Done.** `/contacts/<id>/tab` lists confirmed lines between this user and that contact. Each line shows the payment id, the amount, whether it was incoming or sent, both app aliases, and the note. Two bodies of one id are both shown. A line with anyone else is absent. A pending accept is absent. A settled charge stays on the page and is left out of the tab. The amount on the tab is what `tab_nanodollars` already computes: a positive amount is what the contact owes this user. The owner checks open charges and settles them. The writer signs and sends op `0x66`. The record is not stored here, and a purse does not change, until the other owner signs it back. An empty selection, an id that is not a line for the pair, more than 64 ids, a node that is not the writer, or a missing user key sends nothing. There is no app opcode. `/purses` stays the limits page.
10. **Monthly purse. Done.** `/purses` can create a monthly purse. Kind 1 is monthly and kind 0 stays fixed. The writer rolls it on the reserve sweep and before a new reserve. The period is the UTC year and month on that writer's clock. The available amount becomes the allotment. Unspent amount does not carry, including a negative overrun. Signed lines stay. An open reserve keeps its old period. Releasing it does not add the amount back. A reserve taken after the roll reduces the new allotment, and releasing that one still adds the amount back. A node that is not the writer leaves the purse alone. An older private snapshot that ends at the settlements still loads as fixed. There is no new opcode. The allotment edit is step 11.
11. **Allotment edit. Done.** `POST /purses/edit` names the purse, the kind (`fixed` or `monthly`), and the new allotment. The available amount moves by the difference between the new allotment and the old one, and it may go negative. The same kind and allotment does not publish. The writer closes the previous month before that difference is applied, so a raise does not keep last month's remainder. Switching from fixed to monthly sets the current UTC period and does not refill. Switching from monthly to fixed drops holds from earlier months without adding them back, and sets the period to zero. A hold from the current month, and a hold taken while the purse was fixed, is still returned when it is released. Signed lines stay. The name and the aliases stay. There is no app opcode. An app still cannot raise an allotment.
12. **Writer forwarding. Done.** A device that is not the writer sends the reserve to the writer on the private write and waits for the answer. It does not change its own purse. The writer rolls the month, stamps the 24-hour expiry from its own clock, and stores the hold. The ack carries the payment id, the app result, the available amount, and the expiry. The device replies to the app from that ack. The same hold does not reduce the purse again. A missing purse, an amount past what is available, and a different body come back as those errors. No reachable writer, or no answer, is `no writer`. The offer is still signed only by the writer. A node that is not the writer still drops an offer. There is no new app opcode.

A settlement contact and any outside payment stay out of these steps until those choices are settled.
