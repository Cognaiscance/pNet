# App currency

**Status:** later project. Do not implement this yet.

An approved app will be able to spend a small amount with another pNet node. The owner assigns how much that app may spend. pNet rejects a transaction that would go past what the app has left.

The spend is a tab, settled later. Each user issues their own credit. The rank-1 server keeps that user's books, the same way it orders the directory. A payment creates an obligation from the paying user to a contact. Real money, or a digital currency that already has a price, moves only when those two users clear the net.

## Who issues

The issuer is the user. The user key signs each obligation, so the claim still means something after a device is replaced. Removing a device drops that device's certificate. It does not erase obligations the user key already signed.

Each device does not issue a currency of its own. Sanosuke and n64 are one user. A contact trusts that user, not each device separately. A coin minted by one device would be a different instrument from a coin minted by another, and the contact would have to accept each device on its own.

A device that cannot reach a server does not create new debt while it is partitioned. The writer server orders spends. Two devices of the same user cannot both spend the same remainder.

## What is transferred

One unit of account is shared, so the same number is the same quantity on both sides. The amount 0.005 has to be exact. Store it as an integer count of a smallest unit. The name of the unit, and how many places that atom covers, are not chosen yet.

The claim stays personal. An amount of one user's credit is that user's obligation, measured in the shared unit. It is not the same instrument as the other user's credit.

What the payee holds is a signed statement: who owes it, who is paid, which app, the amount, and an id for that attempt. The payee can sum those statements later. The payer does not hand over a coin that a stranger can spend.

Until anyone settles, the purse is still a hard quota on what an app may do to another node. Settlement is what turns the quota into a bill.

## Two ways to fund an app

The owner funds one app in one of these ways. The amount is a limit on how much obligation that app may create in the owner's name.

**Monthly budget.** The owner sets how much the app may spend in a month. Each accepted transaction reduces what is left of that month's amount. A transaction larger than the remainder is rejected. A new month starts the app again at the assigned amount. Which clock marks the month is not chosen yet.

**Fixed purse.** The owner puts a fixed amount on the app, and spending reduces it until nothing is left. For example, the owner assigns 0.005 to discordium. A transaction larger than the remainder is rejected. When the remainder is gone, further transactions are rejected. The purse does not refill on its own.

Discordium is only an example. The same assignment works for any approved app. An app spends only the amount assigned to it. One app's amount is not available to another app on the node. An app with no assignment cannot spend.

The owner assigns the amount. The app does not set or raise its own budget. An app that is compromised can use up its own purse. It does not receive the keys that pay a contact in actual money.

## What the node enforces

Today the node carries app bytes without reading them. A spend is a separate action the node does read, including its amount, because the node is what accepts or rejects it. Chat, files, and other app bytes stay unread.

The app does not keep the balance. A rejected transaction leaves the remainder unchanged. A transaction equal to the remainder is accepted and leaves zero. A spend is charged once. A retry of the same id does not reduce the remainder again.

Contacts do not learn an app's budget or what it has left.

## One payment

1. The app asks its local node to pay a contact a specific amount, with an id for that attempt.
2. The node checks that this app is approved and that the amount is within what the purse or the month still allows. If it is not, the node rejects it and the remainder stays as it is.
3. If it fits, the node reserves that amount and sends the contact a statement signed by the paying user's key.
4. The contact's node accepts only while the new claim is under a ceiling that contact set for the payer. Past the ceiling, it refuses.
5. On acceptance, the reserve becomes a spent charge and the contact records the receivable. On refusal or timeout, the payer's node releases the reserve.
6. The same id returns the same outcome.

The receive ceiling is what keeps self-issued credit from arriving unwanted. The sanction for someone who will not settle is local: set that person's ceiling to zero and stop accepting their credit.

## Reconciliation

Reconciliation is a different event from an app payment. The two owners take the net of the signed claims and pay that difference once. Both nodes then record a clearing entry signed by both user keys, and those claims no longer count.

Paying the net in dollars keeps the dollars outside pNet. One owner transfers the money, then both record that the tab was cleared. Paying the net in a priced digital currency can be checked by the nodes. Only the owner holds the keys for that currency. The app purse stays an allowance to incur obligations.

Clearing between two people is the first version. Passing one person's obligation along a chain of contacts, or netting a triangle of debts, waits until bilateral tabs are actually being settled.

A public chain or a stablecoin is the rail to use when the receiver must walk away holding something a stranger will take. For the amounts this note is about, that rail clears a month's net. It does not price every app message.

## Still open

- The name of the unit, and which atom makes 0.005 exact.
- Whether a purse or a monthly budget belongs to this install of the app, or to that app's alias across this user's devices.
- Which app on the contact is paid, when the payment is for an app rather than for the contact's user.
- How the owner adds to a purse, lowers a budget, switches an app between the two funding ways, or sets a receive ceiling, and where those controls sit beside the Applications page.
- The wire layout and the error an app receives when a spend is rejected. No opcode or error code is reserved here.
- Which clock marks the month.
- Which priced digital currency, if any, is used when a tab is cleared. A dollar payment outside pNet is enough to start.
