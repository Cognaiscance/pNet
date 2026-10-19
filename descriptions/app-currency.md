# App currency

**Status:** later project. Do not implement this yet.

An approved app will be able to spend a small amount of digital currency with another pNet node. The owner assigns how much that app may spend. pNet rejects a transaction that would go past what the app has left.

This note calls the currency dc. The name, who issues it, and how a node comes to hold any are still open. The spending rules below are the part to keep when this is built.

## Two ways to fund an app

The owner funds one app in one of these ways.

**Monthly budget.** The owner sets how much dc the app may spend in a month. Each accepted transaction reduces what is left of that month's amount. A transaction larger than the remainder is rejected. A new month starts the app again at the assigned amount. Which clock marks the month is not chosen yet.

**Fixed purse.** The owner puts a fixed amount on the app, and spending reduces it until nothing is left. For example, the owner assigns 0.005 dc to discordium. A transaction larger than the remainder is rejected. When the remainder is gone, further transactions are rejected. The purse does not refill on its own.

Discordium is only an example. The same assignment works for any approved app. An app spends only the dc assigned to it. One app's amount is not available to another app on the node. An app with no assignment cannot spend.

## What the node enforces

The owner assigns the amount. The app does not set or raise its own budget.

Today the node carries app bytes without reading them. A spend is a separate action the node does read, including its amount, because the node is what accepts or rejects it. Chat, files, and other app bytes stay unread.

pNet checks the transaction before it leaves for the other node. The app does not keep the balance. A rejected transaction leaves the remainder unchanged. An accepted transaction reduces the remainder by that transaction's amount. A transaction equal to the remainder is accepted and leaves zero.

A spend that pNet has accepted is charged once. A retry of that same transaction does not reduce the remainder again. How the two nodes agree on that is still open.

The other party is another pNet node. The limit lets an app make small payments and stops it once the owner's amount is used up.

Contacts do not learn an app's budget or what it has left.

## Still open

- What dc is, who issues it, and how the owner obtains some to assign.
- How many places past the decimal an amount has. The amount 0.005 has to be exact.
- Whether a purse or a monthly budget belongs to this install of the app, or to that app's alias across this user's devices.
- Who on the other node is paid, and how that node's balance increases.
- How the owner adds to a purse, lowers a budget, or switches an app between the two funding ways, and where that control sits beside the Applications page.
- The wire layout and the error an app receives when a spend is rejected. No opcode or error code is reserved here.
