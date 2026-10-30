# Direct path beside the SG relay

App bytes still have a path through a server-grade node. This note adds a second path, direct UDP between the two nodes, used only after a probe round trip shows the other side received a packet.

`format_version` stays 2. An older node drops an opcode it does not know and keeps relaying. A direct path works only when both ends and the coordinating SG run this build. Observed addresses and the unstable flag are memory on the node. They are not a directory snapshot.

## What a send proves

A UDP send means the local stack accepted the datagram. It does not mean the peer received it. Each direct path has its own probe and probe answer. The path is up only after the answer. It goes cold when the next answer is late. A cold path is dropped. The next app packet uses the SG, and that packet may start a new direct attempt.

When a node's own address changes, or a link goes down, that node tells its rank-1 SG in the same turn. The rank-1 SG tells the peer. Both drop the direct path without waiting for the probe time-to-live. After that down period, the next packet through the SG may try the direct path again.

Apps are not asked to report receipt. The node probes.

## Path order

1. The first app packet for a peer goes through the SG. The SG stores the UDP source address it saw for the sender and shares that observation with the destination and with the sender's rank-1 SG.
2. On a later packet, if both observed addresses are private and in the same range, each side sends a LAN probe. The app packet still goes through the SG until the probe is answered.
3. After the LAN answer, a grade that wants speed sends on the LAN.
4. If the ranges do not match, or the LAN probe is not answered, the app packet stays on the SG. The SG tells both sides the other's observed address and both send a hole-punch datagram.
5. After the punch answer, speed-seeking packets use the punch. If the punch is not answered, packets stay on the SG.

One peer has one live direct path. LAN wins when its probe is up. Otherwise the punch wins when its probe is up. Otherwise the SG.

Private ranges are the three IPv4 blocks `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. Two addresses match when both fall in the same one of those blocks. A public address matches neither, so two nodes seen only by their public addresses skip the LAN and use the punch.

## Grades

The app names a grade on send. Omitted or unknown means stable.

| Grade | Path |
| --- | --- |
| stable | SG only. No LAN probe and no punch. |
| fast | LAN if up, else punch if up, else SG. Try to bring a direct path up. |
| cellphone | Same order as fast, with a shorter probe time-to-live, and no direct path while the peer is marked unstable. |

## Unstable

The node keeps the last three timestamps of its own address changes. Three changes inside five minutes, with the newest still inside those five minutes, marks the node unstable. A maintenance pass every five minutes (the same cadence as `MaintainConnections`) clears the flag when the window no longer holds. While the flag is set, cellphone traffic stays on the SG. Fast and stable ignore the flag. The rank-1 SG stores the flag and tells peers so they stop punching a flapping address.

## Time-to-live

A fast direct probe stays up for 30 seconds after the last answer. A cellphone probe stays up for 10 seconds. A later answer refreshes the deadline. A notify of address change or link down drops the path immediately.
