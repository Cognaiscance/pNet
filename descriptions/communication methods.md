# Processing of communications

The app will recieve messages on a udp listener on the port 7777 by default.

I would like messages to be as deliverable as possible, thus I would like the system to require all udp transmissions fit within the safe internet udp limit. I believe this means that the payload needs to be 512 bytes or less.

the payload will contain a sequence of values that will be parsed on arrival. They are described as follows:
* Byte one is to be interpreted as a number representing what type of operation is to be performed:
  0. application registration
  1. ephemeral key update
  2. generating a new ephemeral key
  3. initializing a contact or device
  4. updating contact or device details
  5. an application sending a packet

* the next 16 bytes will be the uuid of the entity making the request
* the remaining bytes will be the payload of the request.  The contents will vary depending on the type of request.
   0. 
   ┌────────────────┬───────┐
   │     Field      │ Bytes │
   ├────────────────┼───────┤
   │ Operation type │ 1     │
   ├────────────────┼───────┤
   │ Sender UUID    │ 16    │
   ├────────────────┼───────┤
   │ Public key     │ 32    │
   ├────────────────┼───────┤
   │ Alias          │ ?     │
   ├────────────────┼───────┤
   │ Used           │ 49    │
   ├────────────────┼───────┤
   │ Remaining      │ 463   │
   └────────────────┴───────┘ 
   1. 
   ┌────────────────┬───────┐
   │     Field      │ Bytes │
   ├────────────────┼───────┤
   │ Operation type │ 1     │
   ├────────────────┼───────┤
   │ Sender UUID    │ 16    │
   ├────────────────┼───────┤
   │ EKE ID         │ 16    │
   ├────────────────┼───────┤
   │ New public key │ 32    │
   ├────────────────┼───────┤
   │ Used           │ 65    │
   ├────────────────┼───────┤
   │ Remaining      │ 447   │
   └────────────────┴───────┘
   2.
   ┌────────────────┬───────┐
   │     Field      │ Bytes │
   ├────────────────┼───────┤
   │ Operation type │ 1     │
   ├────────────────┼───────┤
   │ Sender UUID    │ 16    │
   ├────────────────┼───────┤
   │ New public key │ 32    │
   ├────────────────┼───────┤
   │ Signature      │ 64    │
   ├────────────────┼───────┤
   │ Used           │ 113   │
   ├────────────────┼───────┤
   │ Remaining      │ 399   │
   └────────────────┴───────┘
   5.
   Unencrypted header:
   ┌───────────────────────────┬───────┐
   │           Field           │ Bytes │
   ├───────────────────────────┼───────┤
   │ Operation type            │ 1     │
   ├───────────────────────────┼───────┤
   │ Peer active connection ID │ 2     │
   ├───────────────────────────┼───────┤
   │ Nonce                     │ 24    │
   └───────────────────────────┴───────┘

   Encrypted body:
   ┌─────────────────┬───────┐
   │      Field      │ Bytes │
   ├─────────────────┼───────┤
   │ Sender app ID   │ 2     │
   ├─────────────────┼───────┤
   │ Receiver app ID │ 2     │
   ├─────────────────┼───────┤
   │ App payload     │ ?     │
   ├─────────────────┼───────┤
   │ Auth tag        │ 16    │
   ├─────────────────┼───────┤
   │ Used            │ 47    │
   ├─────────────────┼───────┤
   │ Remaining       │ 465   │
   └─────────────────┴───────┘

