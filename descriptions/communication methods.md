# Processing of communications

The app will recieve messages on a udp listener on the port 7777 by default.

I would like messages to be as deliverable as possible, thus I would like the system to require all udp transmissions fit within the safe internet udp limit. I believe this means that the payload needs to be 512 bytes or less.

the payload will contain a sequence of values that will be parsed on arrival. They are described as follows:
* Byte one is to be interpreted as a number representing what type of operation is to be performed:
  0. application registration
    * application sends in its alias and the port number it is listening on.  The pnet sends back a token.
  1. application update
    * application sends its token the field or fields it would like to change
      * allowed fields would be alias or host
  2. get data
    * application sends its token
    * pnet returns the data tree that applications are allowed to see.
      * for itself: all data in it's Application struct
      * a tree of data starting at the node level, bacically everything, but without any keys.
  
  4. an application sending a packet

  more operations that I need to do more defining on
  * ephemeral key update
  * generating a new ephemeral key
  * initializing a contact or device
  * updating contact or device details

* the next 16 bytes will be the uuid of the entity making the request
* the remaining bytes will be the payload of the request.  The contents will vary depending on the type of request.
   
   4.
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

