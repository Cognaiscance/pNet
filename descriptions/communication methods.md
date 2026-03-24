# Processing of communications

The app will recieve messages on a udp listener on the port 7777 by default.

Byte one of every message is to be interpreted as a number representing what type of operation is to be performed. that byte is to coincide with the number in the ordered list below.

  0. application registration
    * application sends its alias and the port number it is listening on.  The pnet sends back a token.
  1. application update
    * application sends its token and the field or fields it would like to change
      * allowed fields would be alias or host
  2. application get data
    * application sends its token
    * pnet returns the data tree that applications are allowed to see.
      * for itself: all data in it's Application struct
      * a tree of data starting at the node level, bacically everything, but without any keys.
    * the purpose of this node is so that the application knowns which delivery paths it has available to it when doing operation 3. (sending a packet).
  
  3. an application sending a packet:
    * The application sends is token, delivery path and payload to pnet.
      * pnet packages the data as seen below and sends it to the desired pnet node.
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


  
  
  below are more operations that I need to do more defining on. I want them added to the list above as we work on defining each one. It looks like these are operations that are used to handle pnet administration: making and keeping connections, keeping nodes up to date with changes
  * initializing a contact or device
  * ephemeral key update
  * generating a new ephemeral key
  * updating contact or device details
  * synchronizing user data across pnet nodes owned by the same user

   
I would like these administration messages sent from pnet to pnet node to be as deliverable as possible, thus I would like the system to require all udp transmissions fit within the safe internet udp limit. I believe this means that the payload needs to be 512 bytes or less.