# Processing of communications

The app will recieve messages on a udp listener on the port 7777 by default.

The package recieved will be in the following format.  The first byte will represent a number.  Each numeric value will represent which type of transaction is expected:
0. application registration
1. ephemeral key update
2. generating a new ephemeral key
3. initializing a contact
4. send a packet from an application
5. send a packet from a contact

