# Description
The app api is for communicating with applications.  It is a key part in the process described in the [[Data transport diagram]].

These api transactions need to be on https.

The app will need to request connection to the pNet node.  After the request is made the user needs to accept the request in the user UI. After it is accepted the app gets an api key sent to it that will be required when making any other requests.

# node_controller
routing: get on the root
## get index
* get all the node data and its children according to the [[Data Models]].
* exclude connections, key_pairs and ephemeral_keys information, these should be private from the apps
## post  index

interface for sending payloads through the pNet system
Thinking it through this will require the apps api key, the username to whom the payload will be sent, the device name that it will be sent to and the data itself.

## post index#register
The only endpoint that works without an api_key.  the app sends its ip address and port number, along with its name and a unique id for this instance of the app, essentially all the information required to connect to its api later, perhaps the app should send an api_key to the pnet node so that it can verify that packages sent to it are from the pnet node.    If it gets an OK response from this endpoint then it should wait for the acceptance of the user to get an api key.  The idea of the api key is not neccessary if there is something better, perhaps you can suggest something to establish this connection.  I have heard that the app and pnet could user their public private keypairs in this exchange.  And even establish ephemeral keys for most transactions, that are renewed periodically.

# App expectations

apps are expected to have their own api with endpoints for the following:
* receiving an api key, once they are accepted
* receiving a message that arrived at the pNet node with the intent of being sent to this app.
* Since this project is being established before any apps have been made. You should set the standard here that apps will need to implement to be part of the system.