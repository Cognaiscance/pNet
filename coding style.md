## interactors

I am used to a rails system that uses the interactor style in the ruby on rails environment.  I would like any large and complicated processes to be built into an interactor.

In the case of sending a udp packet, there would be an interactor organizer for sending the udp; the organizer would break down each step of the process into an interactor file.  The process for finding the contact and device information of who to send to would be one interactor.  Verifying that we have all the up to date keys would be another interactor in the organizer.  Requesting new ephemeral keys if they are expired could be another interactor.  Sending the actual udp message would be another.  Notifying the app of a successful packet delivery would be another.  The organizer would call all the steps and make it very easy for a human reader to understand and follow.

There would be other interactor organizers for things like receiving a udp packet from another pNet node.  The steps  involved should be broken up into interactors that are small discrete steps.

## api for apps

interactions with the apps are to be done through an api.  they will do things like request settings up a secure connection.  requesting some data be sent.  requesting the list of possible destinations.

## the user interface

The user interface should be available only on localhost.  Here is a list of things I think should be done here:
* review apps that have requested to be authenticated and accept or reject the request
* review the address book, connected devices owned by the user and connected devices owned by other users that have been accepted by this user.
	* delete connected users and devices
	* add a new connection to a user or device
* 