# Peer to Peer Communication in a LAN network

if two users are connected to the same network, they can communicate using there local ip addresses using this application. No interference of a server.

## version 1.0.0

No server at all.
using plain text - not encrypted.
only a command line application.
just for checking sending messages successfully.
exit from a chat using "exit" message.
can chat with one user at a time. have to exit for chat with another.


## version 1.1.0

Assume users exchanged public keys somehow.
End to End Encrypted using Hybrid encryption (AES-256 + RSA).
Should know receivers ip address (ipv4 and ipv6 both communication possible).
only tested on LAN network.
