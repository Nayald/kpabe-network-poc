
# kpabe-network-poc

This repository contains source code to compile 4 programs for a Proof of Concept about enabling KP-ABE encryption inside a TLS session.

![CG server](https://github.com/Nayald/kpabe-network-poc/blob/main/image/overview.png?raw=true)

The programs do the following things:

 - Proxy: As the current web browsers do not understand KP-ABE encryption, the proxy is here to add the needed missing logic. It is expected to be removed from the chain in case of adoption.
 - Authority: Manage the keys for each clients, generate decryption keys based on policies (whitelist, blacklist and rules based on attributes).
 - Verifier: It is like a firewall, with the help of iptables, it will perform deep packet inspection to get the clienthello of the TLS sessions. It will check if the two added TLS extensions (KP-ABE public key and an encrypted scalar for anonymity)  are present and verify if there are derived from the Authority public key. If the clienthello is not compliant, it will drop packets from related to the client TLS session.
 - Server: It is a basic web server that implement the logic needed to encrypt content with KP-ABE. It maps contents with attributes for encryption. KP-ABE encryption is enable only if the client provide a KP-ABE public key in its clienthello else it works as a normal web server.
