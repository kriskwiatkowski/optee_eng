# OPTEE OpenSSL ENGINE for TLS

[![DOI](https://zenodo.org/badge/326074401.svg)](https://zenodo.org/badge/latestdoi/326074401)

Typically, a TLS server uses an X509 Certificate and associated Private Key to sign a TLS session. Both the certificate and private key used for signing the certificate form an asymmetric cryptographic key-pair. Revealing the traffic-private-key makes it possible to perform men-in-the-middle type of attacks. Typically, private-key is stored on the server’s hard disk. Even if it is stored in encrypted form, at some point the HTTPS server needs to have a possibility to decrypt it to use for signing. It means that at runtime the key in the plaintext will be available in memory of an HTTPS process. In the case of software errors, attackers may be able to steal a private key (see [Heartbleed](https://heartbleed.com/)). On the other hand, in multiple domains, there is a need for binding of secret keys to the hardware on which software is running comes with multiple (IoT devices, software deployments on the edge networks).

Secure Trusted Execution Environments may address those needs. The repository provides a PoC implementation of Trusted Application that can be run in the ARM's TrustZone and be used for storing the secret key of a TLS server as well as perform signing operation with that key. The implementation uses [OPTEE](https://www.op-tee.org/) as an implementation of the TEE.  as an implementation of the TEE. The secret key is stored in encrypted form on secure storage. The secure storage is encrypted with device Hardware Unique Key (HUK) and hence it can be only used by any other hardware after being copied from one device to the other.

The plugin to OpenSSL provides integration between Trusted Application running in Trust Zone and TLS stack. Namely, the plugin implements OpenSSL ENGINE API and hence it can be dynamically loaded by OpenSSL, eliminating a need to modify OpenSSL source code.


The idea was initially described on a blog [here](https://www.amongbytes.com/post/201904-tee-sign-delegator/). The main improvement provided by software in this repository is the implementation of the OpenSSL plugin.
