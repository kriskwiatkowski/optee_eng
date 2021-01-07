# OPTEE OpenSSL ENGINE for TLS

Typically, a TLS server uses a X509 Certificate and associated Private Key in order to sign TLS session. Both certificate and private key used for
signing the certificate form a asymmetric cryptographic key-pair. Revealing the traffic-private-key makes it possible to perform men-in-the-middle
type of attacks. Typically private-key is stored on the server’s hard disk. Even if it is stored in encrypted form, at some point HTTPS server 
needs to have a possibility to decrypt it in order to use for signing. It means that at runtime the key in plaintext will be available in a memory
of a HTTPS process. In case of software errors (see [Heartbleed](https://heartbleed.com/).
