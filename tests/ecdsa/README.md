Note that Ring does not support SEC1 format private elliptic curve keys
(I.e containing markers like `-----BEGIN EC PRIVATE KEY-----`) so they instead
need to be converted to PKCS#8 format.

Unfortunately the example keys found on jwt.io use the SEC1 format so there's
a reasonable chance that anyone testing this API might hit this limitation.

SEC1 private keys can be converted with openssl like this:

```
openssl pkcs8 -nocrypt -in private_ecdsa_key_jwtio_p256.pem -topk8 -out private_ecdsa_key_jwtio_p256_pkcs8.pem
```
