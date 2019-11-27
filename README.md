# Aims

To be a low-level library for encoding, decoding, signing and verifying Json
Web Tokens


# Thoughts based on reviewing other implementations:

Use Auth0's [node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
and [java-jwt](https://github.com/auth0/java-jwt) implementations as models
to follow since Auth0 clearly have a lot of experience handling JWTs and so
their APIs should be battle tested and show the scope of functionality that
is needed in practice.

Consider that claims are extensible and make it possible for the claims to be
validated by mulitple interested parties (such as some AWS/Azure specific
middleware in addition to the user). This implies that we internally have to
fully deserialize the claims and so we can't internally work with a fixed
claims struct even if the user would like to get the results deserialized
into a custom struct. Deserializing into a custom claims struct should be
optional since it will always imply deserializing more than once which might
not be desirable.

Don't define a fixed Validation struct for configuring how to validate
claims. Again since claims can vary between environments we should find a way
that at least generalizes to validating arbitrary <String, String> key value
pairs. Notably Auth0's node.js API also allows validating the audience using a
set of regular expressions.

Having a separate, configurable Validator seems good in itself and then it
should be easy to construct validators for specific use cases; such as
validating Cognito ID or access tokens. With rust then it could make sense
to follow a builder pattern here.

Consider that the user may be interested in inspecting the decoded header and
claims and if so they shouldn't need to do a second decode after validating.

Decode keys/secrets once, upfront so they don't need to be re-parsed when
validating tokens. It seems like a good idea to borrow an idea from
`java-jwt` here and have a separate `Algorithm` be defined that can hold
any cryptographic state.

Support HMAC secrets that are optionally base64 encoded (seems common enough
that jwt.io and jsonwebtoken-node support this)


# Notable security considerations:

https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid

https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
TL;DR:
Don't blindly trust 'alg' in the header and make sure it matches what you expect,
otherwise you can be coerced into interpreting an RSA public key as a HMAC secret
or worse with 'none' might validate without any cryptographic check.

https://blogs.adobe.com/security/2017/03/critical-vulnerability-uncovered-in-json-encryption.html
TL;DR:
```
"At the end of the day, the issue here is that the specification and
consequently all the libraries that I checked missed validating that the
received public key (contained in the JWE Protected Header is on the curve).
You can see the Vulnerable Libraries section below to check how the various
libraries fixed the issue."
```
