Interactive Handshake Design
============================

This protocol is almost a direct instantiation of the XK1 pattern from
the [Noise Protocol Framework](https://noiseprotocol.org/), simplified
under the assumptions that this is all users will ever need for
interactive sessions.

XK1 was chosen because it has the best identity hiding properties.  It
assumes the sender knows the recipient's public key before hand, but I
felt this wasn't a meaningful requirement, since the sender is trying to
contact the recipient in the first place.

The recipient however doesn't need to know of the sender's public key:
it is transmitted as part of the handshake. (It can then be used as a
sender ID.)


Protocol description
--------------------

Sender and recipient have the following X25519 key pairs (private half
in lower case, public half in upper case):

- __(es, ES)__ The sender's ephemeral key.
- __(ls, LS)__ The sender's long term key.
- __(er, ER)__ The recipient's ephemeral key.
- __(lr, LR)__ The recipient's long term key.

Those key pairs are used to derive the following shared secrets:

- __ee__ = X25519(es, ER) = X25519(er, ES)
- __el__ = X25519(es, LR) = X25519(lr, ES)
- __le__ = X25519(ls, ER) = X25519(er, LS)

Those shared secrets are hashed to derive the following keys:

- __CK1:__ Blake2b-256(zero, ee)
- __CK2:__ Blake2b-256(CK1 , el)
- __CK3:__ Blake2b-256(CK2 , le)
- __AK2:__ Blake2b-512(CK2)[ 0:31]
- __EK2:__ Blake2b-512(CK2)[32:63]
- __AK3:__ Blake2b-512(CK3)[ 0:31]
- __EK3:__ Blake2b-512(CK3)[32:63]

_("[x:y]" denotes a range; Blake2b-256 is used in keyed mode, with the
key on the left.)_

The messages contain the following (`||` denotes concatenation):

    XS           = LS XOR EK2

    request      = ES
    response     = ER || Poly1305(AK2, LR || ES || ER)
    confirmation = XS || Poly1305(AK3, LR || ES || ER || XS)

The handshake proceeds as follows:

1. The sender sends the _request_ to the recipient.
2. The recipient receives the request, then sends its _response_.
3. The sender verifies the response, and aborts if it fails.
4. The sender sends its _confirmation_ to the recipient.
5. The recipient verifies the confirmation, and aborts if it fails.
6. The recipient decrypts & records the sender's transmitted public key.
7. The protocol is complete. The session key is _EK3_.


Rationale
---------

__Why not use Noise directly?__ The Noise Protocol Framework is quite
general, and rather complex.  In practice though, one handshake is
enough in most situations.  Solving this one problem (interactive
handshake without assuming any prior exchange), is much simpler.

__Why Blake2b instead of the real HKDF?__ One intended use case for
Blake2b was key derivation.  It's safe.  It's also simpler and faster
than HKDF, which requires a significant amount of hashes. (We would call
the hash function 32 times instead of the current 7.)


One way Handshake design
========================

This protocol is a direct instantiation of the X pattern from the Noise
Protocol Framework, simplified under the assumptions that this is all
users will ever need for one way messages. (In practice, they may need
the N pattern as well, but then `crypto_key_exchange()` is all they
need).

One way handshakes cannot be as secure as interactive handshakes. This
one for instance fails as soon as the recipient's private key is leaked:
the message is disclosed, the identity of the sender is uncovered, and
the recipient can no longer authenticate messages.  It's also vulnerable
to replay attacks.

You don't want to send such messages to sloppy recipients.


Protocol description
--------------------

Sender and recipient have the following X25519 key pairs (private half
in lower case, public half in upper case):

- __(es, ES)__ The sender's ephemeral key.
- __(ls, LS)__ The sender's long term key.
- __(lr, LR)__ The recipient's long term key.

Those key pairs are used to derive the following shared secrets:

- __el__ = X25519(es, LR) = X25519(lr, ES)
- __ll__ = X25519(ls, LR) = X25519(lr, LS)

Those shared secrets are hashed to derive the following keys:

- __CK1:__ Blake2b-256(zero, el)
- __CK2:__ Blake2b-256(CK1 , ll)
- __AK1:__ Blake2b-512(CK1)[ 0:31]
- __EK1:__ Blake2b-512(CK1)[32:63]
- __AK2:__ Blake2b-512(CK2)[ 0:31]
- __EK2:__ Blake2b-512(CK2)[32:63]

_("[x:y]" denotes a range; Blake2b-256 is used in keyed mode, with the
key on the left.)_

The message contain the following (`||` denotes concatenation):

    XS      = LS XOR EK1
    message = ES || XS || Poly1305(AK2, LR || ES || XS)

The handshake proceeds as follows:

1. The sender sends the _message_ to the recipient.
2. The recipient decrypts & records the sender's transmitted public key.
3. The recipient verifies the message, and aborts if it fails.
4. The protocol is complete. The session key is _EK2_.


Rationale
---------

The same as for the interactive handshake.
