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
- __es__ = X25519(es, LR) = X25519(lr, ES)
- __se__ = X25519(ls, ER) = X25519(er, LS)

Those shared secrets are hashed to derive the following keys:

- __CK1:__ HChacha20(ee, zero) XOR HChacha20(zero, one)
- __CK2:__ HChacha20(es, zero) XOR HChacha20(CK1 , one)
- __CK3:__ HChacha20(se, zero) XOR HChacha20(CK2 , one)
- __AK2:__ Chacha20(CK2, one)[ 0:31]
- __EK2:__ Chacha20(CK2, one)[32:63]
- __AK3:__ Chacha20(CK3, one)[ 0:31]
- __EK3:__ Chacha20(CK3, one)[32:63]

_("[x:y]" denotes a range; zero and one are encoded in little endian
format)._

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

__Why keys are derived with HChacha20 instead of HKDF?__ The handshake
is intened to be used for a ChachaPoly based AEAD session.  Using
HChacha20 allows us to avoid brining in another primitive.  It's also
faster than HKDF.


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

- __es__ = X25519(es, LR) = X25519(lr, ES)
- __ss__ = X25519(ls, LR) = X25519(lr, LS)

Those shared secrets are hashed to derive the following keys:

- __CK1:__ HChacha20(es, zero) XOR HChacha20(zero, one)
- __CK2:__ HChacha20(ss, zero) XOR HChacha20(CK1 , one)
- __AK1:__ Chacha20(CK1, one)[ 0:31]
- __EK1:__ Chacha20(CK1, one)[32:63]
- __AK2:__ Chacha20(CK2, one)[ 0:31]
- __EK2:__ Chacha20(CK2, one)[32:63]

_("[x:y]" denotes a range; zero and one are encoded in little endian
format)._

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
