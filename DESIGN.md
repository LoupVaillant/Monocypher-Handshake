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

- __(is, IS)__ The initiator's static key.
- __(ie, IE)__ The initiator's ephemeral key.
- __(rs, RS)__ The respondent's static key.
- __(re, RE)__ The respondent's ephemeral key.

Those key pairs are used to derive the following shared secrets:

- __ee__ = X25519(ie, RE) = X25519(re, IE)
- __es__ = X25519(ie, RS) = X25519(rs, IE)
- __se__ = X25519(is, RE) = X25519(re, IS)

Those shared secrets are hashed to derive the following keys:

- __CK1:__ HChacha20(ee, zero) XOR HChacha20(zero, one)
- __CK2:__ HChacha20(es, zero) XOR HChacha20(CK1 , one)
- __CK3:__ HChacha20(se, zero) XOR HChacha20(CK2 , one)
- __AK2:__ Chacha20(CK2, one)[ 0:31]
- __AK3:__ Chacha20(CK3, one)[ 0:31]
- __EK2:__ Chacha20(CK2, one)[32:63]
- __EK3:__ Chacha20(CK3, one)[32:63]

_("[x:y]" denotes a range; zero and one are encoded in little endian
format.)_

The messages contain the following (`||` denotes concatenation):

    XIS  = IS XOR EK2

    msg1 = IE
    msg2 = RE  || Poly1305(AK2, RS || IE || RE)
    msg3 = XIS || Poly1305(AK3, RS || IE || RE || XIS)

Note that RS is shared in advance.
The handshake proceeds as follows:

- The initiator sends msg1 to the respondent.
- The respondent receives msg1.
- The respondent sends msg2 to the initiator.
- The initiator verifies msg2, and aborts if it fails.
- The initiator sends msg3 to the respondent.
- The respondent verifies msg3, and aborts if it fails.
- The respondent checks the initiator's static key, and aborts if it fails.
- The protocol is complete.  The session key is EK3.


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

- __(is, IS)__ The initiator's static key.
- __(ie, IE)__ The initiator's ephemeral key.
- __(rs, RS)__ The respondent's static key.

Those key pairs are used to derive the following shared secrets:

- __es__ = X25519(ie, RS) = X25519(rs, IE)
- __ss__ = X25519(is, RS) = X25519(rs, IS)

Those shared secrets are hashed to derive the following keys:

- __CK1:__ HChacha20(es, zero) XOR HChacha20(zero, one)
- __CK2:__ HChacha20(ss, zero) XOR HChacha20(CK1 , one)
- __AK2:__ Chacha20(CK2, one)[ 0:31]
- __EK1:__ Chacha20(CK1, one)[32:63]
- __EK2:__ Chacha20(CK2, one)[32:63]

_("[x:y]" denotes a range; zero and one are encoded in little endian
format.)_

The messages contain the following (`||` denotes concatenation):

    XIS  = IS XOR EK1

    msg1 = IE || XIS || Poly1305(AK2, RS || IE || XIS)

Note that RS is shared in advance.
The handshake proceeds as follows:

- The initiator sends msg1 to the respondent.
- The respondent verifies msg1, and aborts if it fails.
- The respondent checks the initiator's static key, and aborts if it fails.
- The protocol is complete.  The session key is EK2.


Rationale
---------

The same as for the interactive handshake.
