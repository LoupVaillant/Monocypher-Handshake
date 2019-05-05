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

Those shared secrets are hashed to derive the following:

- For all i > 0:
  - __Ci__ = __Hi__[ 0:31]
  - __Ki__ = __Hi__[31:63]
  - __Ti__ = __Hi__[31:47]

- __C0__  = "Monokex XK1" _(32 bytes, ASCII encoded, zero padded)_
- __H1__  = Blake2b(C0  || prelude), or H0 if there is no prelude
- __H2__  = Blake2b(C1  || RS)
- __H3__  = Blake2b(C2  || IE)
- __H4__  = Blake2b(C3  || RE)
- __H5__  = Blake2b(C4  || ee)
- __H6__  = Blake2b(C5  || es)
- __H7__  = Blake2b(C6  || EP2), or H6 if msg2 has no payload
- __H8__  = Blake2b(C7)
- __H9__  = Blake2b(C8  || IS XOR K8)
- __H10__ = Blake2b(C9  || ss)
- __H11__ = Blake2b(C10 || EP3), or H10 if msg3 has no payload
- __H12__ = Blake2b(C11)

_("||" denodes concatenation; "[x:y]" denotes a range; C0 is 32 bytes,
ASCII encoded, zero padded.)_

Payloads, if any, are as follows:

- __UP1__ = payload1                or nothing if there is no payload1
- __EP2__ = Chacha20(K6 , payload2) or nothing if there is no payload2
- __EP3__ = Chacha20(K10, payload3) or nothing if there is no payload3

The messages contain the following:

- XIS  = IS XOR EK2

- __msg1__ = IE        || UP1
- __msg2__ = RE        || EP2 || T7
- __msg3__ = IS XOR K8 || EP3 || T11

The handshake proceeds as follows:

- The initiator sends msg1 to the respondent.
- The respondent receives msg1.
- The respondent sends msg2 to the initiator.
- The initiator verifies msg2, and aborts if it fails.
- The initiator sends msg3 to the respondent.
- The respondent verifies msg3, and aborts if it fails.
- The respondent checks the initiator's static key, and aborts if it fails.
- The protocol is complete.  The session keys are C11 and K11.


Rationale
---------

__Why not use Noise directly?__ The Noise Protocol Framework is quite
general, and rather complex.  In practice though, one handshake is
enough in most situations.  Solving this one problem (interactive
handshake without assuming any prior exchange), is much simpler.


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

Those shared secrets are hashed to derive the following:

- For all i > 0:
  - __Ci__ = __Hi__[ 0:31]
  - __Ki__ = __Hi__[31:63]
  - __Ti__ = __Hi__[31:47]

- __C0__ = "Monokex XK1" _(32 bytes, ASCII encoded, zero padded)_
- __H1__ = Blake2b(C0 || prelude), or H0 if there is no prelude
- __H2__ = Blake2b(C1 || RS)
- __H3__ = Blake2b(C2 || IE)
- __H4__ = Blake2b(C3 || es)
- __H5__ = Blake2b(C4 || IS XOR K4)
- __H6__ = Blake2b(C5 || ss)
- __H7__ = Blake2b(C6 || EP2), or H6 if msg1 has no payload
- __H8__ = Blake2b(C7)

_("||" denodes concatenation; "[x:y]" denotes a range)_

Payloads, if any, are as follows:

- __EP1__ = Chacha20(K6 , payload1) or nothing if there is no payload2

The messages contain the following:

- __msg1__ = IE || IS XOR K4 || EP1 || T7

The handshake proceeds as follows:

- The initiator sends msg1 to the respondent.
- The respondent verifies msg1, and aborts if it fails.
- The respondent checks the initiator's static key, and aborts if it fails.
- The protocol is complete.  The session key is EK2.


Rationale
---------

The same as for the interactive handshake.
