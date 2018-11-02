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

Sender and recipient have the following X25519 key pairs:

- _Es:_ The sender's ephemeral key.
- _Ls:_ The sender's long term key.
- _Er:_ The recipient's ephemeral key.
- _Lr:_ The recipient's long term key.

Those key pairs are used to derive the following symmetric keys:

- _K1:_ HChacha20(X25519(Es, Er), 0)
- _K2:_ HChacha20(X25519(Es, Lr), 1) XOR K1
- _K3:_ HChacha20(X25519(Ls, Er), 2) XOR K2
- _AK2, EK2:_ Chacha20_stream(K2)
- _AK3, EK3:_ Chacha20_stream(K3)

(The authentication keys AK* use the first 32 bytes of the Chacha20
stream. The encryption keys EK* use the next 32 bytes. The streams'
nonce and counter are both zero.)

The messages contain the following (Es, Er, and Ls denote the public
half of the key pairs, and `||` denotes concatenation):

    XLs          = Ls XOR EK2

    request      = Es
    response     = Er  || Poly1305(AK2, Es || Er)
    confirmation = XLs || Poly1305(AK3, Es || Er || XLs)

The handshake proceeds as follows:

1. The sender sends the _request_ to the recipient.
2. The recipient receives the request, then sends its _response_.
3. The sender authenticates the response, and aborts if it fails.
4. The sender sends its _confirmation_ to the recipient.
5. The recipient decrypts & records the sender's transmitted public key.
6. The recipient authenticates the confirmation, and aborts if it fails.
7. The protocol is complete. The session key is _EK3_.


Rationale
---------

_Why not use Noise XK1 protocol directly?_ The Noise Protocol Framework
is quite general, and rather complex.  In practice though, one handshake
is enough in most situations.  Solving this one problem (interactive
handshake without assuming any prior exchange), is much simpler.

_Why HChacha20 instead of a real Hash like Blake2b?_ The idea is to
minimise the code necessary to setup and use the secure channel (less
code means smaller programs and less strain for the instruction cache).
Users are expected to use Chacha20/Poly1305 anyway, so we might as well
use them to perform the handshake.


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


protocol description
--------------------

Sender and recipient have the following X2519 key pairs:

- _Es:_ The sender's ephemeral key.
- _Ls:_ The sender's long term key.
- _Lr:_ The recipient's long term key.

Those key pairs are used to derive the following symmetric keys:

- _K1:_ HChacha20(X25519(Es, Lr), 0)
- _K2:_ HChacha20(X25519(Ls, Lr), 1) XOR K1
- _AK1, EK1:_ Chacha20_stream(K1)
- _AK2, EK2:_ Chacha20_stream(K2)

(The authentication keys AK* use the first 32 bytes of the Chacha20
stream. The encryption keys EK* use the next 32 bytes. The streams'
nonce an counter are both zero.)

The message contain the following (Es, Er, and Ls denote the public half
of the key pairs, and `||` denotes concatenation):

    XLs     = Ls XOR EK1
    message = Es || XLs || Poly1305(AK2, Es || XLs)

The handshake proceeds as follows:

1. The sender sends the _message_ to the recipient.
2. The recipient decrypts & records the sender's transmitted public key.
3. The recipient authenticates the message, and aborts if it fails.
4. The protocol is complete. The session key is _EK2_.


Rationale
---------

The same as for the interactive handshake.
