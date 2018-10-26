Interactive Handshake Design
============================

This protocol is almost a direct instantiation of the XK1 pattern from
the [Noise Protocol Framework](https://noiseprotocol.org/), simplified
under the assumptions that this is all users will ever need for
interactive sessions.

The choice of the XK1 pattern was made because it looked like it would
be the most useful, and it has the best identity hiding properties of
all the Noise handshakes.

The handshake assumes the sender knows the recipient's public key before
hand. Since the sender is trying to contact the recipient in the first
place, I felt this was a fair assumption.

The recipient however doesn't need to know of the sender's public key:
it is transmitted as part of the handshake. (It can then be used as a
sender ID.)


Protocol description
--------------------

The handshake comprises 3 messages:

1. The _request_, from the sender to the recipient.
2. The _response_, from the recipient to the sender.
3. The _confirmation_, from the sender to the recipient.

The handshake involves the following X25519 shared secrets:

- _ee:_ The shared secret between the ephemeral keys.
- _es:_ The shared secret between the sender's ephemeral key, and the
  recipient's long term key.
- _se:_ The shared secret between the sender's long term key, and the
  recipient's ephemeral key.

Those shared secrets are used to derive the following keys:

- _K1:_ HChacha20(ee)
- _K2:_ HChacha20(es) XOR K1
- _K3:_ HChacha20(se) XOR K2
- _Ks:_ Chacha20_stream(K3) (bytes 32 to 63)

The contents of the messages are:

- _Request:_ the sender's ephemeral public key _Es_ (plaintext).
- _Response:_ the recipient's ephemeral public key _Er_ (plaintext), and
  an authentication tag _T2_.
- _Confirmation:_ the sender's long term public key _Ls_ (encrypted with
  K2), and an authentication tag _T3_.

The authentication tags T2 and T3 are constructed thus:

    T2 = Poly1305(Chach20_stream(K2), Es || Er)
    T3 = Poly1305(Chach20_stream(K3), Es || Er || Chacha20(K2, Ls))

(We use the first 32 bytes of the Chacha20 stream, with nonce 0.  Note
that the authentication of the second message is not authenticated. )

The handshake aborts if the sender gets an invalid tag T2, or if the
recipient gets an invalid tag T3. Otherwise, the handshake succeeds, and
the shared secret key Ks can then be used as a symmetric session key.


Rationale
---------

_Why not use Noise XK1 protocol directly?_ The Noise Protocol Framework
is quite general, and rather complex.  In practice though, one handshake
is enough in most situations.  Solving this one problem (interactive
handshake without assuming any prior exchange), is much simpler.

_Why HChacha20 instead of a real Hash like Blake2b?_ The idea is to
minimise the code necessary to setup and use the secure channel (less
code means smaller programs and less strain for the instruction cache).
Users are expected to use Chacha20/Poly1305, anyway, we might as well
use them to perform the handshake. As a bonus, it also leverages the
`crypto_key_exchange()` API.

_Why is K3 hashed into Ks?_ To avoid nonce reuse.  K3 is used to
authenticate the last message with nonce 0 and counter 0, which the user
might reuse by accident. We could change those values, but it is simpler
to just provide an untainted key.  The cost is negligible anyway, since
a Chacha block can hold both an authentication key and a derived key.


One way Handshake design
========================

This protocol is a direct instantiation of the X pattern from the Noise
Protocol Framework, simplified under the assumptions that this is all
users will ever need for one way messages. (In practice, they may need
the N pattern as well, but then `crypto_key_exchange()` is all they
need).

One way handshake cannot be as secure as interactive handshake. This one
for instance crumbles as soon as the recipient's private key is leaked:
the message is disclosed, the identity of the sender is uncovered, and
the recipient can no longer authenticate messages.  It's also vulnerable
to replay attacks.

You don't want to send such messages to sloppy recipients.


protocol description
--------------------

The one way handshake involves the following shared secrets:

- _es:_ The shared secret between the sender's ephemeral key, and the
  recipient's long term key.
- _ss:_ The shared secret between the sender's long term key, and the
  recipient's long term key.

Those shared secrets are used to derive the following keys:

- _K1:_ HChacha20(es)
- _K2:_ HChacha20(ss) XOR K1
- _Ks:_ Chacha20_stream(K2) (bytes 32 to 63)

The key K2 is used to generate the authentication tag _T2_:

    T2 = Poly1305(Chach20_stream(K2), Es || Chacha20(K1, Ls))

The content of the message is (from beginning to end):

- The sender's ephemeral key _Es_, in plain text.
- The sender's long term key _Ls_, encrypted with K1.
- The authentication tag _T2_.

The sender sends that message, the recipient receives and verify that
message.  If the verification is successful, the protocol completes.
Otherwise, it aborts.


Rationale
---------

The same as for the interactive handshake.
