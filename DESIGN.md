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

- _K1:_ HChacha20(ee, 0)
- _K2:_ HChacha20(es, 1) XOR K1
- _K3:_ HChacha20(se, 2) XOR K2
- _Ks:_ HChacha20(K3, 0)

The contents of the messages are:

- _Request:_ the sender's ephemeral public key _Es_ (plaintext).
- _Response:_ the recipient's ephemeral public key _Er_ (plaintext), and
  an authentication tag _T2_.
- _Confirmation:_ the sender's long term public key _Ls_ (encrypted with
  K2), and an authentication tag _T3_.

The authentication tags T2 and T3 are constructed thus:

    T2 = Poly1305(K2, Es || Er)
    T3 = Poly1305(K3, Es || Er || Chacha20(K2, Ls))

(They basically authenticate the transcript of the handshake, minus the
authentication tags themselves.)

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
use them to perform the handshake.

_What's up with using Poly1305 with the keys?_ Indeed, Poly1305 is a one
time authenticator. Using it twice with the same key instantly reveals
the key, so it is generally a very bad idea to use keys directly. K2 and
K3 however are thrown away when the handshake is done, so Poly1305 is
guaranteed to be used only once per key.

_Why is K3 hashed into Ks?_  While we could in principle use K3 as the
session key, Poly1305 has already been used once with it.  Users unaware
of the internals of the handshake, yet aware of the fact they can get
away with using Poly1305 once on a key, might be tempted to use it on
K3, without realising their use would be the _second_ one.  Better be
safe and provide a clean key.

An alternative would be to derive the authentication keys from K2 and K3
(using HChacha20), and use K3 as the session key.  This would spend an
additional run of HChacha20, and would ensure that no key is used for
both authentication and encryption.  We might need to switch to this
design if it turns out the keys used with Poly1305 are potentially
compromised after a single run (even if only partially compromise).
