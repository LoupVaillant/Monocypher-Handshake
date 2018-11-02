Security Analysis
=================

Here is is an informal security analysis of the handshake.

Goals
-----

- __Forward secrecy:__ the session key must not be compromised even if
  the long term keys are leaked after the handshake.
- __Anonymity:__ to the extent possible, the handshake must not leak the
  identities of the parties involved.
- __Key compromise impersonation resistance:__ sender and recipient must
  retain their ability to authenticate the other party even if their own
  long term key was compromised prior to the handshake.
- __Deniability:__ No one should be able to prove the communication
  actually took place.  Both parties should be able to forge the
  messages involved in the handshake.


Key derivation
--------------

- __Assumption (1):__ When the private keys involved in an X25519 key
  exchange are unknown, The HChacha20 of the shared secret is
  indistinguishable from random. _Rationale: DJB said Salsa20 is a
  suitable way to derive keys from shared secret. in his Curve25519
  paper._

- __Assumption (2):__ For any shared secret `ss`, and any nonce `i` and
  `j` such that `i≠j`; `HChacha20(ss, i)` and `HChacha20(ss, j)` are
  independent. _Rationale: Chacha20 is a stream cipher in CTR mode. The
  same can be done with HChacha20._

- __Assumption (3):__ Chacha20 is a secure stream cipher.  It produces a
  uniformly random output when its key is uniformly random. _Rationale:
  Show me the cryptanalysis._

The chaining keys `K1`, `K2`, and `K3` are constructed thus:

    Es = Sender's ephemeral key.
    Ls = Sender's long term key.
    Er = Recipient's ephemeral key.
    Lr = Recipient's long term key.

    H1 = HChacha20(X25519(Es, Er), 0)
    H2 = HChacha20(X25519(Es, Lr), 1) XOR K1
    H3 = HChacha20(X25519(Ls, Er), 2) XOR K2

    K1 = H1
    K2 = H1 XOR H2
    K3 = H1 XOR H2 XOR H3

Note that:

- `H1` looks random iff the private halves of `Es` and `Er` are unknown.
- `H2` looks random iff the private halves of `Es` and `Lr` are unknown.
- `H3` looks random iff the private halves of `Ls` and `Er` are unknown.

From Assumption (2), we can deduce that:

- `K1` looks random iff `H1` looks random.
- `K2` looks random iff `H1` _or_ `H2` looks random.
- `K3` looks random iff `H1` _or_ `H2` _or_ `H3` looks random.

That is, using XOR won't allow secrets to cancel each other out, because
the 3 HChacha20 are independent, thanks to using different nonces.

__Conclusion:__ the derivation of the chaining keys K1, K2, and K3 are
as good as the following (the `||` operator denotes concatenation):

    k1 = HKDF(X25519(Es, Er))
    k2 = HKDF(X25519(Es, Lr) || k1)
    k3 = HKDF(X25519(Ls, Er) || k2)


### Authentication, encryption, and session keys

Four keys are derived from the chaining keys `K2` and `K3`: the
authentication keys AK2 and AK3, and the encryption keys EK2 and EK3.

    AK2 || EK2 = Chacha20_stream(K2)
    AK3 || EK3 = Chacha20_stream(K3)

From assumption (3) (security of Chacha20 as a stream cipher):

- Revealing AK2 does not leak information about EK2 or K2.
- Revealing AK3 does not leak information about EK3 or K3.
- Revealing EK2 does not leak information about AK2 or K2.

__Conclusion:__

- AK2 can be used as the authentication key for Poly1305.  Once.
- AK3 can be used as the authentication key for Poly1305.  Once.
- EK2 can be used as a random stream, to encrypt _one_ message.

Note that AK2 and AK3 are used for one authentication each, and EK2 is
used for exactly one encryption.  Since EK3 isn't used for anything, it
can safely be the session key.


Interactive handshake
---------------------

The interactive handshake involves 3 messages: the _request_, the
_response_, and the _confirmation_, containing the following:

    XLs          = Ls XOR EK2

    request      = Es
    response     = Er  || Poly1305(AK2, Es || Er)
    confirmation = XLs || Poly1305(AK3, Es || Er || XLs)


### Request

The request contains the sender's ephemeral key, unencrypted,
unauthenticated. It's content do not reveal the identity of either
party. Attackers learn nothing from this message alone.

On the other hand, an active attacker can intercept the messages, and
send their own. In particular, they can:

- Replace the genuine ephemeral key by their own.
- Replace the genuine ephemeral key by a short order key.
- Replay an old request, with a genuine obsolete sender's key.

Therefore, a recipient that receives a request cannot assume anything
about it.


### Response (as sent by the recipient)

The response contains the recipient's ephemeral key, and a MAC (Message
Authentication Code) of the transcript.  The MAC uses the key AK2, which
is derived from the following key exchanges:

- `X25519(Es, Er)` (Let's call this shared secret `ee`)
- `X25519(Es, Lr)` (Let's call this shared secret `es`)

`Es` might come from the sender, or from an active attacker.  `Er` comes
from the recipient, and is unknown to the attacker. `Lr` comes from the
recipient, and is not _yet_ known by the attacker.

If `Es` indeed came from the sender (whether this is a replay or not),
the attacker will never be able to guess `ee`.  Even if they compromise
`Lr` later, they won't be able to guess `AK2`, and won't be able to
interpret the MAC.

If `Es` is a low order point, the shared secrets, and therefore K2, will
be a known constant.  The MAC will be independent from `Lr`, and won't
leak the identity of the recipient.

If `Es` comes from the attacker, the tag will leak the identity of the
recipient (the attacker has to try all known public keys to get to the
right one).  __An active attacker can learn that the recipient is able
and willing to accept connections.__ Not very incriminating, but still
worth pointing out.


### Response (as received by the sender)

The MAC of the response authenticates both `Es` and `Er`, with `AK2`,
which is derived from both `ee` and `es`.  After the reception of the
message, the sender's transcript will contain the public half of two
ephemeral keys:

- `Es`, which they sent themselves.
- `Er`, which they just received, and could come from an attacker.

They will then check the MAC against their transcript, and abort the
protocol if it doesn't match.

The only way to construct a genuine looking MAC is to somehow:

- Authenticate `Es` (the one sent by the sender);
- authenticate some `Er` (which may come from the attacker);
- be able to guess both `ee` and `es`, to derive `AK2`.

Any active attacker can guess `ee`: they just provide their own `Er`, of
which they would know the private half (or provide a low order point,
forcing `ee` to be a known constant).  On the other hand, besides the
sender, only the recipient can guess `es`: no one else knows the private
halves of either `Es` or `Lr`.  Thus, only the recipient can
authenticate the transcript.

Attackers cannot replay old responses or otherwise modify `Es`: the
transcript won't match, and the MAC won't look genuine.

__Conclusion:__ The response has been sent by the recipient, for this
session.  The key `Er` comes from them, the shared secret `ee` is
unknown to the attacker, and `K2` (and by extension the session key
`EK3`) enjoys forward secrecy (it won't be compromised even if the long
term keys `Ls` or `Lr` get compromised later on).

Moreover, the sender hasn't used their own long term key `Ls` yet.  They
can ascertain the identity of the recipient even if it is compromised.
The sender is therefore resistant to key compromise impersonation.


### Confirmation (as sent by the sender)

At this point, `K2` is secure and provides forward secrecy.  Therefore,
so does `EK2`, which is derived from it.

The confirmation contains the sender's public key, XORed with `EK2`
(both are 32-bytes long), and the MAC of the transcript.  Since `EK2` is
uniformly random, so is `Ls XOR EK2`.  It therefore leaks no
information (and never will, thanks to forward secrecy).

The MAC authenticates the transcript with `AK3`, which being derived
from `K2` also enjoy forward secrecy.  The attackers therefore cannot
predict `AK3`, cannot interpret the MAC, and cannot guess anyone's
identity.

__Conclusion:__ The sender is anonymous, now and forever.


### Confirmation (as received by the recipient)

The response contains `Ls` (encrypted), and a MAC of the
transcript. When the recipient receives it, their transcript will
contain the following:

- `Es`, which could have been sent by anyone.
- `Er`, which the recipient have sent.
- `Ls XOR EK2`, which an attacker might try to forge.

The only way to produce a genuine looking MAC is to somehow:

- Authenticate some `Es` (which may have come from the attacker);
- Authenticate `Er` (the one sent by the recipient);
- Authenticate `Ls XOR EK2` (which may have come from the attacker);
- Know `ee`, `es`, and `se`.

Only the recipient knows the private half of `Er`. Therefore, the only
way to know both `ee` and `se` is to provide _both_ `Es` and `Ls`.

Attackers cannot replay old confirmations or otherwise modify `Er`: the
transcript won't match, and the MAC won't look genuine.

__Conclusion:__ The request and the confirmation came from the same
person, for the present session.  __That person could be an attacker.__
Even though the protocol has successfully completed, the application must
authenticate `Ls` itself (for instance by checking a list of known
contacts).  If `Ls` is the public key of a trusted contact, the
connection is secure, and enjoys forward secrecy.

Note that the recipient's long term key `Lr` is not involved in the
shared secrets `ee` and `se`, so the above holds even if `Lr` was
compromised.  The recipient is resistant to key compromise
impersonation.


Deniability
-----------

All authentication is done with symmetric crypto, using the shared
secrets generated by the key exchanges.  To verify a MAC, both parties
actually _generate_ a MAC, then compare it to what they received.
Forging a genuine looking transcript is trivial for both parties, so no
one can prove the handshake actually took place.

To maximize effective deniability, though, applications should provide
an easy way to edit messages that were exchanged after the fact.

Users who want _accountability_ instead can use public key signatures.
