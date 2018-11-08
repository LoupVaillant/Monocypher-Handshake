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

The ultimate goal of key derivation is that:

1. __AK2__ and __EK2__ are uniformly random and independent from each
   other, if:

   - __es__ and __er__ are uniformly random, _OR_
   - __es__ and __lr__ are uniformly random.

2. __AK2__ and __AK3__ are uniformly random, independent from each
   other, and independent from __AK2__ and __EK2__, if:

   - __es__ and __er__ are uniformly random, _OR_
   - __es__ and __lr__ are uniformly random. _OR_
   - __ls__ and __er__ are uniformly random.

I am currently trying to achieve that with a pure Chacha20 based scheme,
under the assumption that hashing a single X25519 shared secret with
HChacha20 is safe.

Hashing several of them however is more delicate, and I have yet to come
up with a suitable security reduction. Should I fail, I will change the
current scheme to something that uses Blake2b (keyed mode).


### Authentication, encryption, and session keys

Four keys are derived from the chaining keys _K2_ and _K3_: the
authentication keys AK2 and AK3, and the encryption keys _EK2_ and
_EK3_.

    AK2 || EK2 = Chacha20_stream(K2)
    AK3 || EK3 = Chacha20_stream(K3)

From assumption (3) (security of Chacha20 as a stream cipher):

- Revealing _AK2_ does not leak information about _EK2_ or _K2_.
- Revealing _AK3_ does not leak information about _EK3_ or _K3_.
- Revealing _EK2_ does not leak information about _AK2_ or _K2_.

__Conclusion:__

- _AK2_ can be used as the authentication key for Poly1305.  Once.
- _AK3_ can be used as the authentication key for Poly1305.  Once.
- _EK2_ can be used as a random stream, to encrypt _one_ message.

Note that _AK2_ and _AK3_ are used for one authentication each, and
_EK2_ is used for exactly one encryption.  Since _EK3_ isn't used for
anything, it can safely be the session key.


Interactive handshake
---------------------

The interactive handshake involves 3 messages: the _request_, the
_response_, and the _confirmation_, containing the following:

    XS           = Ls XOR EK2

    request      = ES
    response     = ER || Poly1305(AK2, LR || ES || ER)
    confirmation = XS || Poly1305(AK3, LR || ES || ER || XS)


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

- __<ee>__ = X25519(es, ER) = X25519(er, ES)
- __<el>__ = X25519(es, LR) = X25519(lr, ES)

_ES_ might come from the sender, or from an active attacker.  _ER_ comes
from the recipient, and is unknown to the attacker. _LR_ comes from the
recipient, and is not yet known to the attacker.

If _ES_ indeed came from the sender (whether this is a replay or not),
the attacker will never be able to guess _<ee>_.  Even if they
compromise _LR_ later, they won't be able to guess _AK2_, and won't be
able to interpret the MAC.

If _ES_ is a low order point, the shared secrets, and therefore _K2_,
will be a known constant.  The MAC will be independent from _LR_, and
won't leak the identity of the recipient.

If _ES_ comes from the attacker, the tag will leak the identity of the
recipient (the attacker has to try all known public keys to get to the
right one).  __An active attacker can learn that the recipient is able
and willing to accept connections.__ Not very incriminating, but still
worth pointing out.


### Response (as received by the sender)

The MAC of the response authenticates both _ES_ and _ER_, with _AK2_,
which is derived from both _<ee>_ and _<el>_.  After the reception of the
message, the sender's transcript will contain the public half of two
ephemeral keys:

- _ES_, which they sent themselves.
- _ER_, which they just received, and could come from an attacker.

They will then check the MAC against their transcript, and abort the
protocol if it doesn't match.

The only way to construct a genuine looking MAC is to somehow:

- Authenticate _ES_ (the one sent by the sender);
- authenticate some _ER_ (which may come from the attacker);
- be able to guess both _<ee>_ and _<el>_, to derive _AK2_.

Any active attacker can guess _<ee>_: they just provide their own _ER_,
so they can know _er_ (or provide a low order point, forcing _<ee>_ to
be a known constant).  On the other hand, besides the sender, only the
recipient can guess _<el>_: no one else knows either _es_ or _lr_.
Thus, only the recipient can authenticate the transcript.

Attackers cannot replay old responses or otherwise modify _ES_: the
transcript won't match, and the MAC won't look genuine.

__Conclusion:__ The response has been sent by the recipient, for this
session.  The key _ER_ comes from them, the shared secret _<ee>_ is
unknown to the attacker, and _K2_ (and by extension the session key
_EK3_) enjoys forward secrecy (it won't be compromised even if _LS_ or
_LR_ get compromised later on).

Moreover, the sender hasn't used _LS_ yet.  They can ascertain the
identity of the recipient even if it is compromised.  The sender is
therefore resistant to key compromise impersonation.


### Confirmation (as sent by the sender)

At this point, _K2_ is secure and provides forward secrecy.  Therefore,
so does _EK2_, which is derived from it.

The confirmation contains _LS XOR EK2_, and the MAC of the transcript.
Since _EK2_ is uniformly random, so is _LS XOR EK2_.  It therefore leaks
no information (and never will, thanks to forward secrecy).

The MAC authenticates the transcript with _AK3_, which being derived
from _K2_ also enjoy forward secrecy.  The attackers therefore cannot
predict _AK3_, cannot interpret the MAC, and cannot guess anyone's
identity.

__Conclusion:__ The sender is anonymous, now and forever.


### Confirmation (as received by the recipient)

The response contains _LS_ (encrypted), and a MAC of the
transcript. When the recipient receives it, their transcript will
contain the following:

- _ES_, which could have been sent by anyone.
- _ER_, which the recipient have sent.
- _LS XOR EK2_, which an attacker might try to forge.

The only way to produce a genuine looking MAC is to somehow:

- Authenticate some _ES_ (which may have come from the attacker);
- Authenticate _ER_ (the one sent by the recipient);
- Authenticate _LS XOR EK2_ (which may have come from the attacker);
- Know _<ee>_, _<el>_, and _<le>_.

Only the recipient knows _er_. Therefore, the only way to know both
_<ee>_ and _<le>_ is to provide _both_ _ES_ and _LS_.

Attackers cannot replay old confirmations or otherwise modify _ER_: the
transcript won't match, and the MAC won't look genuine.

__Conclusion:__ The request and the confirmation came from the same
person, for the present session.  __That person could be an attacker.__
Even though the protocol has successfully completed, the application must
authenticate _LS_ itself (for instance by checking a list of known
contacts).  If _LS_ is the public key of a trusted contact, the
connection is secure, and enjoys forward secrecy.

Note that the recipient's long term key _LR_ is not involved in the
shared secrets _<ee>_ and _<le>_, so the above holds even if _LR_ was
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
