Security Analysis
=================

Here is an informal security analysis of the handshake.

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

Key derivation must ensure that if any shared secret is indeed secret,
all output keys using this shared secret must be indistinguishable from
uniformly random, and they must be independent from each other.

For this, we use a cascading scheme involving the following:

- __IK(i-1):__ previous intermediate key
- __ss(i):__ current shared secret
- __HK(i):__ current hashed shared secret
- __CK(i):__ current chaining key
- __AK(i):__ current authentication key
- __EK(i):__ current encryption key
- __IK(i):__ current intermediate key

From the current shared secret and the previous chaining key, we derive
all current keys thus:

    CK(0) = zero
    HK(i) = HChacha20(ss(i), zero)
    CK(i) = HK(i) XOR IK(i-1)
    AK(i) = Chacha20(CK(i), one)[ 0:31]
    EK(i) = Chacha20(CK(i), one)[32:63]
    IK(i) = HChacha20(CK(i-1), one)

This is an extract-expand scheme, where __CK(i)__ is extracted from
__ss(i)__ and __IK(i-1)__, to then be expanded into __AK(i)__,
__EK(i)__, and __IK(i)__.

__Notation:__ by "random", we mean "indistinguishable from uniformly
random in a feasible amount of computation".

__Assumption 1:__ HChacha20 is a random oracle when its input is an
X25519 shared secret.  Justification: The NaCl crypto library uses
HSalsa20 for its own key exchanges.

Therefore, if the attacker doesn't know the private keys involved in the
ss(i) exchange, then HK(i) will be random.  Moreover, if the attacker
cannot determine that those private keys are the same as some other
private key, HK(i) will be _independently_ random.

__Theorem 2:__ if A and B are independent, and at least one of them is
random, then A XOR B is random. Justification: obvious.

__Corollary 3:__ if IK(i-1) is an independent random string, then so is
CK(i).

__Corollary 4:__ if ss(i) is secret then CK(i) is random.

__Assumption 5:__ if CK(i) is random, then AK(i), EK(i), and IK(i) are
independent random strings. Justification: from the security model of
Chacha20. We have a random key CK(i), and different nonces: AK(i) and
EK(i) are produced with nonce 1 (and counter 0), and IK(i) is produced
with nonce 0 (and counter 1).

__Corollary 6 (induction):__ if IK(i-1) is an independent random
string, then so are AK(i), EK(i), and IK(i). Justification: from (3) and
(5).

__Corollary 7 (initialisation):__ if ss(1) is secret, then AK(1), EK(1),
and IK(1) are independent random strings. Justification: from (4) and
(5).

__Conclusion:__ for any i and j such that i < j, if ss(i) is secret,
then AK(j) and EK(j) are independently random.

__Note:__ IK(i) and HK(i) could use the same counter without affecting
the analysis. If they did, however, an attacker that knows ss(i-1) and
controls ss(i) could make ss(i) be HChacha20(ss(i-1)), and eliminate
ss(i-1) altogether. While the attack doesn't look very practical, or
even useful, there's no reason to allow it when simply hashing ss(i) and
ss(i-1) together wouldn't.

---

We can then apply this to our key exchange:

- __CK1:__ HChacha20(ee, zero) XOR HChacha20(zero, one)
- __CK2:__ HChacha20(es, zero) XOR HChacha20(CK1 , one)
- __CK3:__ HChacha20(se, zero) XOR HChacha20(CK2 , one)
- __AK2:__ Chacha20(CK2, one)[ 0:31]
- __EK2:__ Chacha20(CK2, one)[32:63]
- __AK3:__ Chacha20(CK3, one)[ 0:31]
- __EK3:__ Chacha20(CK3, one)[32:63]

1. __AK2__ and __EK2__ are independently random if any of __ee__ or
   __es__ is secret.
1. __AK3__ and __EK3__ are independently random if any of __ee__,
   __es__, or __se__ is secret.


### Authentication, encryption, and session keys

_AK2_, _EK2_, _AK3_, and _EK3_ are all derived from chaining keys, and
are not used to derive any other key. Therefore, revealing those keys
does not leak information about any other key.

Therefore:

- _AK2_ can be used as the authentication key for Poly1305.  Once.
- _AK3_ can be used as the authentication key for Poly1305.  Once.
- _EK2_ can be used as we would a one time pad (XOR with one message).

Note that _AK2_ and _AK3_ are used for one authentication each, and
_EK2_ is used for exactly one encryption. So this is safe.  Since _EK3_
isn't used for anything, it can safely be the session key.


Interactive handshake
---------------------

The interactive handshake involves 3 messages: the _request_, the
_response_, and the _confirmation_, containing the following:

    XS           = LS XOR EK2

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

- __ee__ = X25519(es, ER) = X25519(er, ES)
- __el__ = X25519(es, LR) = X25519(lr, ES)

_ES_ might come from the sender, or from an active attacker.  _ER_ comes
from the recipient, and is unknown to the attacker. _LR_ comes from the
recipient, and is not yet known to the attacker.

If _ES_ indeed came from the sender (whether this is a replay or not),
the attacker will never be able to guess _ee_.  Even if they
compromise _LR_ later, they won't be able to guess _AK2_, and won't be
able to interpret the MAC.

If _ES_ is a low order point, the shared secrets will be known
constants, and so will _K2_ and _AK2_.  The MAC will be independent from
_LR_, and won't leak the identity of the recipient.

If _ES_ comes from the attacker, the tag will leak the identity of the
recipient (the attacker has to try all known public keys to get to the
right one).  __An active attacker can learn that the recipient is able
and willing to accept connections.__ Not very incriminating, but still
worth pointing out.


### Response (as received by the sender)

The MAC of the response authenticates both _ES_ and _ER_, with _AK2_,
which is derived from both _ee_ and _el_.  After the reception of the
message, the sender's transcript will contain:

- _LR_, which is known in advance.
- _ES_, which they sent themselves.
- _ER_, which they just received, and could come from an attacker.

They will then check the MAC against their transcript, and abort the
protocol if it doesn't match.

The only way to construct a genuine looking MAC is to somehow:

- Authenticate _ES_ (the one sent by the sender);
- authenticate some _ER_ (which may come from the attacker);
- be able to guess both _ee_ and _el_, to derive _AK2_.

Any active attacker can guess _ee_: they just provide their own _ER_,
so they can know _er_ (or provide a low order point, forcing _ee_ to
be a known constant).  On the other hand, besides the sender, only the
recipient can guess _el_: no one else knows either _es_ or _lr_.
Thus, only the recipient can authenticate the transcript.

Attackers cannot replay old responses or otherwise modify _ES_: the
transcript won't match, and the MAC won't look genuine.

__Conclusion:__ The response has been sent by the recipient, for this
session.  The key _ER_ comes from them, the shared secret _ee_ is
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

The confirmation contains _LS_ (encrypted), and a MAC of the
transcript. When the recipient receives it, their transcript will
contain the following:

- _LR_, which is set in advance.
- _ES_, which could have been sent by anyone.
- _ER_, which the recipient have sent.
- _LS XOR EK2_, which an attacker might try to forge.

The only way to produce a genuine looking MAC is to somehow:

- Authenticate some _ES_ (which may have come from the attacker);
- Authenticate _ER_ (the one sent by the recipient);
- Authenticate _LS XOR EK2_ (which may have come from the attacker);
- Know _ee_, _el_, and _le_.

Only the recipient knows _er_. Therefore, the only way to know both
_ee_ and _le_ is to provide _both_ _ES_ and _LS_.

Attackers cannot replay old confirmations or otherwise modify _ER_: the
transcript won't match, and the MAC won't look genuine.

__Conclusion:__ The request and the confirmation came from the same
person, for the present session.  __That person could be an attacker.__
Even though the protocol has successfully completed, the application must
authenticate _LS_ itself (for instance by checking a list of known
contacts).  If _LS_ is the public key of a trusted contact, the
connection is secure, and enjoys forward secrecy.

Note that the recipient's long term key _LR_ is not involved in the
shared secrets _ee_ and _le_, so the above holds even if _LR_ was
compromised.  The recipient is resistant to key compromise
impersonation.


Deniability
-----------

All authentication is done with symmetric crypto, using the shared
secrets generated by the key exchanges.  To verify a MAC, both parties
actually _generate_ a MAC, then compare it to what they received.
Forging a genuine looking transcript is trivial for both parties, so no
one can prove the handshake actually took place.

To maximise effective deniability, though, applications should provide
an easy way to edit messages that were exchanged after the fact.

Users who want _accountability_ instead can use public key signatures.
