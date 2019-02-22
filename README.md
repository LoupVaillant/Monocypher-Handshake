Secure channel with Monocypher
==============================

Setting up a secure channel is a bit complex. Even when both parties
knows of each other public key, one does not simply perform a key
exchange between the two long term static keys and call it a day.
It might work, but it doesn't provide any kind of forward secrecy or
identity hiding.

This project aims to demonstrate how one might use Monocypher to set up
a secure channel properly.  It will be integrated into Monocypher itself
when it's ready.

Use cases might include:

- Interactive session (both parties must be connected at the same time).
- One way message (one party sends a message to another, without any
  infrastructure support).
- Federated setting (we're allowed to use a server to try and increase
  security, like the Signal protocol).

Goals are:

- A simple, easy to use API.
- A simple, hard to screw up implementation.
- 3 messages at most.


Interactive handshake
---------------------

This API is about setting up a secure channel for an interactive
session.

    void crypto_kex_init_client(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   local_sk   [32],
                                const uint8_t   local_pk   [32],
                                const uint8_t   remote_pk  [32]);

    void crypto_kex_init_server(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   local_sk   [32],
                                const uint8_t   local_pk   [32]);

    void crypto_kex_request(crypto_kex_ctx *ctx,
                            uint8_t         msg1       [32]);

    void crypto_kex_respond(crypto_kex_ctx *ctx,
                            uint8_t         msg2       [48],
                            const uint8_t   msg1       [32]);

    int crypto_kex_confirm(crypto_kex_ctx *ctx,
                           uint8_t         session_key[32],
                           uint8_t         msg3       [48],
                           const uint8_t   msg2       [48]);

    int crypto_kex_accept(crypto_kex_ctx *ctx,
                          uint8_t         session_key[32],
                          uint8_t         remote_pk  [32],
                          const uint8_t   msg3       [48]);

The _sender_ will use `crypto_kex_init_client()`,
`crypto_handshake_request()` and `crypto_handshake_confirm()`. The
_receiver_ will use void `crypto_kex_init_server()`
`crypto_handshake_respond()` and `crypto_handshake_accept()`.

`crypto_kex_init_client()` and `crypto_kex_init_server()` initialise a
context for the handshake.

`crypto_handshake_request()` writes the first message, to be sent to the
recipient.

`crypto_handshake_respond()` reads the first message and writes the
second message, to be sent back to the sender.

`crypto_handshake_confirm()` reads the second message, authenticates the
recipient, generates the session key, and writes the third message, to
be sent to the recipient.

`crypto_handshake_accept()` reads the third message, authenticates the
sender (and get their public key), and generates the session key.


One way handshake
-----------------

This API tries to set up a secure key without requiring any response
from the recipient.  (This is most useful for file encryption.) It is
unfortunately not as secure as the interactive handshake: when the
recipient's private key is leaked, so are the message and the identity of
its sender. It is also not resistant against key compromise
impersonation (if your key is leaked, you can no longer authenticate
incoming messages).

The only way to have better identity hiding is to sacrifice
authentication altogether, by sending an _anonymous_ message.  For this,
just use `crypto_key_exchange()` with an ephemeral key pair.  There's no
need for a specialised API.

    void crypto_kex_init_client(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   local_sk   [32],
                                const uint8_t   local_pk   [32],
                                const uint8_t   remote_pk  [32]);

    void crypto_kex_init_server(crypto_kex_ctx *ctx,
                                uint8_t         random_seed[32],
                                const uint8_t   local_sk   [32],
                                const uint8_t   local_pk   [32]);

    void crypto_send(crypto_kex_ctx *ctx,
                     uint8_t         session_key[32],
                     uint8_t         msg        [80]);

    int crypto_receive(crypto_kex_ctx *ctx,
                       uint8_t         session_key[32],
                       uint8_t         remote_pk  [32],
                       const uint8_t   msg        [80]);

The _sender_ initialises a handshake context with
`crypto_kex_init_client()`, then writes the message with
`crypto_send()`. The recipient can then initialise it own context with
`crypto_kex_init_server()`, then receive and authenticate the message
with `crypto_receive()`.  The session key can then be used to secure the
payload.
