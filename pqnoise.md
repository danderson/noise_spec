---
title:      'The PQPQNoise Protocol Framework'
author:     'David Anderson (dave@natulte.net)'
revision:   '1'
status: 'unstable'
date:       '2026-09-13'
bibliography: 'my.bib'
link-citations: 'true'
---

# 1. Introduction

PQPQNoise is a framework for crypto protocols based on KEM ciphertexts. 
It is a continuation of the classic Noise protocol framework, modified to be resistant
to quantum computer attacks.

**TODO**: this is a work in progress draft. It has not been reviewed by anyone for accuracy
or correctness. If you're looking to implement PQNoise, you should refer to the
[PQNoise paper](https://eprint.iacr.org/2022/539) and the [Noise specification](https://noiseprotocol.org/noise.html).
You should assume that this document is dangerously inaccurate at this time.

I'm drafting this spec as a reference for implementors, but did not create Noise or PQNoise.
Noise is due to Trevor Perrin and a [cast of dozens more listed in the Noise Spec's acknowledgements](https://noiseprotocol.org/noise.html#acknowledgements).
PQNoise is due to [Yawning Angel, Benjamin Dowling, Andreas Hülsing, Peter Schwabe, and Fiona Johanna Weber](https://eprint.iacr.org/2022/539). 

# 2. Overview

## 2.1. Terminology

A PQNoise protocol begins with two parties exchanging **handshake messages**.
During this **handshake phase** the parties exchange KEM keys and ciphertexts,
hashing the KEM secrets into a shared secret key.
After the handshake phase each party can use this shared key to send encrypted
**transport messages**.

The PQNoise framework supports handshakes where each party has a long-term
**static key pair** and/or an **ephemeral key pair**.  A PQNoise handshake is
described by a simple language.  This language consists of **tokens** which are
arranged into **message patterns**.  Message patterns are arranged into
**handshake patterns**.

A **message pattern** is a sequence of tokens that specifies the KEM public keys
that comprise a handshake message, and the KEM operations that are performed
when sending or receiving that message.  A **handshake pattern** specifies the
sequential exchange of messages that comprise a handshake.

A handshake pattern can be instantiated by **KEM functions**, **cipher functions**,
and **hash functions** to give a concrete **PQNoise protocol**.

## 2.2. Overview of handshake state machine

The core of PQNoise is a set of variables maintained by each party during a
handshake, and rules for sending and receiving handshake messages by
sequentially processing the tokens from a message pattern.

Each party maintains the following variables:

 * **`s, e`**: The local party's static and ephemeral key pairs (which may be
   empty).

 * **`rs, re`**: The remote party's static and ephemeral public keys (which may
   be empty).

 * **`h`**: A **handshake hash** value that hashes all the handshake data that's
   been sent and received.

 * **`ck`**: A **chaining key** that hashes all previous KEM secrets.  Once the
   handshake completes, the chaining key will be used to derive the encryption
   keys for transport messages.
 
 * **`k, n`**: An encryption key `k` (which may be empty) and a counter-based
   nonce `n`.  Whenever a new KEM operation causes a new `ck` to be calculated,
   a new `k` is also calculated.  The key `k` and nonce `n` are used to encrypt
   static public keys and handshake payloads.  Encryption with `k` uses some
   **AEAD** cipher mode (in the sense of Rogaway [@Rogaway:2002]) 
   and uses the current `h` value as **associated data**
   which is covered by the AEAD authentication.  Encryption of static public
   keys and payloads provides some confidentiality and key confirmation during
   the handshake phase.

A handshake message consists of some KEM public keys or ciphertext, followed by
a **payload**.  The payload may contain certificates or other data chosen by the
application.  To send a handshake message, the sender specifies the payload and
sequentially processes each token from a message pattern.  The possible tokens are:

 * **`"e"`**: The sender generates a new ephemeral key pair and stores it in
   the `e` variable, writes the ephemeral public key as cleartext into the
   message buffer, and hashes the public key along with the old `h` to derive a
   new `h`.

 * **`"s"`**: The sender writes its static public key from the `s` variable
   into the message buffer, encrypting it if `k` is non-empty, and hashes the
   output along with the old `h` to derive a new `h`.

 * **`"ekem", "skem"`**: a KEM encapsulation or decapsulation is performed using
   the message sender's keypair (whether static or ephemeral is determined by the
   first letter).  The result is hashed along with the old `ck` to derive a new
   `ck` and `k`, and `n` is set to zero.

After processing the final token in a handshake message, the sender then writes
the payload into the message buffer, encrypting it if `k` is non-empty, and
hashes the output along with the old `h` to derive a new `h`.

As a simple example, an unauthenticated DH handshake is described by the
handshake pattern:

      -> e
      <- ekem

The **initiator** sends the first message, which is simply an ephemeral public key.
The **responder** sends back a KEM ciphertext addressed to that key. Both parties hash
the secret produced by the KEM into a shared secret key.

Note that a cleartext payload is sent in the first message, after the cleartext
ephemeral public key, and an encrypted payload is sent in the response message,
after the KEM ciphertext.  The application may send whatever payloads it wants.

The responder can send its static public key (under encryption) and
authenticate itself via a slightly different pattern:

      -> e
      <- ekem, s
      -> skem

In this case, the final `ck` and `k` values are a hash of both KEM secrets.
Since the `skem` token indicates a KEM operation involving the responder's static
key, successful decryption of messages that following the handshake authenticate
the responder to the initiator.

Note that the second and third messages' payloads may contain a zero-length plaintext,
but the payload ciphertext will still contain authentication data (such as an
authentication tag or "synthetic IV"), since encryption is with an AEAD mode.
The second message's payload can also be used to deliver certificates for the
responder's static public key.

The initiator can send *its* static public key (under encryption), and
authenticate itself, using a handshake pattern with one additional message:

      -> e
      <- ekem, s
      -> skem, s
      <- skem

The following sections flesh out the details, and add some complications.
However, the core of PQNoise is this simple system of variables, tokens, and
processing rules, which allow concise expression of a range of protocols.

# 3.  Message format

All PQNoise messages are less than or equal to 65535 bytes in length.
Restricting message size has several advantages:

 * Simpler testing, since it's easy to test the maximum sizes.

 * Reduces the likelihood of errors in memory handling, or integer overflow. 

 * Enables support for streaming decryption and random-access decryption of
   large data streams.

 * Enables higher-level protocols that encapsulate PQNoise messages to use an efficient
 standard length field of 16 bits.

All PQNoise messages can be processed without parsing, since there are no type or
length fields.  Of course, PQNoise messages might be encapsulated within a
higher-level protocol that contains type and length information.  PQNoise
messages might encapsulate payloads that require parsing of some sort, but
payloads are handled by the application, not by PQNoise.

A PQNoise **transport message** is simply an AEAD ciphertext that is less than or
equal to 65535 bytes in length, and that consists of an encrypted payload plus
16 bytes of authentication data.  The details depend on the AEAD cipher
function, e.g. AES256-GCM, or ChaCha20-Poly1305, but typically the
authentication data is either a 16-byte authentication tag appended to the
ciphertext, or a 16-byte synthetic IV prepended to the ciphertext.

A PQNoise **handshake message** is also less than or equal to 65535 bytes.  It
begins with a sequence of one or more KEM public keys or ciphertexts, as
determined by its message pattern.  Following the public keys will be a single
payload which can be used to convey certificates or other handshake data, but
can also contain a zero-length plaintext.

Static public keys and payloads will be in cleartext if they are sent in a
handshake prior to a KEM operation, and will be AEAD ciphertexts if they occur
after a KEM operation.  (If PQNoise is being used with pre-shared symmetric keys,
this rule is different; see [Section 9](#pre-shared-symmetric-keys)).
Like transport messages, AEAD ciphertexts will expand each encrypted field
(whether static public key or payload) by 16 bytes.

For an example, consider the handshake pattern:

      -> e
      <- ekem, s
      -> skem, s
      <- skem

The first message consists of a cleartext public key (`"e"`) followed by a
cleartext payload (remember that a payload is implicit at the end of each
message pattern).  The second message consists of a KEM ciphertext (`"ekem"`)
followed by an encrypted public key (`"s"`) followed by an encrypted
payload.  The third message consists of an encrypted KEM ciphertext (`"skem"`)
followed by an encrypted public key (`"s"`) followed by an encrypted payload.
The final message consists of an encrypted KEM ciphertext (`"skem"`) followed by
an encrypted payload.

Assuming each payload contains a zero-length plaintext, KEM keys are 1000 bytes,
and KEM ciphertexts are 1200 bytes, the message sizes will be:

  1. 1000 bytes (one cleartext public key and a cleartext payload)
  2. 2232 bytes (one KEM ciphertext, one encrypted public key, and encrypted payload)  
  3. 2248 bytes (one encrypted KEM ciphertext, one encrypted public key, and encrypted payload)
  3. 1232 bytes (one encrypted KEM ciphertext, and encrypted payload)

&nbsp;
\newpage

# 4. Crypto functions

A PQNoise protocol is instantiated with a concrete set of **KEM functions**,
**cipher functions**, and **hash functions**.  The signature for these
functions is defined below.  Some concrete functions are defined in [Section
12](#dh-functions-cipher-functions-and-hash-functions).

The following notation will be used in algorithm pseudocode:

 * The `||` operator concatenates byte sequences.
 * The `byte()` function constructs a single byte.

## 4.1. DH functions

PQNoise depends on the following **KEM functions** (and an associated constant):

 * **`GENERATE_KEYPAIR()`**: Generates a new KEM key pair.  A KEM key pair
   consists of `public_key` and `private_key` elements.  A `public_key`
   represents an encoding of a KEM public key into a byte sequence of length
   `KEM_KEY_LEN`.  The `public_key` encoding details are specific to each set
   of KEM functions.

 * **`ENCAPS(public_key)`**: Performs a KEM encapsulation addressed to `public_key`,
   and returns a shared secret (a byte sequence of length `KEM_SECRET_LEN`) and its
   corresponding KEM ciphertext (a byte sequence of length `KEM_CIPHERTEXT_LEN`).

 * **`DECAPS(private_key, ciphertext)`**: Performs a KEM decapsulation of `ciphertext`
   using `private_key`, and returns the same shared secret as the `ENCAPS` operation that
   produced the ciphertext (a byte sequence of `KEM_SECRET_LEN`).

 * **`KEM_KEY_LEN`** = A constant specifying the size in bytes of KEM public keys.

 * **`KEM_CIPHERTEXT_LEN`** = A constant specifying the size in bytes of KEM ciphertexts.

 * **`KEM_SECRET_LEN`** = A constant specifying the size in bytes of the shared secret
   produced by a KEM exchange. For security reasons, `KEM_SECRET_LEN` must be 32 or greater
   (**TODO**: why? This is lifted from classical Noise. Does the ck construction depend on each
   new secret being large enough to be impossible to brute-force?)

The KEM must be **correct** (for honestly generated keys and ciphertexts, `DECAPS` recovers
the same shared secret as `ENCAPS` with overwhelmingly high probability), **post-quantum
IND-CCA secure** (indistinguishability under adaptive chosen ciphertext attacks). It may use
either explicit or implicit rejection of invalid ciphertexts.

**TODO**: reference NIST SP 800-227, note that ML-KEM meets the above requirements?

## 4.2. Cipher functions

PQNoise depends on the following **cipher functions**:

 * **`ENCRYPT(k, n, ad, plaintext)`**: Encrypts `plaintext` using the cipher
   key `k` of 32 bytes and an 8-byte unsigned integer nonce `n` which must be
   unique for the key `k`.  Returns the ciphertext.  Encryption must be done
   with an "AEAD" encryption mode with the associated data `ad` (using the
   terminology from [@Rogaway:2002]) and returns a ciphertext that is the same
   size as the plaintext plus 16 bytes for authentication data.

   The entire ciphertext must be indistinguishable from random if the key is
   secret (using the terminology from [@Rogaway:2002], the AEAD must be IND$-CPA,
   not merely IND-CPA). Note that this is an additional requirement that isn't
   necessarily met by all AEAD schemes. 

 * **`DECRYPT(k, n, ad, ciphertext)`**: Decrypts `ciphertext` using a cipher
   key `k` of 32 bytes, an 8-byte unsigned integer nonce `n`, and associated
   data `ad`.  Returns the plaintext, unless authentication fails, in which
   case an error is signaled to the caller.

 * **`REKEY(k)`**:  Returns a new 32-byte cipher key as a pseudorandom function
   of `k`.

   If this function is not specifically defined for some set of cipher functions,
   then it defaults to returning the first 32 bytes from `ENCRYPT(k, maxnonce,
   zerolen, zeros)`, where `maxnonce` equals 2^64^-1, `zerolen` is a zero-length
   byte sequence, and `zeros` is a sequence of 32 bytes filled with zeros.

## 4.3. Hash functions

PQNoise depends on the following **hash function** (and associated constants):

 * **`HASH(data)`**: Hashes some arbitrary-length data with a
   collision-resistant cryptographic hash function and returns an output of
   `HASHLEN` bytes.

 * **`HASHLEN`** = A constant specifying the size in bytes of the hash output.
   Must be 32 or 64.

 * **`BLOCKLEN`** = A constant specifying the size in bytes that the hash
   function uses internally to divide its input for iterative processing.  This
   is needed to use the hash function with HMAC (`BLOCKLEN` is `B` in [@rfc2104]).

PQNoise defines additional functions based on the above `HASH()` function:

 * **`HMAC-HASH(key, data)`**:  Applies `HMAC` from [@rfc2104] 
   using the `HASH()` function.  This function is only called as part of `HKDF()`, below.

 * **`HKDF(chaining_key, input_key_material, num_outputs)`**:  Takes a `chaining_key` byte
   sequence of length `HASHLEN`, and an `input_key_material` byte sequence with 
   length either zero bytes, 32 bytes, or `DHLEN` bytes.  Returns a pair or triple of byte
   sequences each of length `HASHLEN`, depending on whether `num_outputs` is two or three:
     * Sets `temp_key = HMAC-HASH(chaining_key, input_key_material)`.
     * Sets `output1 = HMAC-HASH(temp_key, byte(0x01))`.
     * Sets `output2 = HMAC-HASH(temp_key, output1 || byte(0x02))`.
     * If `num_outputs == 2` then returns the pair `(output1, output2)`.
     * Sets `output3 = HMAC-HASH(temp_key, output2 || byte(0x03))`.
     * Returns the triple `(output1, output2, output3)`.

   Note that `temp_key`, `output1`, `output2`, and `output3` are all `HASHLEN` bytes in
   length.  Also note that the `HKDF()` function is simply `HKDF` from [@rfc5869] 
   with the `chaining_key` as HKDF `salt`, and zero-length HKDF `info`.

# 5. Processing rules

To precisely define the processing rules we adopt an object-oriented
terminology, and present three "objects" which encapsulate state variables and
contain functions which implement processing logic.  These three objects are
presented as a hierarchy: each higher-layer object includes one instance of the
object beneath it.  From lowest-layer to highest, the objects are:

 * A **`CipherState`** object contains `k` and `n` variables, which it uses to
   encrypt and decrypt ciphertexts.  During the handshake phase each party has
   a single `CipherState`, but during the transport phase each party has two
   `CipherState` objects: one for sending, and one for receiving.

 * A **`SymmetricState`** object contains a `CipherState` plus `ck` and `h`
   variables.  It is so-named because it encapsulates all the "symmetric
   crypto" used by PQNoise.  During the handshake phase each party has a single
   `SymmetricState`, which can be deleted once the handshake is finished.

 * A **`HandshakeState`** object contains a `SymmetricState` plus KEM variables
   `(s, e, rs, re)` and a variable representing the handshake pattern.
   During the handshake phase each party has a single `HandshakeState`, which
   can be deleted once the handshake is finished.

To execute a PQNoise protocol you `Initialize()` a `HandshakeState`.  During
initialization you specify the handshake pattern, any local key pairs, and any
public keys for the remote party you have knowledge of.  After `Initialize()`
you call `WriteMessage()` and `ReadMessage()` on the `HandshakeState` to
process each handshake message.  If any error is signaled by the `DECRYPT()` or
`DECAPS()` functions then the handshake has failed and the `HandshakeState` is deleted.

Processing the final handshake message returns two `CipherState` objects, the
first for encrypting transport messages from initiator to responder, and the
second for messages in the other direction.  At that point the `HandshakeState`
should be deleted except for the hash value `h`, which may be used for post-handshake
channel binding (see [Section 11.2](#channel-binding)).

Transport messages are then encrypted and decrypted by calling
`EncryptWithAd()` and `DecryptWithAd()` on the relevant `CipherState` with
zero-length associated data.  If `DecryptWithAd()` signals an error due to
`DECRYPT()` failure, then the input message is discarded.  The application may
choose to delete the `CipherState` and terminate the session on such an error,
or may continue to attempt communications.  If `EncryptWithAd()` or
`DecryptWithAd()` signal an error due to nonce exhaustion, then the
application must delete the `CipherState` and terminate the session.

The below sections describe these objects in detail.

## 5.1. The `CipherState` object

A `CipherState` can encrypt and decrypt data based on its `k` and `n`
variables:

  * **`k`**: A cipher key of 32 bytes (which may be `empty`).  `Empty` is a
    special value which indicates `k` has not yet been initialized.

  * **`n`**: An 8-byte (64-bit) unsigned integer nonce.

A `CipherState` responds to the following functions.  The `++` post-increment
operator applied to `n` means "use the current `n` value, then increment it".
The maximum `n` value (2^64^-1) is reserved for rekeying, described in
[Section 11.3](#rekey).  If incrementing `n` results in 2^64^-1, then any
further `EncryptWithAd()` or `DecryptWithAd()` calls will signal an error to
the caller.

  * **`InitializeKey(key)`**:  Sets `k = key`.  Sets `n = 0`.

  * **`HasKey()`**: Returns true if `k` is non-empty, false otherwise.

  * **`SetNonce(nonce)`**: Sets `n = nonce`.  This function is used for
    handling out-of-order transport messages, as described in [Section 11.4](#out-of-order-transport-messages).  

  * **`EncryptWithAd(ad, plaintext)`**:  If `k` is non-empty returns
    `ENCRYPT(k, n++, ad, plaintext)`.  Otherwise returns `plaintext`.

  * **`DecryptWithAd(ad, ciphertext)`**:  If `k` is non-empty returns
    `DECRYPT(k, n++, ad, ciphertext)`.  Otherwise returns `ciphertext`.  If an
    authentication failure occurs in `DECRYPT()` then `n` is not incremented
    and an error is signaled to the caller.

  * **`Rekey()`**: Sets `k = REKEY(k)`.

## 5.2. The `SymmetricState` object

A `SymmetricState` object contains a `CipherState` plus the following
variables:

  * **`ck`**: A chaining key of `HASHLEN` bytes.
  * **`h`**: A hash output of `HASHLEN` bytes.

A `SymmetricState` responds to the following functions:   
 
  * **`InitializeSymmetric(protocol_name)`**:  Takes an arbitrary-length
   `protocol_name` byte sequence (see [Section 8](#protocol-names-and-modifiers)).  Executes the following steps:

      * If `protocol_name` is less than or equal to `HASHLEN` bytes in length,
        sets `h` equal to `protocol_name` with zero bytes appended to make
        `HASHLEN` bytes.  Otherwise sets `h = HASH(protocol_name)`.  

      * Sets `ck = h`. 

      * Calls `InitializeKey(empty)`.

  * **`MixKey(input_key_material)`**:  Executes the following steps:
  
      * Sets `ck, temp_k = HKDF(ck, input_key_material, 2)`.
      * If `HASHLEN` is 64, then truncates `temp_k` to 32 bytes.
      * Calls `InitializeKey(temp_k)`.

  * **`MixHash(data)`**:  Sets `h = HASH(h || data)`.

  * **`MixKeyAndHash(input_key_material)`**:  This function is used for
    handling pre-shared symmetric keys, as described in [Section
    9](#pre-shared-symmetric-keys). It executes the following steps:
  
      * Sets `ck, temp_h, temp_k = HKDF(ck, input_key_material, 3)`.
      * Calls `MixHash(temp_h)`.
      * If `HASHLEN` is 64, then truncates `temp_k` to 32 bytes.
      * Calls `InitializeKey(temp_k)`.

  * **`GetHandshakeHash()`**:  Returns `h`.  This function should only be
    called at the end of a handshake, i.e. after the `Split()` function has
    been called.  This function is used for channel binding, as described in
    [Section 11.2](#channel-binding) 

  * **`EncryptAndHash(plaintext)`**: Sets `ciphertext = EncryptWithAd(h,
    plaintext)`, calls `MixHash(ciphertext)`, and returns `ciphertext`.  Note that if 
    `k` is `empty`, the `EncryptWithAd()` call will set `ciphertext` equal to  `plaintext`.

  * **`DecryptAndHash(ciphertext)`**: Sets `plaintext = DecryptWithAd(h,
    ciphertext)`, calls `MixHash(ciphertext)`, and returns `plaintext`.  Note that if 
    `k` is `empty`, the `DecryptWithAd()` call will set `plaintext` equal to `ciphertext`. 

  * **`Split()`**:  Returns a pair of `CipherState` objects for encrypting
    transport messages.  Executes the following steps, where `zerolen` is a zero-length
    byte sequence:
      * Sets `temp_k1, temp_k2 = HKDF(ck, zerolen, 2)`.
      * If `HASHLEN` is 64, then truncates `temp_k1` and `temp_k2` to 32 bytes.
      * Creates two new `CipherState` objects `c1` and `c2`.
      * Calls `c1.InitializeKey(temp_k1)` and `c2.InitializeKey(temp_k2)`.
      * Returns the pair `(c1, c2)`.  


## 5.3. The `HandshakeState` object

A `HandshakeState` object contains a `SymmetricState` plus the following
variables, any of which may be `empty`.  `Empty` is a special value which
indicates the variable has not yet been initialized.
 
  * **`s`**: The local static key pair 
  * **`e`**: The local ephemeral key pair
  * **`rs`**: The remote party's static public key
  * **`re`**: The remote party's ephemeral public key 

A `HandshakeState` also has variables to track its role, and the remaining
portion of the handshake pattern:

  * **`initiator`**: A boolean indicating the initiator or responder role.

  * **`message_patterns`**: A sequence of message patterns.  Each message
    pattern is a sequence of tokens from the set `("e", "s", "ekem", "skem")`.
    (An additional `"psk"` token is introduced in [Section 9](#pre-shared-symmetric-keys),
    but we defer its explanation until then.)

A `HandshakeState` responds to the following functions:

  * **`Initialize(handshake_pattern, initiator, prologue, s, e, rs, re)`**:
    Takes a valid `handshake_pattern` (see [Section 7](#handshake-patterns)) and an
    `initiator` boolean specifying this party's role as either initiator or
    responder.  
    
    Takes a `prologue` byte sequence which may be zero-length, or
    which may contain context information that both parties want to confirm is
    identical (see [Section 6](#prologue)).  
    
    Takes a set of KEM key pairs `(s, e)` and
    public keys `(rs, re)` for initializing local variables, any of which may be empty.
    Public keys are only passed in if the `handshake_pattern` uses pre-messages 
    (see [Section 7](#handshake-patterns)).  The ephemeral values `(e, re)` are typically
    left empty, since they are created and exchanged during the handshake; but there are
    exceptions (see [Section 10](#compound-patterns)).

    Performs the following steps:

      * Derives a `protocol_name` byte sequence by combining the names for the
        handshake pattern and crypto functions, as specified in [Section
        8](#protocol-names-and-modifiers). Calls `InitializeSymmetric(protocol_name)`.

      * Calls `MixHash(prologue)`.

      * Sets the `initiator`, `s`, `e`, `rs`, and `re` variables to the
        corresponding arguments.

      * Calls `MixHash()` once for each public key listed in the pre-messages
        from `handshake_pattern`, with the specified public key as input (see
        [Section 7](#handshake-patterns) for an explanation of pre-messages).
        If both initiator and responder have pre-messages, the initiator's
        public keys are hashed first.  If multiple public keys are listed in
        either party's pre-message, the public keys are hashed in the order
        that they are listed.

      * Sets `message_patterns` to the message patterns from `handshake_pattern`.

  * **`WriteMessage(payload, message_buffer)`**: Takes a `payload` byte sequence
   which may be zero-length, and a `message_buffer` to write the output into.  Performs the following steps, aborting if any `EncryptAndHash()` call returns an error:

      * Fetches and deletes the next message pattern from `message_patterns`,
        then sequentially processes each token from the message pattern:

          * For `"e"`:  Sets `e` (which must be empty) to `GENERATE_KEYPAIR()`.
            Appends `e.public_key` to the buffer.  Calls `MixHash(e.public_key)`.

          * For `"s"`:  Appends `EncryptAndHash(s.public_key)` to the buffer.  

          * For `"ekem"`: Computes `k, c = ENCAPS(re)`, appends `EncryptAndHash(c)` to the buffer, and calls `MixKey(k)`.

          * For `"skem"`: Computes `k, c = ENCAPS(rs)`, appends `EncryptAndHash(c)` to the buffer, and calls `MixKey(k)`.

      * Appends `EncryptAndHash(payload)` to the buffer.  

      * If there are no more message patterns returns two new `CipherState`
        objects by calling `Split()`.

\newpage

  * **`ReadMessage(message, payload_buffer)`**: Takes a byte sequence
    containing a PQNoise handshake message, and a `payload_buffer` to write the
    message's plaintext payload into.  Performs the following steps, aborting
    if any `DecryptAndHash()` or `DECAPS()` call returns an error:

      * Fetches and deletes the next message pattern from `message_patterns`,
        then sequentially processes each token from the message pattern:

          * For `"e"`: Sets `re` (which must be empty) to the next `DHLEN`
            bytes from the message.  Calls `MixHash(re.public_key)`. 

          * For `"s"`: Sets `temp` to the next `DHLEN + 16` bytes of the message if
            `HasKey() == True`, or to the next `DHLEN` bytes otherwise.  Sets `rs` (which must be empty)
            to `DecryptAndHash(temp)`.

          * For `"ekem"`: Sets `temp` to the next `KEM_CIPHERTEXT_LEN + 16` bytes of the message if
            `HasKey() == True`, or to the next `KEM_CIPHERTEXT_LEN` bytes otherwise. Calls
            `MixKey(DECAPS(e, DecryptAndHash(temp)))`.

          * For `"ekem"`: Sets `temp` to the next `KEM_CIPHERTEXT_LEN + 16` bytes of the message if
            `HasKey() == True`, or to the next `KEM_CIPHERTEXT_LEN` bytes otherwise. Calls
            `MixKey(DECAPS(s, DecryptAndHash(temp)))`.

      * Calls `DecryptAndHash()` on the remaining bytes of the message and stores
        the output into `payload_buffer`.

      * If there are no more message patterns returns two new `CipherState`
        objects by calling `Split()`.

# 6. Prologue 

PQNoise protocols have a **prologue** input which allows arbitrary data to be
hashed into the `h` variable.  If both parties do not provide identical
prologue data, the handshake will fail due to a decryption error.  This is
useful when the parties engaged in negotiation prior to the handshake and want
to ensure they share identical views of that negotiation.  

For example, suppose Bob communicates to Alice a list of PQNoise protocols that
he is willing to support.  Alice will then choose and execute a single
protocol.  To ensure that a "man-in-the-middle" did not edit Bob's list to
remove options, Alice and Bob could include the list as prologue data.

Note that while the parties confirm their prologues are identical, they don't
mix prologue data into encryption keys. If an input contains secret data that’s
intended to strengthen the encryption, a PSK handshake should be used
instead (see [Section 9](pre-shared-symmetric-keys)).  


# 7. Handshake patterns 

## 7.1. Handshake pattern basics

A **message pattern** is some sequence of tokens from the set `("e", "s", "ekem",
"skem", "psk")`.  The handling of these tokens within `WriteMessage()` and `ReadMessage()`
has been described previously, except for the `"psk"` token, which will be described in
[Section 9](pre-shared-symmetric-keys).  Future specifications might introduce other tokens.

A **pre-message pattern** is one of the following sequences of tokens:

  * `"e"`
  * `"s"`
  * `"e, s"`
  * empty


A **handshake pattern** consists of:

  * A pre-message pattern for the initiator, representing information about
  the initiator's public keys that is known to the responder.

  * A pre-message pattern for the responder, representing information about the
  responder's public keys that is known to the initiator.

  * A sequence of message patterns for the actual handshake messages.

The pre-messages represent an exchange of public keys that was somehow
performed prior to the handshake, so these public keys must be inputs to
`Initialize()` for the "recipient" of the pre-message.  

The first actual handshake message is sent from the initiator to the responder.
The next message is sent from the responder, the next from the initiator, and so
on in alternating fashion.


The following handshake pattern describes an unauthenticated PQNoise handshake consisting of two message patterns:

    pqNN:
      -> e
      <- ekem

In the following handshake pattern both the initiator and responder possess
static key pairs, and the handshake pattern comprises four message patterns:

    pqXX:
      -> e
      <- ekem, s
      -> skem, s
      <- skem

The handshake pattern names are `pqNN` and `pqXX`.  This naming convention will be
explained in [Section 7.5](#interactive-handshake-patterns-fundamental).

Non-empty pre-messages are shown as pre-message patterns prior to the delimiter
`"..."`.  If both parties have a pre-message, the initiator's is listed first,
and hashed first.  During `Initialize()`, `MixHash()` is called on any
pre-message public keys, as described in [Section
5.3](#the-handshakestate-object).

The following handshake pattern describes a handshake where the initiator has
pre-knowledge of the responder's static public key and uses it for "zero-RTT"
encryption:

    pqNK:
      <- s
      ...
      -> skem, e 
      <- ekem

In the following handshake pattern both parties have pre-knowledge of the
other's static public key.  The initiator's pre-message is listed first:

    pqKK:
      -> s
      <- s
      ...
      -> skem, e
      <- ekem, skem

\newpage

## 7.2. Alice and Bob

In all handshake patterns shown previously, the initiator is the party on the
left (sending with right-pointing arrows) and the responder is the party on the
right.

However, multiple PQNoise protocols might be used within a **compound protocol**
where the responder in one PQNoise protocol becomes the initiator for a later
PQNoise protocol.  As a convenience for terminology and notation in this case, we
introduce the notion of **Alice** and **Bob** roles which are different from
initiator and responder roles.  Alice will be viewed as the party on the
left (sending messages with right arrows), and Bob will be the party on the
right.

Handshake patterns written in **canonical form** (i.e. **Alice-initiated
form**) assume the initiator is Alice (the left-most party).  All processing
rules and discussion so far have assumed canonical-form handshake patterns.

However, handshake patterns can be written in **Bob-initiated form** by
reversing the arrows.  This doesn't change the handshake pattern, it simply makes
it easier to view Alice-initiated and Bob-initiated handshakes side-by-side.

Below are the handshake patterns from the previous section in Bob-initiated
form:

    pqNN:
      <- e
      -> ekem

    pqXX:
      <- e
      -> ekem, s
      <- skem, s
      <- skem

    pqNK:
      -> s
      ...
      <- skem, e
      -> ekem

    pqKK:
      <- s
      -> s
      ...
      <- skem, e
      -> ekem, skem

## 7.3. Handshake pattern validity 

Handshake patterns must be **valid** in the following senses:

 1. Parties can only perform KEM operations with private keys and public keys
    they possess.

 2. Parties must not send their static public key or ephemeral public key more
    than once per handshake (i.e. including the pre-messages, there must be no
    more than one occurrence of `"e"`, and one occurrence of `"s"`, in the
    messages sent by any party).

 3. Parties must not call `ENCAPS()` more than once on a given public key per
    handshake (i.e. there must be no more than one occurrence of `"ekem"` or
    `"skem"` per message direction in a handshake).

 4. Parties must send KEM ciphertexts for a key in the first message sent after learning the key. For example:
    * A responder that receives `"e"` in a message must include `"ekem"` in the following message.
    * An initiator that receives `"s"` in a pre-message must include `"skem"` in its first message.

 5. Within a message, `"ekem"` always precedes `"skem"`, which always precedes
    all public keys and the payload.

Patterns failing the first check are obviously nonsense.

The second and third checks outlaw redundant transmission of values, and
redundant computation, to simplify implementation and testing.

TODO: could also mandate that you must send ekem/skem as soon as you learn the relevant pubkey. Could also include the
rule from PQNoise paper that ekem precedes skem precedes anything else, which maximizes security properties for
subsequent message fields. Neither is required for a pattern to be valid in the security sense, but eliminate a
number of patterns that are strictly weaker choices than the pattern with those rules applied.

Users are recommended to only use the handshake patterns listed below, or other
patterns that have been vetted by experts to satisfy the above checks.

## 7.4. Handshake patterns (fundamental)

The following handshake patterns represent interactive protocols.  These 
12 patterns are called the **fundamental** interactive handshake patterns.

The fundamental interactive patterns are named with two characters, which
indicate the status of the initiator and responder's static keys:

The first character refers to the initiator's static key:

 * **`N`** = **`N`**o static key for initiator
 * **`K`** = Static key for initiator **`K`**nown to responder
 * **`X`** = Static key for initiator **`X`**mitted ("transmitted") to responder
 * **`I`** = Static key for initiator **`I`**mmediately transmitted to responder,
 despite reduced or absent identity hiding

The second character refers to the responder's static key:

 * **`N`** = **`N`**o static key for responder
 * **`K`** = Static key for responder **`K`**nown to initiator
 * **`X`** = Static key for responder **`X`**mitted ("transmitted") to initiator

\newpage

+---------------------------+--------------------------------+
|     pqNN:                 |        pqKN:                   |
|       -> e                |          -> s                  |
|       <- ekem             |          ...                   |
|                           |          -> e                  |
|                           |          <- ekem, skem         |
+---------------------------+--------------------------------+
|     pqNK:                 |        pqKK:                   |
|       <- s                |          -> s                  |
|       ...                 |          <- s                  |
|       -> skem, e          |          ...                   |
|       <- ekem             |          -> skem, e            |
|                           |          <- ekem, skem         |
+---------------------------+--------------------------------+
|     pqNX:                 |         pqKX:                  |
|       -> e                |           -> s                 |
|       <- ekem, s          |           ...                  |
|       -> skem             |           -> e                 |
|                           |           <- ekem, skem, s     |
|                           |           -> skem              |
+---------------------------+--------------------------------+
|     pqXN:                 |         pqIN:                  |
|       -> e                |           -> e, s              |
|       <- ekem             |           <- ekem, skem        |
|       -> s                |                                |
|       <- skem             |                                |
+---------------------------+--------------------------------+
|     pqXK:                 |         pqIK:                  |
|       <- s                |           <- s                 |      
|       ...                 |           ...                  |
|       -> skem, e          |           -> skem, e, s        |
|       <- ekem             |           <- ekem, skem        |
|       -> s                |                                |
|       <- skem             |                                |
+---------------------------+--------------------------------+
|     pqXX:                 |         pqIX:                  |
|       -> e                |           -> e, s              |
|       <- ekem, s          |           <- ekem, skem, s     |
|       -> skem, s          |           -> skem              |
|       <- skem             |                                |
+---------------------------+--------------------------------+

\newpage

The `pqXX` pattern is the most generically useful, since it supports mutual
authentication and transmission of static public keys.

All fundamental patterns allow some encryption of handshake payloads:

 * Patterns where the initiator has pre-knowledge of the responder's static
   public key (i.e. patterns ending in `K`) allow **zero-RTT** encryption,
   meaning the initiator can encrypt the first handshake payload.  

 * All fundamental patterns allow **half-RTT** encryption of the first response
   payload, but the encryption only targets an initiator static public key in
   patterns starting with `K` or `I`.

The security properties for handshake payloads are usually weaker than the
final security properties achieved by transport payloads, so these early
encryptions must be used with caution.

In some patterns the security properties of transport payloads can also vary.
In particular: patterns starting with `K` or `I` have the caveat that the
responder is only guaranteed "weak" forward secrecy for the transport messages
it sends until it receives a transport message from the initiator.  After
receiving a transport message from the initiator, the responder becomes assured
of "strong" forward secrecy.

More analysis of these payload security properties is in [Section 7.5](#payload-security-properties).

## 7.5. Payload security properties

The following table lists the security properties for PQNoise handshake and
transport payloads for all the fundamental patterns in [Section 7.4](#handshake-patterns-fundamental).
Each payload is assigned a "source" property regarding the degree of authentication of the
sender provided to the recipient, and a "destination" property regarding the degree of
confidentiality provided to the sender.

The source properties are:

 0. **No authentication.**  This payload may have been sent by any party,
    including an active attacker.

 1. **Sender authentication**.  The payload's `CipherState` derives from a contribution
    tied to the sender's static identity.  Encrypting the payload with the correct encryption
    key requires possession of the sender's static private key.

Message payloads are unauthenticated (source property = 0) until the sender receives and
successfully processes an `"skem"` token. Thereafter, all message payloads are sender
authenticated (source property = 1).

The destination properties are:

 0. **No confidentiality.**  This payload is sent in cleartext.

 1. **Encryption to an ephemeral recipient, forward secrecy.**  The payload's `CipherState`
    includes an ephemeral contribution.  However, the sender has not authenticated the
    recipient, so this payload might be sent to any party, including an active attacker.

 2. **Encryption to a known recipient, forward secrecy for sender
    compromise only, vulnerable to replay.** The payload's `CipherState` includes a contribution
    tied to the recipient's static identity.  If the recipient's static private key is compromised,
    even at a later date, this payload can be decrypted.  This message can also be replayed, since 
    there's no ephemeral contribution.

 3. **Encryption to a known recipient, forward secrecy.**  The payload's `CipherState`
    includes a contribution tied to the recipient's static identity, as well as an ephemeral
    contribution.  Assuming the ephemeral private keys are secure, and the recipient is not being
    actively impersonated by an attacker that has stolen its static private key, this payload
    cannot be decrypted.

In the fundamental patterns, the destination property is determined entirely by the presence or
absence of two tokens in the portion of the handshake preceding a payload: an `"skem"` token
flowing from sender to recipient, and an `"ekem"` token in any direction:

+---------------------+--------------------------+-----------------------+
|                     | No `"skem"` to recipient | `"skem"` to recipient |
+---------------------+--------------------------+-----------------------+
| No `"ekem"`         |            0             |           2           |
+---------------------+--------------------------+-----------------------+
| `"ekem"` processed  |            1             |           3           |
+---------------------+--------------------------+-----------------------+

In fundamental patterns, the presence or absence of an `"skem"` addressed to the sender has no
influence on the destination property: if a message payload's `CipherState` receives a
contribution from such an `"skem"`, it always receives an `"ekem"` contribution as well.
The resulting destination property is the same as that of an `"ekem"` contribution alone.

Non-fundamental patterns may have message payloads whose sole `CipherState` contribution is from
an `"skem"` addressed to the sender. The destination property in that case is
**Encryption to an unknown recipient, forward secrecy for recipient compromise only**, which lies
between destination property 0 (no encryption) and destination property 1 (encryption to ephemeral
recipient).

Security properties are listed for each handshake payload.  Transport payloads are
listed as arrows without a pattern.  Transport payloads are only listed if they have
different security properties than the previous handshake payload sent from the same
party.  If two transport payloads are listed, the security properties for the second
only apply if the first was received.

+--------------------------------------------------------------+
|                              Source         Destination      |
+--------------------------------------------------------------+
|     pqNN                                                     |             
|       -> e                      0                0           |               
|       <- ekem                   0                1           |               
|       ->                        0                1           |               
+--------------------------------------------------------------+
|     pqNK                                                     |                                 
|       <- s                                                   |
|       ...                                                    |                                 
|       -> skem, e                0                2           |               
|       <- ekem                   1                1           |               
|       ->                        0                3           |               
+--------------------------------------------------------------+
|     pqNX                                                     |             
|       -> e                      0                0           |               
|       <- ekem, s                0                1           |               
|       -> skem                   0                3           |
|       <-                        1                1           |
+--------------------------------------------------------------+
|     pqXN                                                     |                                 
|       -> e                      0                0           |               
|       <- ekem                   0                1           |               
|       -> s                      0                1           |               
|       <- skem                   0                3           |
|       ->                        1                1           |
+--------------------------------------------------------------+
|     pqXK                                                     |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> skem, e                0                2           |               
|       <- ekem                   1                1           |               
|       -> s                      0                3           |               
|       <- skem                   1                3           |
|       ->                        1                3           |
+--------------------------------------------------------------+
|     pqXX                                                     |                                 
|       -> e                      0                0           |               
|       <- ekem, s                0                1           |
|       -> skem, s                0                3           |
|       <- skem                   1                3           |
|       ->                        1                3           |               
+--------------------------------------------------------------+
|     pqKN                                                     |                                 
|       -> s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- ekem, skem             0                3           |               
|       ->                        1                1           |               
+--------------------------------------------------------------+
|     pqKK                                                     |                                 
|       -> s                                                   |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> skem, e                0                2           |               
|       <- ekem, skem             1                3           |               
|       ->                        1                3           |               
+--------------------------------------------------------------+
|     pqKX                                                     |                           
|       -> s                                                   |                           
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- ekem, skem, s          0                3           |               
|       -> skem                   1                3           |               
|       <-                        1                3           |               
+--------------------------------------------------------------+
|     pqIN                                                     |    
|       -> e, s                   0                0           |         
|       <- ekem, skem             0                3           |         
|       ->                        1                1           |         
+--------------------------------------------------------------+
|     pqIK                                                     |                        
|       <- s                                                   |                        
|       ...                                                    |                        
|       -> skem, e, s             0                2           |         
|       <- ekem, skem             1                3           |         
|       ->                        1                3           |         
+--------------------------------------------------------------+
|     pqIX                                                     |                        
|       -> e, s                   0                0           |         
|       <- ekem, skem, s          0                3           |         
|       -> skem                   1                3           |         
|       <-                        1                3           |         
+--------------------------------------------------------------+


## 7.6. Identity hiding

**TODO**: recheck all these properties carefully. KEMs don't have the symmetry properties of DH, which may
change the ability of attackers to probe in some cases. I've done one pass so far, but I'm not highly confident
in my judgement.

The following table lists the identity-hiding properties for all the fundamental handshake
patterns in [Section 7.4](#handshake-patterns-fundamental).

Each pattern is assigned properties describing the confidentiality supplied to
the initiator's static public key, and to the responder's static public key.
The underlying assumptions are that ephemeral private keys are secure, and that
parties abort the handshake if they receive a static public key from the other
party which they don't trust.

This section only considers identity leakage through static public key fields
in handshakes.  Of course, the identities of PQNoise participants might be
exposed through other means, including payload fields, traffic analysis, or
metadata such as IP addresses.

The properties for the relevant public key are:

  0. Transmitted in clear.

  1. Encrypted with forward secrecy, but can be probed by an
     anonymous initiator.

  2. Encrypted with forward secrecy, but sent to an anonymous responder. 

  3. Not transmitted, but a passive attacker can check candidates for the
     responder's private key and determine whether the candidate is correct.
     An attacker could also replay a previously-recorded message to a new
     responder and determine whether the two responders are the "same" (i.e. are
     using the same static key pair) by whether the recipient accepts the message.

  4. Encrypted to responder's static public key, without forward secrecy.
     If an attacker learns the responder's private key they can decrypt the
     initiator's public key. 

  5. Not transmitted, but a passive attacker can check candidates for the pair
     of (responder's private key, initiator's public key) and learn whether the
     candidate pair is correct.

  6. Encrypted but with weak forward secrecy.  An active attacker who
     pretends to be the initiator without the initiator's static private key,
     then later learns the initiator private key, can then decrypt the
     responder's public key.

  7. Not transmitted, but an active attacker who pretends to be the
     initator without the initiator's static private key, then later learns a
     candidate for the initiator private key, can then check whether the
     candidate is correct.

  8. Encrypted with forward secrecy to an authenticated party.

  9. An active attacker who pretends to be the initiator and records a single
     protocol run can then check candidates for the responder's public key.

<!-- end of list - necesary to trick Markdown into seeing the following -->

+------------------------------------------+
|                Initiator      Responder  |
+------------------------------------------+
|     NN             -              -      |
+------------------------------------------+
|     NK             -              3      |
+------------------------------------------+
|     NX             -              1      |
+------------------------------------------+
|     XN             2              -      |
+------------------------------------------+
|     XK             8              3      |
+------------------------------------------+
|     XX             8              1      |
+------------------------------------------+
|     KN             7              -      |
+------------------------------------------+
|     KK             5              5      |
+------------------------------------------+
|     KX             7              6      |
+------------------------------------------+
|     IN             0              -      |
+------------------------------------------+
|     IK             4              3      |
+------------------------------------------+
|     IX             0              6      |
+------------------------------------------+

\newpage

# 8. Protocol names and modifiers

To produce a **PQNoise protocol name** for `Initialize()` you concatenate the
ASCII string `"PQNoise_"` with four underscore-separated name sections which
sequentially name the handshake pattern, the DH functions, the cipher
functions, and then the hash functions.  The resulting name must be 255 bytes
or less.  Examples:

 * `PQNoise_XX_MLKEM768_AESGCM128_SHA256`
 * `PQNoise_N_MLKEM512_ChaChaPoly_BLAKE2s`
 * `PQNoise_IK_Kopis512_ChaChaPoly_BLAKE2b`

Each name section must consist only of alphanumeric characters (i.e. characters
in one of the ranges `"A"`...`"Z"`, `"a"`...`"z"`, and `"0"`...`"9"`), and the two special
characters `"+"` and `"/"`.

Additional rules apply to each name section, as specified below.

## 8.1. Handshake pattern name section

A handshake pattern name section contains a handshake pattern name plus a
sequence of zero or more **pattern modifiers**.

The handshake pattern name must be an uppercase ASCII string containing only
alphabetic characters or numerals (e.g. `"XX"` or `"IK"`).

Pattern modifiers specify arbitrary extensions or modifications to the behavior
specified by the handshake pattern.  For example, a modifier could be applied
to a handshake pattern which transforms it into a different pattern according
to some rule.  The `"psk0"` modifier is an example of this, and will be defined
later in this document.

A pattern modifier is named with a lowercase alphanumeric ASCII string which
must begin with an alphabetic character (not a numeral).  The pattern modifier
is appended to the base pattern as described below:

The first modifier added onto a base pattern is simply appended.  Thus
the `"psk0"` modifier, when added to the `"XX"` pattern, produces `"XXpsk0"`.
Additional modifiers are separated with a plus sign.  Thus, adding the `"hfs"`
modifier would result in the name section `"XXhfs+psk0"`, or a
full protocol name such as `"PQNoise_XXhfs+psk0_MLKEM768_AESGCM128_SHA256"`.

In some cases the sequential ordering of modifiers will specify different
protocols.  However, if the order of some modifiers does not matter, then they are
required to be sorted alphabetically (this is an arbitrary convention to ensure
interoperability).

## 8.2. Cryptographic algorithm name sections

The rules for the DH, cipher, and hash name sections are identical.  Each name
section must contain one or more algorithm names separated by plus signs.  

Each algorithm name must consist solely of alphanumeric characters and the
forward-slash character (`"/"`).  Algorithm names are recommended to be short,
and to use the `"/"` character only when necessary to avoid ambiguity (e.g.
`"SHA3/256"` is preferable to `"SHA3256"`).

In most cases there will be a single algorithm name in each name section (i.e.
no plus signs).  Multiple algorithm names are only used when called for by the
pattern or a modifier.  

None of the patterns or modifiers in this document require multiple algorithm
names in any name section.  However, this functionality might be useful in
future extensions.

# 9. Pre-shared symmetric keys

PQNoise provides a **pre-shared symmetric key** or **PSK** mode to support
protocols where both parties have a 32-byte shared secret key.

Using a PSK provides some mitigation against a potential future weaknesses in the
protocol's chosen KEM, in situations where it is feasible to securely distribute
a PSK out of band.

## 9.1. Cryptographic functions

PSK mode uses the `SymmetricState.MixKeyAndHash()` function to mix the PSK into both the
encryption keys and the `h` value.

Note that `MixKeyAndHash()` uses `HKDF(..., 3)`.  The third output from `HKDF()` is used
as the `k` value so that calculation of `k` may be skipped if `k` is not used.

## 9.2. Handshake tokens

In a PSK handshake, a `"psk"` token is allowed to appear one or more times in a
handshake pattern.  This token can only appear in message patterns (not
pre-message patterns).  This token is processed by calling
`MixKeyAndHash(psk)`, where `psk` is a 32-byte secret value provided by the
application.

In non-PSK handshakes, the `"e"` token in a pre-message pattern or message pattern always
results in a call to `MixHash(e.public_key)`.  In a PSK handshake, all of these calls
are followed by `MixKey(e.public_key)`.  In conjunction with the validity rule in the
next section, this ensures that PSK-based encryption uses encryption keys that are randomized using
ephemeral public keys as nonces.

## 9.3. Validity rule

To prevent catastrophic key reuse, handshake patterns using the `"psk"` token must
follow an additional validity rule:

 * A party may not send any encrypted data after it processes a `"psk"` token unless
 it has previously sent an ephemeral public key (an `"e"` token) or an ephemeral KEM
  ciphertext (an `"ekem"` token), either before or after the `"psk"` token.

This rule guarantees that a `k` derived from a PSK will never be used for encryption
unless it has also been randomized by locally chosen ephemeral values, either the
ephemeral public key or the ephemeral KEM secret.

## 9.4. Pattern modifiers

To indicate PSK mode and the placement of the `"psk"` token, pattern modifiers
are used (see [Section 8](#protocol-names-and-modifiers)).  The modifier `psk0` places a `"psk"`
token at the beginning of the first handshake message.  The modifiers
`psk1`, `psk2`, etc., place a `"psk"` token at the end of the
first, second, etc., handshake message.  

Any pattern using one of these modifiers must process tokens according to the rules in
[Section 9.2](#handshake-tokens]), and must follow the validity rule in [Section 9.3](#validity-rule). 

The table below lists some unmodified patterns on the left, and the recommended PSK
pattern on the right:

+--------------------------------+--------------------------------------+       
|     NN:                        |     NNpsk0:                          |
|       -> e                     |       -> psk, e                      |
|       <- ekem                  |       <- ekee                        |
+--------------------------------+--------------------------------------+
|     NN:                        |     NNpsk2:                          |
|       -> e                     |       -> e                           |
|       <- ekem                  |       <- ekem, psk                   |
+--------------------------------+--------------------------------------+
|     NK:                        |     NKpsk0:                          |
|       <- s                     |       <- s                           |
|       ...                      |       ...                            |
|       -> skem, e               |       -> psk, skem, e                |
|       <- ekem                  |       <- ekem                        |
+--------------------------------+--------------------------------------+
|     NK:                        |     NKpsk2:                          |
|       <- s                     |       <- s                           |
|       ...                      |       ...                            |
|       -> skem, e               |       -> skem, e                     |
|       <- ekem                  |       <- ekem, psk                   |
+--------------------------------+--------------------------------------+
|     NX:                        |      NXpsk3:                         |
|       -> e                     |        -> e                          |
|       <- ekem, s               |        <- ekem, s                    |
|       -> skem                  |        -> skem, psk                  |
+--------------------------------+--------------------------------------+
|     XN:                        |      XNpsk4:                         |
|       -> e                     |        -> e                          |
|       <- ekem                  |        <- ekem                       |
|       -> s                     |        -> s                          |
|       <- skem                  |        <- skem, psk                  |
+--------------------------------+--------------------------------------+
|     XK:                        |      XKpsk4:                         |
|       <- s                     |        <- s                          |
|       ...                      |        ...                           |
|       -> skem, e               |        -> skem, e                    |
|       <- ekem                  |        <- ekem                       |
|       -> s                     |        -> s                          |
|       <- skem                  |        <- skem, psk                  |
+--------------------------------+--------------------------------------+
|     XX:                        |      XXpsk4:                         |
|       -> e                     |        -> e                          |
|       <- ekem, s               |        <- ekem, s                    |
|       -> skem, s               |        -> skem, s                    |
|       <- skem                  |        <- skem, psk                  |
+--------------------------------+--------------------------------------+   
|     KN:                        |       KNpsk0:                        |
|       -> s                     |         -> s                         |
|       ...                      |         ...                          |
|       -> e                     |         -> psk, e                    |
|       <- ekem, skem            |         <- ekem, skem                |
+--------------------------------+--------------------------------------+   
|     KN:                        |       KNpsk2:                        |
|       -> s                     |         -> s                         |
|       ...                      |         ...                          |
|       -> e                     |         -> e                         |
|       <- ekem, skem            |         <- ekem, skem, psk           |
+--------------------------------+--------------------------------------+
|     KK:                        |       KKpsk0:                        |
|       -> s                     |         -> s                         |
|       <- s                     |         <- s                         |
|       ...                      |         ...                          |
|       -> skem, e               |         -> psk, skem, e              |
|       <- ekem, skem            |         <- ekem, skem                |
+--------------------------------+--------------------------------------+
|     KK:                        |       KKpsk2:                        |
|       -> s                     |         -> s                         |
|       <- s                     |         <- s                         |
|       ...                      |         ...                          |
|       -> skem, e               |         -> skem, e                   |
|       <- ekem, skem            |         <- ekem, skem, psk           |
+--------------------------------+--------------------------------------+
|     KX:                        |        KXpsk3:                       |
|       -> s                     |          -> s                        |
|       ...                      |          ...                         |
|       -> e                     |          -> e                        |
|       <- ekem, skem, s         |          <- ekem, skem, s            |
|       -> skem                  |          -> skem, psk                |
+--------------------------------+--------------------------------------+
|     IN:                        |        INpsk1:                       |
|       -> e, s                  |          -> e, s, psk                |
|       <- ekem, skem            |          <- ekem, skem               |
+--------------------------------+--------------------------------------+
|     IN:                        |        INpsk2:                       |
|       -> e, s                  |          -> e, s                     |
|       <- ekem, skem            |          <- ekem, skem, psk          |
|                                |                                      |
+--------------------------------+--------------------------------------+
|     IK:                        |        IKpsk1:                       |
|       <- s                     |          <- s                        |
|       ...                      |          ...                         |
|       -> skem, e, s            |          -> skem, e, s, psk          |
|       <- ekem, skem            |          <- ekem, skem               |
|                                |                                      |
+--------------------------------+--------------------------------------+
|     IK:                        |        IKpsk2:                       |
|       <- s                     |          <- s                        |
|       ...                      |          ...                         |
|       -> skem, e, s            |          -> skem, e, s               |
|       <- ekem, skem            |          <- ekem, skem, psk          |
|                                |                                      |
+--------------------------------+--------------------------------------+
|     IX:                        |        IXpsk3:                       |
|       -> e, s                  |          -> e, s                     |
|       <- ekem, skem, s         |          <- ekem, skem, s            |
|       -> skem                  |          -> skem, psk                |
+--------------------------------+--------------------------------------+

The above list does not exhaust all possible patterns that can be formed with
these modifiers.  In particular, any of these PSK modifiers can be safely
applied to any previously named pattern, resulting in patterns like
`IKpsk0`, `KKpsk1`, or even `XXpsk0+psk3`, which aren't
listed above.

This still doesn't exhaust all the ways that `"psk"` tokens could be used
outside of these modifiers (e.g. placement of `"psk"` tokens in the middle of a
message pattern).  Defining additional PSK modifiers is outside the scope of
this document.

# 10. Compound protocols

## 10.1. Rationale for compound protocols

So far we've assumed Alice and Bob wish to execute a single PQNoise protocol
chosen by the initiator (Alice).  However, there are a number of reasons why
Bob might wish to switch to a different PQNoise protocol after receiving 
Alice's first message.  For example:

 * Alice might have chosen a PQNoise protocol based on a cipher, KEM, or
   handshake pattern which Bob doesn't support.

 * Alice might have sent a "zero-RTT" encrypted initial message based on an out-of-date
   version of Bob's static public key or PSK.

Handling these scenarios requires a **compound protocol** where Bob switches
from the initial PQNoise protocol chosen by Alice to a new PQNoise protocol.  In such a
compound protocol the roles of initiator and responder would be reversed - Bob
would become the initiator of the new PQNoise protocol, and Alice the responder.

Compound protocols introduce significant complexity as Alice needs to advertise
the PQNoise protocol she is beginning with and the protocol(s) she is capable
of switching to, and both parties have to negotiate a secure transition.

These details are largely out of scope for this document.

# 11. Advanced features

## 11.1. Dummy keys

Consider a protocol where an initiator will authenticate herself if the responder
requests it.  This could be viewed as the initiator choosing between patterns
like `NX` and `XX` based on some value inside the responder's first
handshake payload.  

PQNoise doesn't directly support this.  Instead, this could be simulated by
always executing `XX`.  The initiator can simulate the `NX` case by
sending a **dummy static public key** if authentication is not requested.  The
value of the dummy public key doesn't matter.

This technique is simple, since it allows use of a single handshake pattern.
It also doesn't reveal which option was chosen from message sizes or
computation time.  It could be extended to allow an `XX` pattern to
support any permutation of authentications (initiator only, responder only,
both, or none).  

Similarly, **dummy PSKs** (e.g. a PSK of all zeros) would allow a protocol to
optionally support PSKs.

## 11.2. Channel binding

Parties might wish to execute a PQNoise protocol, then perform authentication at
the application layer using signatures, passwords, or something else.

To support this, PQNoise libraries may call `GetHandshakeHash()` after the
handshake is complete and expose the returned value to the application as a
**handshake hash** which uniquely identifies the PQNoise session.

Parties can then sign the handshake hash, or hash it along with their password,
to get an authentication token which has a "channel binding" property: the
token can't be used by the receiving party with a different sesssion.

## 11.3. Rekey

Parties might wish to periodically update their cipherstate keys using a one-way
function, so that a compromise of cipherstate keys will not decrypt older messages.
Periodic rekey might also be used to reduce the volume of data encrypted under a
single cipher key (this is usually not important with good ciphers, though note the
discussion on `AESGCM` data volumes in [Section 14](#security-considerations)).

To enable this, PQNoise supports a `Rekey()` function which may be called on a `CipherState`.

It is up to to the application if and when to perform rekey.  For example: 

 * Applications might perform **continuous rekey**, where they rekey the relevant
   cipherstate after every transport message sent or received.  This is simple and
   gives good protection to older ciphertexts, but might be difficult for implementations 
   where changing keys is expensive.

 * Applications might rekey a cipherstate automatically after it has has been used to
   send or receive some number of messages.

 * Applications might choose to rekey based on arbitrary criteria, in which case they signal
   this to the other party by sending a message.

Applications must make these decisions on their own; there are no pattern modifiers which 
specify rekey behavior.

Note that rekey only updates the cipherstate's `k` value, it doesn't reset the cipherstate's `n`
value, so applications performing rekey must still perform a new handshake if sending 2^64^ or
more transport messages.

## 11.4. Out-of-order transport messages

In some use cases, PQNoise transport messages might be lost or arrive
out-of-order (e.g. when messages are sent over UDP).  To handle this, an
application protocol can send the `n` value used for encrypting each transport
message alongside that message.  On receiving such a message the recipient
would call the `SetNonce()` function on the receiving `CipherState` using the
received `n` value.  

Recipients doing this must track the received `n` values for which decryption
was successful and reject any message which repeats such a value, to prevent
replay attacks.

Note that lossy and out-of-order message delivery introduces many other concerns
(including out-of-order handshake messages and denial of service risks) which
are outside the scope of this document.

## 11.5. Half-duplex protocols
In some application protocols the parties strictly alternate sending messages.
In this case PQNoise can be used in a **half-duplex** mode [@blinker] where the
first `CipherState` returned by `Split()` is used for encrypting messages in both
directions, and the second `CipherState` returned by `Split()` is unused.  This allows
some small optimizations, since `Split()` only has to calculate a single output
`CipherState`, and both parties only need to store a single `CipherState` during the
transport phase.

This feature must be used with extreme caution.  In particular, it would be a
catastrophic security failure if the protocol is not strictly alternating and both
parties encrypt different messages using the same `CipherState` and nonce value.


# 12. DH functions, cipher functions, and hash functions

**TODO**: everything beyond this point is just the original Noise specification
with s/Noise/PQNoise/ in text, I haven't yet reworked it.

## 12.1. The `25519` DH functions

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve25519 key pair.
 
 * **`DH(keypair, public_key)`**: Executes the Curve25519 DH function (aka
   "X25519" in [@rfc7748]).  Invalid public key values will produce an output
   of all zeros.  
   
     Alternatively, implementations are allowed to detect inputs that 
     produce an all-zeros output and signal an error instead.  This behavior is
     discouraged because it adds complexity and implementation variance, and
     does not improve security.  This behavior is allowed because it might
     match the behavior of some software.

 * **`DHLEN`** = 32

## 12.2. The `448` DH functions

 * **`GENERATE_KEYPAIR()`**: Returns a new Curve448 key pair.
 
 * **`DH(keypair, public_key)`**: Executes the Curve448 DH function (aka "X448"
   in [@rfc7748]).  Invalid public key values will produce an output of all
   zeros.  

     Alternatively, implementations are allowed to detect inputs that 
     produce an all-zeros output and signal an error instead.  This behavior is
     discouraged because it adds complexity and implementation variance, and
     does not improve security.  This behavior is allowed because it might
     match the behavior of some software.

 * **`DHLEN`** = 56

## 12.3. The `ChaChaPoly` cipher functions

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**:
   `AEAD_CHACHA20_POLY1305` from [@rfc7539].  The 96-bit nonce is formed by
   encoding 32 bits of zeros followed by little-endian encoding of `n`.
   (Earlier implementations of ChaCha20 used a 64-bit nonce; with these
   implementations it's compatible to encode `n` directly into the ChaCha20
   nonce without the 32-bit zero prefix).

## 12.4. The `AESGCM` cipher functions

 * **`ENCRYPT(k, n, ad, plaintext)` / `DECRYPT(k, n, ad, ciphertext)`**: AES256
   with GCM from [@nistgcm] with a 128-bit tag appended to the
   ciphertext.  The 96-bit nonce is formed by encoding 32 bits of zeros
   followed by big-endian encoding of `n`.

## 12.5. The `SHA256` hash function

 * **`HASH(input)`**: `SHA-256` from [@nistsha2].
 * **`HASHLEN`** = 32
 * **`BLOCKLEN`** = 64

## 12.6. The `SHA512` hash function

 * **`HASH(input)`**: `SHA-512`  from [@nistsha2].
 * **`HASHLEN`** = 64
 * **`BLOCKLEN`** = 128

## 12.7. The `BLAKE2s` hash function

 * **`HASH(input)`**: `BLAKE2s` from [@rfc7693] with digest length 32.
 * **`HASHLEN`** = 32
 * **`BLOCKLEN`** = 64

## 12.8. The `BLAKE2b` hash function

 * **`HASH(input)`**: `BLAKE2b` from [@rfc7693] with digest length 64.
 * **`HASHLEN`** = 64
 * **`BLOCKLEN`** = 128

\newpage

# 13. Application responsibilities

An application built on PQNoise must consider several issues:

 * **Choosing crypto functions**:  The `25519` DH functions are recommended for
   typical uses, though the `448` DH functions might offer extra security
   in case a cryptanalytic attack is developed against elliptic curve
   cryptography.  The `448` DH functions should be used with a 512-bit hash
   like `SHA512` or `BLAKE2b`.  The `25519` DH functions may be used with a
   256-bit hash like `SHA256` or `BLAKE2s`, though a 512-bit hash might offer
   extra security in case a cryptanalytic attack is developed
   against the smaller hash functions.  `AESGCM` is hard to implement with
   high speed and constant time in software.

 * **Extensibility**:  Applications are recommended to use an extensible data
   format for the payloads of all messages (e.g. JSON, Protocol Buffers).  This
   ensures that fields can be added in the future which are ignored by older
   implementations.

 * **Padding**:  Applications are recommended to use a data format for the
   payloads of all encrypted messages that allows padding.  This allows
   implementations to avoid leaking information about message sizes.  Using an
   extensible data format, per the previous bullet, may be sufficient.

 * **Session termination**: Applications must consider that a sequence of PQNoise
   transport messages could be truncated by an attacker.  Applications should
   include explicit length fields or termination signals inside of transport
   payloads to signal the end of an interactive session, or the end of a
   one-way stream of transport messages. 

 * **Length fields**:  Applications must handle any framing or additional
   length fields for PQNoise messages, considering that a PQNoise message may be up
   to 65535 bytes in length.  If an explicit length field is needed,
   applications are recommended to add a 16-bit big-endian length field prior
   to each message.

 * **Negotiation data**:  Applications might wish to support the transmission
   of some negotiation data prior to the handshake, and/or prior to each
   handshake message.  Negotiation data could contain things like version
   information and identifiers for PQNoise protocols.  For example, a simple
   approach would be to send a single-byte type field prior to each PQNoise
   handshake message.  More flexible approaches might send extensible
   structures such as protobufs.  Negotiation data introduces significant
   complexity and security risks such as rollback attacks (see next section).

\newpage

# 14. Security considerations

This section collects various security considerations:

 * **Authentication**:  A PQNoise protocol with static public keys verifies that
   the corresponding private keys are possessed by the participant(s), but it's
   up to the application to determine whether the remote party's static public
   key is acceptable.  Methods for doing so include certificates which sign the
   public key (and which may be passed in handshake payloads), preconfigured
   lists of public keys, or "pinning" / "key-continuity" approaches where
   parties remember public keys they encounter and check whether the same party
   presents the same public key in the future.

 * **Session termination**:  Preventing attackers from truncating a stream of
   transport messages is an application responsibility.  See previous section.

 * **Rollback**:  If parties decide on a PQNoise protocol based on some previous
   negotiation that is not included as prologue, then a rollback attack might
   be possible.  This is a particular risk with compound protocols,
   and requires careful attention if a PQNoise handshake is preceded by
   communication between the parties.

 * **Static key reuse**:  A static key pair used with PQNoise should be used with
   a single hash algorithm.  The key pair should not be used outside of PQNoise,
   nor with multiple hash algorithms.  It is acceptable to use the static key
   pair with different PQNoise protocols, provided the same hash algorithm is
   used in all of them.  (Reusing a PQNoise static key pair outside of PQNoise
   would require extremely careful analysis to ensure the uses don't compromise
   each other, and security proofs are preserved).

 * **PSK reuse**:  A PSK used with PQNoise should be used with a single hash
   algorithm.  The PSK should not be used outside of PQNoise, nor with multiple
   hash algorithms.

 * **Ephemeral key reuse**:  Every party in a PQNoise protocol must send a fresh
   ephemeral public key prior to sending any encrypted data.  Ephemeral keys
   must never be reused.  Violating these rules is likely to cause catastrophic
   key reuse. This is one rationale behind the patterns in [Section
   7](#handshake-patterns), and the validity rules in [Section
   7.3](#handshake-pattern-validity).  It's also the reason why one-way
   handshakes only allow transport messages from the sender, not the recipient.

 * **Misusing public keys as secrets**: It might be tempting to use a pattern
   with a pre-message public key and assume that a successful handshake implies
   the other party's knowledge of the public key.  Unfortunately, this is not
   the case, since setting public keys to invalid values might cause
   predictable DH output.  For example, a `PQNoise_NK_25519` initiator might send
   an invalid ephemeral public key to cause a known DH output of all zeros,
   despite not knowing the responder's static public key. If the parties want
   to authenticate with a shared secret, it should be used as a PSK.

 * **Channel binding**:  Depending on the DH functions, it might be possible
   for a malicious party to engage in multiple sessions that derive the same
   shared secret key by setting public keys to invalid values that cause
   predictable DH output (as in the previous bullet).  It might also be
   possible to set public keys to equivalent values that cause the same DH
   output for different inputs.  This is why a higher-level protocol should use
   the handshake hash (`h`) for a unique channel binding, instead of `ck`, as
   explained in [Section 11.2](#channel-binding).

 * **Incrementing nonces**:  Reusing a nonce value for `n` with the same key
   `k` for encryption would be catastrophic.  Implementations must carefully
   follow the rules for nonces.  Nonces are not allowed to wrap back to zero
   due to integer overflow, and the maximum nonce value is reserved.  This
   means parties are not allowed to send more than 2^64^-1 transport messages.

 * **Protocol names**:  The protocol name used with `Initialize()` must
   uniquely identify the combination of handshake pattern and crypto functions
   for every key it's used with (whether ephemeral key pair, static key pair,
   or PSK).  If the same secret key was reused with the same protocol name but
   a different set of cryptographic operations then bad interactions could
   occur.

 * **Pre-shared symmetric keys**:  Pre-shared symmetric keys must be secret
   values with 256 bits of entropy.

 * **Data volumes**:  The `AESGCM` cipher functions suffer a gradual reduction
   in security as the volume of data encrypted under a single key increases.
   Due to this, parties should not send more than 2^56^ bytes (roughly 72
   petabytes) encrypted by a single key.  If sending such large volumes of data
   is a possibility then different cipher functions should be chosen.

 * **Hash collisions**:  If an attacker can find hash collisions on prologue
   data or the handshake hash, they may be able to perform "transcript
   collision" attacks that trick the parties into having different views of
   handshake data.  It is important to use PQNoise with
   collision-resistant hash functions, and replace the hash function at any
   sign of weakness.

 * **Implementation fingerprinting**:  If this protocol is used in settings
   with anonymous parties, care should be taken that implementations behave
   identically in all cases.  This may require mandating exact behavior for
   handling of invalid DH public keys.

\newpage

# 15. Rationales

This section collects various design rationales.

## 15.1. Ciphers and encryption

Cipher keys and PSKs are 256 bits because:

  * 256 bits is a conservative length for cipher keys when considering
    cryptanalytic safety margins, time/memory tradeoffs, multi-key attacks,
    rekeying, and quantum attacks.

  * Pre-shared key length is fixed to simplify testing and implementation, and
    to deter users from mistakenly using low-entropy passwords as pre-shared keys.

Nonces are 64 bits because:

  * Some ciphers only have 64 bit nonces (e.g. Salsa20).

  * 64 bit nonces were used in the initial specification and implementations 
    of ChaCha20, so PQNoise nonces can be used with these implementations.

  * 64 bits makes it easy for the entire nonce to be treated as an integer 
    and incremented.

  * 96 bits nonces (e.g. in RFC 7539) are a confusing size where it's unclear if
    random nonces are acceptable.

The authentication data in a ciphertext (i.e. the authentication tag or synthetic IV) is 128 bits because:

  * Some algorithms (e.g. GCM) lose more security than an ideal MAC when 
    truncated.

  * PQNoise may be used in a wide variety of contexts, including where attackers
    can receive rapid feedback on whether guesses for authentication data are correct.

  * A single fixed length is simpler than supporting variable-length tags.

Ciphertexts are required to be indistinguishable from random because:

  * This makes PQNoise protocols easier to use with random padding (for length-hiding), or
  for censorship-resistant "unfingerprintable" protocols, or with steganography.  However note
  that ephemeral keys are likely to be distinguishable from random unless a technique such
  as Elligator [@elligator] is used.

Rekey defaults to using encryption with the nonce 2^64^-1 because:

  * With `AESGCM` and `ChaChaPoly` rekey can be computed efficiently (the
    "encryption" just needs to apply the cipher, and can skip calculation of
    the authentication tag).

Rekey doesn't reset `n` to zero because:

  * Leaving `n` unchanged is simple.

  * If the cipher has a weakness such that repeated rekeying gives rise to a cycle of keys, then letting `n` advance will avoid catastrophic reuse of the same `k` and `n` values.

  * Letting `n` advance puts a bound on the total number of encryptions that can be performed with a set of derived keys.

The `AESGCM` data volume limit is 2^56^ bytes because:

  * This is 2^52^ AES blocks (each block is 16 bytes).  The limit is based on
   the risk of birthday collisions being used to rule out plaintext guesses.
   The probability an attacker could rule out a random guess on a 2^56^ byte
   plaintext is less than 1 in 1 million (roughly (2^52^ * 2^52^) / 2^128^).

Cipher nonces are big-endian for `AESGCM`, and little-endian for `ChaCha20`, because:

  * ChaCha20 uses a little-endian block counter internally.

  * AES-GCM uses a big-endian block counter internally.

  * It makes sense to use consistent endianness in the cipher code.


## 15.2. Hash functions and hashing

The recommended hash function families are SHA2 and BLAKE2 because:

  * SHA2 is widely available and is often used alongside AES.

  * BLAKE2 is fast and similar to ChaCha20.

Hash output lengths of both 256 bits and 512 bits are supported because:

  * 256-bit hashes provide sufficient collision resistance at the 128-bit
    security level.

  * The 256-bit hashes (SHA-256 and BLAKE2s) require less RAM, and less computation when processing 
    smaller inputs (due to smaller block size), than SHA-512 and BLAKE2b.

  * SHA-256 and BLAKE2s are faster on 32-bit processors than the larger hashes, which use 64-bit operations internally.

The `MixKey()` design uses HKDF because:

  * HKDF is well-known and HKDF "chains" are used in similar ways in other protocols (e.g.
    Signal, IPsec, TLS 1.3).

  * HKDF has a published analysis [@hkdfpaper].

  * HKDF applies multiple layers of hashing between each `MixKey()` input.  This
    "extra" hashing might mitigate the impact of hash function weakness.

HMAC is used with all hash functions instead of allowing hashes to use a more
specialized function (e.g. keyed BLAKE2), because:

  * HKDF requires the use of HMAC, and some of the HKDF analysis in
    [@hkdfpaper] depends on the nested structure of HMAC.

  * HMAC is widely used with Merkle-Damgard hashes such as SHA2.  SHA3
    candidates such as Keccak and BLAKE were required to be suitable with HMAC.
    Thus, HMAC should be applicable to all widely-used hash functions. 

  * HMAC applies nested hashing to process each input.  This
    "extra" hashing might mitigate the impact of hash function weakness.

  * HMAC (and HKDF) are widely-used constructions.  If some weakness is found in a
    hash function, cryptanalysts will likely analyze that weakness in the
    context of HMAC and HKDF.

  * Applying HMAC consistently is simple, and avoids having custom designs with different
    cryptanalytic properties when using different hash functions.

  * HMAC is easy to build on top of a hash function interface.  If a more
    specialized function (e.g. keyed BLAKE2) can't be implemented using only
    the underlying hash, then it is not guaranteed to be available everywhere
    the hash function is available. 

`MixHash()` is used instead of sending all inputs directly through `MixKey()` because:

  * `MixHash()` is more efficient than `MixKey()`.

  * `MixHash()` produces a non-secret `h` value that might be useful to
     higher-level protocols, e.g. for channel-binding.

The `h` value hashes handshake ciphertext instead of plaintext because:

  * This ensures `h` is a non-secret value that can be used for channel-binding or
    other purposes without leaking secret information.

  * This provides stronger guarantees against ciphertext malleability. 


## 15.3. Other

Big-endian length fields are recommended because:

  * Length fields are likely to be handled by parsing code where 
    big-endian "network byte order" is traditional.

  * Some ciphers use big-endian internally (e.g. GCM, SHA2).

  * While it's true that Curve25519, Curve448, and ChaCha20/Poly1305 use 
    little-endian, these will likely be handled by specialized libraries, so 
    there's not a strong argument for aligning with them.

Session termination is left to the application because:

  * Providing a termination signal in PQNoise doesn't help the application much, 
    since the application still has to use the signal correctly.

  * For an application with its own termination signal, having a 
    second termination signal in PQNoise is likely to be confusing rather than helpful.

Explicit random nonces (like TLS "Random" fields) are not used because:

  * One-time ephemeral public keys make explicit nonces unnecessary.

  * Explicit nonces allow reuse of ephemeral public keys.  However reusing ephemerals (with periodic replacement) is more complicated, requires a secure time source, is less secure in case of ephemeral compromise, and only provides a small optimization, since key generation can be done for a fraction of the cost of a DH operation.

  * Explicit nonces increase message size.

  * Explicit nonces make it easier to "backdoor" crypto implementations, e.g. by modifying the RNG so that key recovery data is leaked through the nonce fields.


# 16. IPR

The PQNoise specification (this document) is hereby placed in the public domain.

\newpage

# 17. Acknowledgements

PQNoise is inspired by:

  * The NaCl and CurveCP protocols from Dan Bernstein et al [@nacl; @curvecp].
  * The SIGMA and HOMQV protocols from Hugo Krawczyk [@sigma; @homqv].
  * The Ntor protocol from Ian Goldberg et al [@ntor].
  * The analysis of OTR by Mario Di Raimondo et al [@otr].
  * The analysis by Caroline Kudla and Kenny Paterson of "Protocol 4" by Simon Blake-Wilson et al [@kudla2005; @blakewilson1997].
  * Mike Hamburg's proposals for a sponge-based protocol framework, which led to STROBE [@moderncryptostrobe; @strobe].
  * The KDF chains used in the Double Ratchet Algorithm [@doubleratchet].

General feedback on the spec and design came from: Moxie Marlinspike, Jason
Donenfeld, Rhys Weatherley, Mike Hamburg, David Wong, Jake McGinty, Tiffany
Bennett, Jonathan Rudenberg, Stephen Touset, Tony Arcieri, Alex Wied, Alexey
Ermishkin, Olaoluwa Osuntokun, Karthik Bhargavan, and Nadim Kobeissi.

Helpful editorial feedback came from: Tom Ritter, Karthik Bhargavan, David
Wong, Klaus Hartke, Dan Burkert, Jake McGinty, Yin Guanhao, Nazar Mokrynskyi,
Keziah Elis Biermann, Justin Cormack, Katriel Cohn-Gordon, and Nadim Kobeissi.

Helpful input and feedback on the key derivation design came from: Moxie
Marlinspike, Hugo Krawczyk, Samuel Neves, Christian Winnerlein, J.P. Aumasson,
and Jason Donenfeld.

The PSK approach was largely motivated and designed by Jason Donenfeld, based
on his experience with PSKs in WireGuard.

The deferred patterns resulted from discussions with Justin Cormack.  The pattern
derivation rules in the Appendix are also from Justin Cormack.

The security properties table for deferred patterns was derived by the 
PQNoise Explorer tool, from Nadim Kobeissi.

The rekey design benefited from discussions with Rhys Weatherley, Alexey
Ermishkin, and Olaoluwa Osuntokun.  

The BLAKE2 team (in particular J.P.  Aumasson, Samuel Neves, and Zooko)
provided helpful discussion on using BLAKE2 with PQNoise.

Jeremy Clark, Thomas Ristenpart, and Joe Bonneau gave feedback on earlier
versions.

\newpage

# 18. Appendices

## 18.1. Deferred patterns

The following table lists all 23 deferred handshake patterns in the right
column, with their corresponding fundamental handshake pattern in the left
column.  See [Section 7](#handshake-patterns) for an explanation of 
fundamental and deferred patterns.

+---------------------------+--------------------------------+
|     NK:                   |         NK1:                   |
|       <- s                |           <- s                 |
|       ...                 |           ...                  |
|       -> e, es            |           -> e                 |
|       <- e, ee            |           <- e, ee, es         |
|                           |                                |
+---------------------------+--------------------------------+
|     NX:                   |         NX1:                   |
|       -> e                |           -> e                 |
|       <- e, ee, s, es     |           <- e, ee, s          |
|                           |           -> es                |
|                           |                                |
+---------------------------+--------------------------------+
|     XN:                   |         X1N:                   |
|       -> e                |           -> e                 |
|       <- e, ee            |           <- e, ee             |
|       -> s, se            |           -> s                 |
|                           |           <- se                |
|                           |                                |
+---------------------------+--------------------------------+
|     XK:                   |         X1K:                   |
|       <- s                |           <- s                 |
|       ...                 |           ...                  |
|       -> e, es            |           -> e, es             |
|       <- e, ee            |           <- e, ee             |
|       -> s, se            |           -> s                 |
|                           |           <- se                |
|                           |                                |
|                           |         XK1:                   |
|                           |           <- s                 |
|                           |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, es         |
|                           |           -> s, se             |
|                           |                                |
|                           |         X1K1:                  |
|                           |           <- s                 |
|                           |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, es         |
|                           |           -> s                 |
|                           |           <- se                |
|                           |                                |
+---------------------------+--------------------------------+
|     XX:                   |         X1X:                   | 
|       -> e                |           -> e                 |
|       <- e, ee, s, es     |           <- e, ee, s, es      |
|       -> s, se            |           -> s                 |
|                           |           <- se                |
|                           |                                |
|                           |         XX1:                   |
|                           |           -> e                 |
|                           |           <- e, ee, s          |
|                           |           -> es, s, se         |
|                           |                                |
|                           |         X1X1:                  |
|                           |           -> e                 |
|                           |           <- e, ee, s          |
|                           |           -> es, s             |
|                           |           <- se                |
|                           |                                |
+---------------------------+--------------------------------+
|     KN:                   |         K1N:                   |
|       -> s                |           -> s                 |
|       ...                 |           ...                  |
|       -> e                |           -> e                 |
|       <- e, ee, se        |           <- e, ee             |
|                           |           -> se                |
|                           |                                |
+---------------------------+--------------------------------+
|     KK:                   |         K1K:                   | 
|       -> s                |           -> s                 |
|       <- s                |           <- s                 |
|       ...                 |           ...                  |
|       -> e, es, ss        |           -> e, es             |
|       <- e, ee, se        |           <- e, ee             |
|                           |           -> se                |
|                           |                                |
|                           |         KK1:                   |
|                           |           -> s                 |
|                           |           <- s                 |
|                           |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, se, es     |
|                           |                                |
|                           |         K1K1:                  |
|                           |           -> s                 |
|                           |           <- s                 |
|                           |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, es         |
|                           |           -> se                |
|                           |                                |
+---------------------------+--------------------------------+
|     KX:                   |         K1X:                   |
|       -> s                |           -> s                 |
|       ...                 |           ...                  |
|       -> e                |           -> e                 |
|       <- e, ee, se, s, es |           <- e, ee, s, es      |
|                           |           -> se                |
|                           |                                |
|                           |         KX1:                   |
|                           |           -> s                 |
|                           |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, se, s      |
|                           |           -> es                |
|                           |                                |
|                           |         K1X1:                  |
|                           |           -> s                 |
|                           |           ...                  |
|                           |           -> e                 |
|                           |           <- e, ee, s          |
|                           |           -> se, es            |
|                           |                                |
|                           |                                |
+---------------------------+--------------------------------+
|     IN:                   |         I1N:                   |
|       -> e, s             |           -> e, s              |
|       <- e, ee, se        |           <- e, ee             |
|                           |           -> se                |
|                           |                                |
+---------------------------+--------------------------------+
|     IK:                   |         I1K:                   |
|       <- s                |           <- s                 |
|       ...                 |           ...                  |
|       -> e, es, s, ss     |           -> e, es, s          |
|       <- e, ee, se        |           <- e, ee             |
|                           |           -> se                |
|                           |                                |
|                           |         IK1:                   |
|                           |           <- s                 |
|                           |           ...                  |
|                           |           -> e, s              |
|                           |           <- e, ee, se, es     |
|                           |                                |
|                           |         I1K1:                  |
|                           |           <- s                 |
|                           |           ...                  |
|                           |           -> e, s              |  
|                           |           <- e, ee, es         |
|                           |           -> se                | 
|                           |                                |
+---------------------------+--------------------------------+
|     IX:                   |         I1X:                   | 
|       -> e, s             |           -> e, s              |
|       <- e, ee, se, s, es |           <- e, ee, s, es      |
|                           |           -> se                |
|                           |                                |
|                           |         IX1:                   |
|                           |           -> e, s              |
|                           |           <- e, ee, se, s      |
|                           |           -> es                |
|                           |                                |
|                           |         I1X1:                  |
|                           |           -> e, s              |
|                           |           <- e, ee, s          |
|                           |           -> se, es            |
|                           |                                |
+---------------------------+--------------------------------+

\newpage

## 18.2. Security properties for deferred patterns

The following table lists the the security properties for the PQNoise handshake
and transport payloads for all the deferred patterns in the previous section.
The security properties are labelled using the notation from [Section 7.7](#payload-security-properties).

+--------------------------------------------------------------+
|                              Source         Destination      |
+--------------------------------------------------------------+
|     NK1                                                      |                                 
|       <- s                                                   |
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, es              2                1           |               
|       ->                        0                5           |               
+--------------------------------------------------------------+
|     NX1                                                      |             
|       -> e                      0                0           |               
|       <- e, ee, s               0                1           |               
|       -> es                     0                3           |               
|       ->                        2                1           |
|       <-                        0                5           |
+--------------------------------------------------------------+
|     X1N                                                      |                                 
|       -> e                      0                0           |               
|       <- e, ee                  0                1           |               
|       -> s                      0                1           |               
|       <- se                     0                3           |               
|       ->                        2                1           |
+--------------------------------------------------------------+
|     X1K                                                      |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e, es                  0                2           |               
|       <- e, ee                  2                1           |               
|       -> s                      0                5           |               
|       <- se                     2                3           |               
|       ->                        2                5           |
|       <-                        2                5           |
+--------------------------------------------------------------+
|     XK1                                                      |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, es              2                1           |               
|       -> s, se                  2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     X1K1                                                     |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, es              2                1           |               
|       -> s                      0                5           |               
|       <- se                     2                3           |               
|       ->                        2                5           |
|       <-                        2                5           |
+--------------------------------------------------------------+
|     X1X                                                      |                                 
|       -> e                      0                0           |               
|       <- e, ee, s, es           2                1           |               
|       -> s                      0                5           |               
|       <- se                     2                3           |               
|       ->                        2                5           |
|       <-                        2                5           |
+--------------------------------------------------------------+
|     XX1                                                      |                                 
|       -> e                      0                0           |               
|       <- e, ee, s               0                1           |               
|       -> es, s, se              2                3           |               
|       <-                        2                5           |
|       ->                        2                5           |
+--------------------------------------------------------------+
|     X1X1                                                     |                                 
|       -> e                      0                0           |               
|       <- e, ee, s               0                1           |               
|       -> es, s                  0                3           |               
|       <- se                     2                3           |               
|       ->                        2                5           |
|       <-                        2                5           |
+--------------------------------------------------------------+
|     K1N                                                      |                                 
|       -> s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee                  0                1           |               
|       -> se                     2                1           |               
|       <-                        0                5           |               
+--------------------------------------------------------------+
|     K1K                                                      |                                 
|       -> s                                                   |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e, es                  0                2           |               
|       <- e, ee, se              2                1           |               
|       -> se                     2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     KK1                                                      |                                 
|       -> s                                                   |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, se, es          2                3           |               
|       ->                        2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     K1K1                                                     |                                 
|       -> s                                                   |                                 
|       <- s                                                   |                                 
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, es              2                1           |               
|       -> se                     2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     K1X                                                      |                           
|       -> s                                                   |                           
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, s, es           2                1           |               
|       -> se                     2                5           |               
|       <-                        2                5           |               
+--------------------------------------------------------------+
|     KX1                                                      |                           
|       -> s                                                   |                           
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, se, s           0                3           |               
|       -> es                     2                3           |               
|       <-                        2                5           |               
|       ->                        2                5           |
+--------------------------------------------------------------+
|     K1X1                                                     |                           
|       -> s                                                   |                           
|       ...                                                    |                                 
|       -> e                      0                0           |               
|       <- e, ee, s               0                1           |               
|       -> se, es                 2                3           |               
|       <-                        2                5           |               
|       ->                        2                5           |
+--------------------------------------------------------------+
|     I1N                                                      |    
|       -> e, s                   0                0           |         
|       <- e, ee                  0                1           |         
|       -> se                     2                1           |         
|       <-                        0                5           |         
+--------------------------------------------------------------+
|     I1K                                                      |                        
|       <- s                                                   |                        
|       ...                                                    |                        
|       -> e, es, s               0                2           |         
|       <- e, ee                  2                1           |         
|       -> se                     2                5           |         
|       <-                        2                5           |         
+--------------------------------------------------------------+
|     IK1                                                      |                        
|       <- s                                                   |                        
|       ...                                                    |                        
|       -> e, s                   0                0           |         
|       <- e, ee, se, es          2                3           |         
|       ->                        2                5           |         
|       <-                        2                5           |         
+--------------------------------------------------------------+
|     I1K1                                                     |                        
|       <- s                                                   |                        
|       ...                                                    |                        
|       -> e, s                   0                0           |         
|       <- e, ee, es              2                1           |         
|       -> se                     2                5           |         
|       <-                        2                5           |         
+--------------------------------------------------------------+
|     I1X                                                      |                        
|       -> e, s                   0                0           |         
|       <- e, ee, s, es           2                1           |         
|       -> se                     2                5           |         
|       <-                        2                5           |         
+--------------------------------------------------------------+
|     IX1                                                      |                        
|       -> e, s                   0                0           |         
|       <- e, ee, se, s           0                3           |         
|       -> es                     2                3           |         
|       <-                        2                5           |         
|       ->                        2                5           |         
+--------------------------------------------------------------+
|     I1X1                                                     |                        
|       -> e, s                   0                0           |         
|       <- e, ee, s               0                1           |         
|       -> se, es                 2                3           |         
|       <-                        2                5           |         
|       ->                        2                5           |         
+--------------------------------------------------------------+

## 18.3. Pattern derivation rules

The following rules were used to derive the one-way, fundamental, and deferred handshake patterns.

First, populate the pre-message contents as defined by the pattern name.

Next populate the initiator's first message by applying the first rule from the below table which matches.  Then delete the matching rule and repeat this process until no more rules can be applied.  If this is a one-way pattern, it is now complete.

Otherwise, populate the responder's first message in the same way.  Once no more responder rules can be applied, then switch to the initiator's next message and repeat this process, switching messages until no more rules can be applied by either party.

**Initiator rules:**

  1. Send `"e"`.
  2. Perform `"ee"` if `"e"` has been sent, and received.
  3. Perform `"se"` if `"s"` has been sent, and `"e"` received. If initiator authentication is deferred, skip this rule for the first message in which it applies, then mark the initiator authentication as non-deferred.
  4. Perform `"es"` if `"e"` has been sent, and `"s"` received. If responder authentication is deferred, skip this rule for the first message in which it applies, then mark the responder authentication as non-deferred.
  5. Perform `"ss"` if `"s"` has been sent, and received, and `"es"` has been performed, and this is the first message, and initiator authentication is not deferred.
  6. Send `"s"` if this is the first message and initiator is "I" or one-way "X".
  7. Send `"s"` if this is not the first message and initiator is "X".

**Responder rules:**

  1. Send `"e"`.
  2. Perform `"ee"` if `"e"` has been sent, and received.
  3. Perform `"se"` if `"e"` has been sent, and `"s"` received.  If initiator authentication is deferred, skip this rule for the first message in which it applies, then mark the initiator authentication as non-deferred.
  4. Perform `"es"` if `"s"` has been sent, and `"e"` received.  If responder authentication is deferred, skip this rule for the first message in which it applies, then mark the responder authentication as non-deferred.
  5. Send `"s"` if responder is "X".

\newpage

## 18.4. Change log


**Revision 34:**

 * Added official/unstable marking; the unstable only refers to the new deferred patterns, the rest of this document is considered stable.

 * Clarified DH() definition so that the identity element is an invalid value (not a generator), thus may be rejected.

 * Clarified ciphertext-indistinguishability requirement for AEAD schemes and added a rationale.

 * Clarified the order of hashing pre-message public keys.

 * Rewrote handshake patterns explanation for clarity.

 * Added new validity rule to disallow repeating the same DH operation.

 * Clarified the complex validity rule regarding ephemeral keys and key re-use.

 * Removed parenthesized list of keys from pattern notation, as it was redundant. 

 * Added deferred patterns.

 * Renamed "Authentication" and "Confidentiality" security properties to "Source" and "Destination" to avoid confusion.

 * **[SECURITY]** Added a new identity-hiding property, and changed identity-hiding property 3 to discuss an identity equality-check attack. 

 * Replaced "fallback patterns" concept with Bob-initiated pattern notation.

 * Rewrote section on compound protocols and pipes for clarity, including
   clearer distinction between "switch protocol" and "fallback patterns".

 * De-emphasized "type byte" suggestion, and added a more general discussion of negotiation data.

 * **[SECURITY]** Added security considerations regarding static key reuse and PSK reuse.

 * Added pattern derivation rules to Appendix.

\newpage

# 19.  References
