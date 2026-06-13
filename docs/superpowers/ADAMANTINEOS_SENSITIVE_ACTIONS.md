# AdamantineOS Sensitive Action Gate

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Status: sensitive-action gate scaffolding  
Default behaviour: not configured; existing wallet behaviour remains unchanged until a maintainer wires context and runtime boundary

## Purpose

This layer prepares AdamantineOS protection for sensitive wallet actions beyond transaction sending.

Covered action types:

```text
wipe_wallet
recover_wallet
digiid_authenticate
sign_message
```

## What this layer does

This PR adds:

- `AdamantineSensitiveActionGate`
- safe metadata request builder for sensitive actions
- action-specific allowlists
- deterministic request ID
- deterministic request context hash
- deny / require-human-confirmation / allow result handling
- tests proving no seed, mnemonic, private key, signature, raw transaction, or message body is included in the request

## What this layer does not do

This PR does not add:

- key custody
- signing authority
- live cloud dependency
- native/JNI changes
- consensus changes
- transaction broadcast changes
- bypass path

## No secret material rule

The sensitive-action gate must never receive:

- seed phrase
- mnemonic
- private key
- xprv / xpub material
- PIN or password
- auth token
- signature
- unsigned transaction
- signed transaction
- raw transaction
- serialized transaction
- native wallet memory

## Action metadata

### Wipe wallet

The wipe request only carries safe metadata:

```text
destructive=true
requires_user_confirmation=true
```

### Recover wallet

The recover request does not carry the mnemonic.

It only carries:

```text
creation_timestamp
mnemonic_word_count
```

### Digi-ID authentication

The Digi-ID request does not carry the raw URI or signature.

It only carries:

```text
domain
callback_host
nonce_hash
is_unsecure
```

### Message signing

The message-signing request does not carry the message body or signature.

It only carries:

```text
message_hash
message_length
address_format
purpose
```

## Default behaviour

If no maintainer wires a context provider, the gate returns:

```text
ADAMANTINEOS_SENSITIVE_GATE_NOT_CONFIGURED
```

as an allow result with `configured=false`.

This preserves existing wallet behaviour while making the protection boundary reviewable.

## Future wiring

The next step is to wire this gate into the exact call-sites:

```text
WalletManager.wipeWallet
WalletManager.recoverWallet
DigiIdManager.authenticate before NativeBridge.signMessage
ChatViewModel.sendMessage before NativeBridge.signMessage
ForumViewModel create/reply before NativeBridge.signMessage
```

Each wiring point must prove:

```text
DENY stops before sensitive execution
REQUIRE_HUMAN_CONFIRMATION stops before sensitive execution
ALLOW continues
```
