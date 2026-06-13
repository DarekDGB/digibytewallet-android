# AdamantineOS Runtime Connector

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Status: runtime connector boundary only  
Default behaviour: disabled / not wired unless a maintainer provides runtime host, context provider, and evidence providers

## Purpose

This layer adds the wallet-side connector boundary for AdamantineOS runtime calls.

It connects the previous layers:

```text
wallet action request
    -> evidence providers
    -> execution_request_v2 builder
    -> AdamantineOS runtime host interface
    -> execution_response_v2 validator
    -> wallet decision result
```

## What this layer does

This PR adds:

- `AdamantineExecutionRuntimeHost`
- disabled default runtime host
- runtime call context provider
- deterministic `execution_request_v2` builder
- evidence bundle injection
- strict `execution_response_v2` validation before mapping
- request ID echo validation
- fail-closed handling for missing evidence, missing runtime context, runtime exceptions, malformed responses, and response mismatches

## What this layer does not do

This PR does not add:

- cloud dependency
- remote service dependency
- key custody
- signing authority
- transaction creation
- transaction signing
- transaction broadcasting
- native/JNI changes
- consensus changes
- bypass path

## Evidence mapping

Wallet-side evidence providers expose:

```text
Q-ID
Shield
Adaptive Core
```

The AdamantineOS `execution_request_v2` evidence envelope expects:

```text
qid
oracle
shield
```

For runtime compatibility, Adaptive Core evidence is injected into the `oracle` lane.

## Disabled-by-default rule

The runtime connector is not active unless a maintainer explicitly wires:

- runtime host
- runtime call context provider
- evidence providers

If the runtime context is missing, the connector returns:

```text
DENY_NOT_WIRED
```

If evidence is missing, the connector fails closed before calling the runtime.

If the runtime throws or is unavailable, the connector returns:

```text
DENY_ADAPTER_UNAVAILABLE
```

If the runtime response is malformed or does not echo the request ID, the connector returns:

```text
DENY_ADAMANTINEOS_RESPONSE_INVALID
```

## Security boundary

The runtime connector must never receive or send:

- seed phrase
- mnemonic
- private key
- xprv / xpub material
- PIN or password
- auth token
- unsigned transaction
- signed transaction
- raw transaction
- serialized transaction
- signature
- native wallet memory

The connector sends only safe wallet action metadata and evidence summaries.

## Next layer

The next safe layer is protecting additional sensitive wallet actions:

```text
wipe wallet
recover wallet
Digi-ID
message signing
```

Each action should be added as a separate guarded path with tests proving AdamantineOS decisions stop execution before sensitive logic.
