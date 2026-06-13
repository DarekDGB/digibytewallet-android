# AdamantineOS Evidence Providers

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Status: evidence-provider scaffolding only  
Default behaviour: providers are missing/not wired; no wallet execution behaviour changes

## Purpose

This layer adds wallet-side scaffolding for AdamantineOS evidence providers.

The supported evidence lanes are:

```text
Q-ID
Shield
Adaptive Core
```

These providers prepare safe evidence summaries that a future AdamantineOS runtime connector can use.

## What this layer does

This PR adds:

- `AdamantineEvidenceProviderContext`
- `AdamantineEvidenceProvider`
- `AdamantineEvidenceCollector`
- source-specific evidence results
- missing-provider defaults
- fail-closed provider validation
- deterministic evidence hashes
- tests for missing, valid, wrong-source, forbidden-field, and unavailable providers

## What this layer does not do

This PR does not add:

- live AdamantineOS runtime connector
- live Q-ID integration
- live Shield integration
- live Adaptive Core integration
- send-flow behaviour change
- consensus changes
- key/signing changes
- native/JNI changes
- broadcast changes
- bypass path

## Evidence sources

### Q-ID

Q-ID evidence is expected to represent identity/session binding evidence in a future layer.

Missing Q-ID evidence maps to:

```text
EQC_MISSING_QID_SESSION
```

### Shield

Shield evidence is expected to represent Shield/orchestrator receipt evidence in a future layer.

Missing Shield evidence maps to:

```text
EQC_MISSING_SHIELD_BUNDLE
```

### Adaptive Core

Adaptive Core evidence is expected to represent risk/adaptive-policy evidence in a future layer.

Missing Adaptive Core evidence maps to:

```text
EQC_MISSING_RISK_REPORT
```

## Default behaviour

All providers are missing by default.

That means the evidence bundle is incomplete unless a maintainer wires real providers later.

The default missing state is intentional. It prevents the wallet from silently pretending that Q-ID, Shield, or Adaptive Core evidence exists.

## Security rules

Evidence providers must never include:

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

Evidence provider fields are validated for forbidden wallet-material names and unsafe control characters.

## Current scope

This is scaffolding only.

The next safe layer is the live AdamantineOS runtime connector. That connector can consume the request, response validator, send gate, UI state, and evidence-provider bundle together.
