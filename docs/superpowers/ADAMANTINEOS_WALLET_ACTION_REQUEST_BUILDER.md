# AdamantineOS Wallet Action Request Builder

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Status: request-builder layer only  
Default behaviour: not wired into wallet execution

## Purpose

This layer prepares safe wallet-action metadata for a future AdamantineOS gate.

It does not call AdamantineOS yet. It does not change wallet execution. It does not create, sign, or broadcast transactions.

The request builder only prepares a deterministic action request that can later be evaluated before sensitive execution continues.

```text
Wallet send metadata
    -> AdamantineWalletActionRequestBuilder
    -> AdamantineWalletActionRequest
    -> future AdamantineOS decision boundary
