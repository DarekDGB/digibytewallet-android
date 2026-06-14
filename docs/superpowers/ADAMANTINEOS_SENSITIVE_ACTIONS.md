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
