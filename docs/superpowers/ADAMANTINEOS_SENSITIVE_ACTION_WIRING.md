# AdamantineOS Sensitive Action Wiring

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Branch: `feature/adamantineos-sensitive-action-wiring`  
Status: experimental fork wiring for maintainer review

## Purpose

This branch wires the existing AdamantineOS sensitive-action gate into real wallet call-sites.

The wiring is intentionally conservative:

```text
DENY stops before sensitive execution.
REQUIRE_HUMAN_CONFIRMATION stops before sensitive execution.
ALLOW continues.
Not configured keeps existing wallet behaviour unchanged.
