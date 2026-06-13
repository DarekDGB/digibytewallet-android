# AdamantineOS Send UI State

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Status: UI/domain-state layer only  
Default behaviour: no bypass button; no live runtime connector yet

## Purpose

This layer makes AdamantineOS send outcomes visible as explicit wallet states instead of generic send errors.

The send flow can now distinguish:

```text
SUCCESS
GENERIC ERROR
ADAMANTINEOS DENY
ADAMANTINEOS REQUIRE_HUMAN_CONFIRMATION
