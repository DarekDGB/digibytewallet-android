# AdamantineOS Send-Flow Gate

Author attribution: **DarekDGB**  
Repository context: `digibytewallet-android` fork  
Status: send-flow gate layer only  
Default behaviour: not configured; existing wallet send behaviour remains unchanged until a maintainer wires a context provider and runtime boundary

## Purpose

This layer introduces the send-flow gate position for AdamantineOS.

The gate is placed after normal wallet validation and coin selection, but before native transaction execution.

```text
validate address / amount
    -> select coins
    -> AdamantineOS send-flow gate
    -> NativeBridge.createTransaction
    -> NativeBridge.signTransaction
    -> NativeBridge.publishTransaction
