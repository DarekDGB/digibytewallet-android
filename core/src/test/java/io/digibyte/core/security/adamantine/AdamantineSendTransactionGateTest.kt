package io.digibyte.core.security.adamantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdamantineSendTransactionGateTest {
    private fun input(): AdamantineSendTransactionGateInput = AdamantineSendTransactionGateInput(
        toAddress = "DExampleSafeAddressForSendGateOnly",
        amountSatoshis = 100_000L,
        feePerKb = 1_000L,
        selectedInputCount = 2,
        selectedInputTotalSatoshis = 150_000L,
        estimatedFeeSatoshis = 500L,
        changeSatoshis = 49_500L,
        availableUtxoCount = 5,
        assetUtxoCount = 1
    )

    private fun contextProvider(nonce: String = "nonce-send-gate-test"): AdamantineSendTransactionContextProvider =
        AdamantineSendTransactionContextProvider {
            AdamantineSendTransactionGateContext(
                walletId = "wallet-send-gate-test",
                deviceId = "device-send-gate-test",
                sessionId = "session-send-gate-test",
                actionNonce = nonce
            )
        }

    @Test
    fun `not configured send gate preserves optional wallet behaviour`() {
        val result = AdamantineSendTransactionGate.notConfigured().evaluate(input())

        assertTrue(result is AdamantineSendTransactionGateResult.Allow)
        val allow = result as AdamantineSendTransactionGateResult.Allow
        assertFalse(allow.configured)
        assertEquals(REASON_ADAMANTINEOS_SEND_GATE_NOT_CONFIGURED, allow.reasonId)
        assertNull(allow.request)
    }

    @Test
    fun `configured send gate returns allow when boundary allows`() {
        val gate = AdamantineSendTransactionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.allow() },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(input())

        assertTrue(result is AdamantineSendTransactionGateResult.Allow)
        val allow = result as AdamantineSendTransactionGateResult.Allow
        assertTrue(allow.configured)
        assertEquals(REASON_OK_ALLOW, allow.reasonId)
        assertNotNull(allow.request)
        assertEquals(ADAMANTINE_ACTION_SEND_TRANSACTION, allow.request?.action)
    }

    @Test
    fun `configured send gate returns deny when request builder fails`() {
        val gate = AdamantineSendTransactionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.allow() },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(input().copy(amountSatoshis = 0L))

        assertTrue(result is AdamantineSendTransactionGateResult.Deny)
        val deny = result as AdamantineSendTransactionGateResult.Deny
        assertEquals(REASON_ADAMANTINEOS_REQUEST_INVALID, deny.reasonId)
        assertNull(deny.request)
    }

    @Test
    fun `configured send gate returns deny when boundary denies`() {
        val gate = AdamantineSendTransactionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.deny("DENY_POLICY") },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(input())

        assertTrue(result is AdamantineSendTransactionGateResult.Deny)
        val deny = result as AdamantineSendTransactionGateResult.Deny
        assertEquals("DENY_POLICY", deny.reasonId)
        assertNotNull(deny.request)
    }

    @Test
    fun `configured send gate returns human confirmation when boundary requires review`() {
        val gate = AdamantineSendTransactionGate(
            boundary = AdamantineWalletDecisionBoundary {
                AdamantineDecision.requireHumanConfirmation("DENY_POLICY")
            },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(input())

        assertTrue(result is AdamantineSendTransactionGateResult.RequireHumanConfirmation)
        val review = result as AdamantineSendTransactionGateResult.RequireHumanConfirmation
        assertEquals("DENY_POLICY", review.reasonId)
        assertNotNull(review.request)
    }

    @Test
    fun `configured send gate fails closed when boundary throws`() {
        val gate = AdamantineSendTransactionGate(
            boundary = AdamantineWalletDecisionBoundary { throw IllegalStateException("runtime unavailable") },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(input())

        assertTrue(result is AdamantineSendTransactionGateResult.Deny)
        val deny = result as AdamantineSendTransactionGateResult.Deny
        assertEquals(REASON_ADAMANTINEOS_SEND_GATE_BOUNDARY_ERROR, deny.reasonId)
        assertNotNull(deny.request)
    }
}
