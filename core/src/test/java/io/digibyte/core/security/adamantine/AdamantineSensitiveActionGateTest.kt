package io.digibyte.core.security.adamantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdamantineSensitiveActionGateTest {
    private fun contextProvider(nonce: String = "nonce-sensitive-test"): AdamantineSensitiveActionContextProvider =
        AdamantineSensitiveActionContextProvider {
            AdamantineSensitiveActionGateContext(
                walletId = "wallet-sensitive-test",
                deviceId = "device-sensitive-test",
                sessionId = "session-sensitive-test",
                actionNonce = nonce
            )
        }

    @Test
    fun `not configured sensitive gate preserves optional wallet behaviour`() {
        val result = AdamantineSensitiveActionGate.notConfigured().evaluate(
            AdamantineSensitiveActionInput.wipeWallet()
        )

        assertTrue(result is AdamantineSensitiveActionGateResult.Allow)
        val allow = result as AdamantineSensitiveActionGateResult.Allow
        assertFalse(allow.configured)
        assertEquals(REASON_ADAMANTINEOS_SENSITIVE_GATE_NOT_CONFIGURED, allow.reasonId)
        assertNull(allow.request)
    }

    @Test
    fun `configured sensitive gate allows wipe when boundary allows`() {
        val gate = AdamantineSensitiveActionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.allow() },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(AdamantineSensitiveActionInput.wipeWallet())

        assertTrue(result is AdamantineSensitiveActionGateResult.Allow)
        val allow = result as AdamantineSensitiveActionGateResult.Allow
        assertTrue(allow.configured)
        assertEquals(REASON_OK_ALLOW, allow.reasonId)
        assertEquals(ADAMANTINE_ACTION_WIPE_WALLET, allow.request?.action)
    }

    @Test
    fun `configured sensitive gate denies recover when boundary denies`() {
        val gate = AdamantineSensitiveActionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.deny("DENY_POLICY") },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(
            AdamantineSensitiveActionInput.recoverWallet(
                creationTimestamp = 1_774_252_800L,
                mnemonicWordCount = 12
            )
        )

        assertTrue(result is AdamantineSensitiveActionGateResult.Deny)
        val deny = result as AdamantineSensitiveActionGateResult.Deny
        assertEquals("DENY_POLICY", deny.reasonId)
        assertEquals(ADAMANTINE_ACTION_RECOVER_WALLET, deny.request?.action)
        assertFalse(deny.request?.fields?.containsKey("mnemonic") == true)
        assertFalse(deny.request?.fields?.containsKey("seed") == true)
    }

    @Test
    fun `configured sensitive gate returns human confirmation for Digi-ID`() {
        val gate = AdamantineSensitiveActionGate(
            boundary = AdamantineWalletDecisionBoundary {
                AdamantineDecision.requireHumanConfirmation("DENY_POLICY")
            },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(
            AdamantineSensitiveActionInput.digiIdAuthenticate(
                domain = "example.com",
                callbackHost = "login.example.com",
                nonce = "nonce-value",
                isUnsecure = false
            )
        )

        assertTrue(result is AdamantineSensitiveActionGateResult.RequireHumanConfirmation)
        val review = result as AdamantineSensitiveActionGateResult.RequireHumanConfirmation
        assertEquals("DENY_POLICY", review.reasonId)
        assertEquals(ADAMANTINE_ACTION_DIGIID_AUTHENTICATE, review.request.action)
        assertTrue(review.request.fields["nonce_hash"]?.matches(Regex("^[0-9a-f]{64}$")) == true)
        assertFalse(review.request.fields.containsKey("raw_uri"))
    }

    @Test
    fun `message signing gate stores message hash not message body`() {
        val gate = AdamantineSensitiveActionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.allow() },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(
            AdamantineSensitiveActionInput.messageSigning(
                message = "hello private message content",
                purpose = "hub_chat_message",
                addressFormat = 1
            )
        )

        assertTrue(result is AdamantineSensitiveActionGateResult.Allow)
        val allow = result as AdamantineSensitiveActionGateResult.Allow
        val request = requireNotNull(allow.request)

        assertEquals(ADAMANTINE_ACTION_SIGN_MESSAGE, request.action)
        assertTrue(request.fields["message_hash"]?.matches(Regex("^[0-9a-f]{64}$")) == true)
        assertEquals("29", request.fields["message_length"])
        assertFalse(request.fields.values.contains("hello private message content"))
    }

    @Test
    fun `sensitive gate fails closed when boundary throws`() {
        val gate = AdamantineSensitiveActionGate(
            boundary = AdamantineWalletDecisionBoundary { throw IllegalStateException("runtime unavailable") },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(AdamantineSensitiveActionInput.wipeWallet())

        assertTrue(result is AdamantineSensitiveActionGateResult.Deny)
        val deny = result as AdamantineSensitiveActionGateResult.Deny
        assertEquals(REASON_ADAMANTINEOS_SENSITIVE_GATE_BOUNDARY_ERROR, deny.reasonId)
    }

    @Test
    fun `field allowlist rejects forbidden wallet material fields`() {
        val gate = AdamantineSensitiveActionGate(
            boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.allow() },
            contextProvider = contextProvider()
        )

        val result = gate.evaluate(
            AdamantineSensitiveActionInput(
                action = ADAMANTINE_ACTION_SIGN_MESSAGE,
                intent = ADAMANTINE_INTENT_MESSAGE_SIGNING,
                purpose = "bad_test",
                safeFields = mapOf("private_key" to "redacted")
            )
        )

        assertTrue(result is AdamantineSensitiveActionGateResult.Deny)
        val deny = result as AdamantineSensitiveActionGateResult.Deny
        assertEquals(REASON_ADAMANTINEOS_FORBIDDEN_WALLET_MATERIAL, deny.reasonId)
    }
}
