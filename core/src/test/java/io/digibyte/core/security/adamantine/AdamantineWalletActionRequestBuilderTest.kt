package io.digibyte.core.security.adamantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdamantineWalletActionRequestBuilderTest {
    private fun input(actionNonce: String = "nonce-1"): AdamantineSendTransactionActionInput =
        AdamantineSendTransactionActionInput(
            walletId = "wallet-local-test",
            deviceId = "device-local-test",
            sessionId = "session-local-test",
            toAddress = "DExampleSafeAddressForRequestBuilderOnly",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            selectedInputCount = 2,
            selectedInputTotalSatoshis = 150_000L,
            estimatedFeeSatoshis = 500L,
            changeSatoshis = 49_500L,
            availableUtxoCount = 5,
            assetUtxoCount = 1,
            actionNonce = actionNonce
        )

    @Test
    fun `send transaction builder creates deterministic safe wallet action request`() {
        val first = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input())
        val second = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input())

        assertTrue(first.built)
        assertTrue(second.built)
        assertEquals(first.request, second.request)

        val request = requireNotNull(first.request)
        assertEquals(ADAMANTINE_ACTION_SEND_TRANSACTION, request.action)
        assertEquals(ADAMANTINE_INTENT_WALLET_SEND, request.intent)
        assertEquals("wallet-local-test", request.walletId)
        assertEquals("device-local-test", request.deviceId)
        assertEquals(ADAMANTINE_DEFAULT_APP_ID, request.appId)
        assertEquals("session-local-test", request.sessionId)
        assertNull(first.denyDecision)
    }

    @Test
    fun `send transaction builder output contains only allowlisted safe fields`() {
        val result = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input())
        val request = requireNotNull(result.request)

        val expectedFields = setOf(
            "action_nonce",
            "action_version",
            "amount_satoshis",
            "app_id",
            "asset_utxo_count",
            "available_utxo_count",
            "change_satoshis",
            "device_id",
            "estimated_fee_satoshis",
            "fee_per_kb",
            "native_execution_position",
            "network",
            "request_context_hash",
            "request_id",
            "selected_input_count",
            "selected_input_total_satoshis",
            "session_id",
            "to_address",
            "wallet_id"
        )

        assertEquals(expectedFields, request.fields.keys)
        assertEquals(ADAMANTINE_WALLET_ACTION_REQUEST_VERSION, request.fields["action_version"])
        assertEquals(ADAMANTINE_NATIVE_POSITION_BEFORE_CREATE_SIGN_BROADCAST, request.fields["native_execution_position"])
        assertNull(AdamantineWalletActionFieldAllowlist.validate(request))
    }

    @Test
    fun `send transaction builder does not include wallet secrets or raw transaction material`() {
        val result = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input())
        val request = requireNotNull(result.request)

        val forbiddenFragments = listOf(
            "seed",
            "mnemonic",
            "private",
            "xprv",
            "xpub",
            "signature",
            "signed",
            "unsigned",
            "rawtx",
            "serialized"
        )

        for (field in request.fields.keys) {
            val normalized = field.lowercase().filter { it.isLetterOrDigit() }
            assertFalse("field=$field", forbiddenFragments.any { normalized.contains(it) })
        }
    }

    @Test
    fun `different nonce changes deterministic request id and context hash`() {
        val first = requireNotNull(
            AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input("nonce-1")).request
        )
        val second = requireNotNull(
            AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input("nonce-2")).request
        )

        assertFalse(first.fields["request_id"] == second.fields["request_id"])
        assertFalse(first.fields["request_context_hash"] == second.fields["request_context_hash"])
    }

    @Test
    fun `invalid amount fails closed before request is built`() {
        val result = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(
            input().copy(amountSatoshis = 0L)
        )

        assertFalse(result.built)
        assertNull(result.request)
        assertEquals(REASON_ADAMANTINEOS_REQUEST_INVALID, result.denyDecision?.reasonId)
    }

    @Test
    fun `insufficient selected total fails closed before request is built`() {
        val result = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(
            input().copy(selectedInputTotalSatoshis = 100_100L, estimatedFeeSatoshis = 500L)
        )

        assertFalse(result.built)
        assertNull(result.request)
        assertEquals(REASON_ADAMANTINEOS_REQUEST_INVALID, result.denyDecision?.reasonId)
    }

    @Test
    fun `manual request with forbidden field fails allowlist validation`() {
        val request = requireNotNull(AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input()).request)
        val tampered = request.copy(fields = request.fields + mapOf("private_key" to "redacted"))

        val deny = AdamantineWalletActionFieldAllowlist.validate(tampered)

        assertNotNull(deny)
        assertEquals(REASON_ADAMANTINEOS_FORBIDDEN_WALLET_MATERIAL, deny?.reasonId)
    }

    @Test
    fun `manual request with unknown non-secret field fails request validation`() {
        val request = requireNotNull(AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input()).request)
        val tampered = request.copy(fields = request.fields + mapOf("extra_field" to "not allowed"))

        val deny = AdamantineWalletActionFieldAllowlist.validate(tampered)

        assertNotNull(deny)
        assertEquals(REASON_ADAMANTINEOS_REQUEST_INVALID, deny?.reasonId)
    }

    @Test
    fun `manual request with invalid request id fails validation`() {
        val request = requireNotNull(AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(input()).request)
        val tampered = request.copy(fields = request.fields + mapOf("request_id" to "A".repeat(64)))

        val deny = AdamantineWalletActionFieldAllowlist.validate(tampered)

        assertNotNull(deny)
        assertEquals(REASON_ADAMANTINEOS_REQUEST_INVALID, deny?.reasonId)
    }
}
