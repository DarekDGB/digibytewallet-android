package io.digibyte.core.security.adamantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdamantineEvidenceProvidersTest {
    private fun actionRequest(): AdamantineWalletActionRequest {
        val result = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(
            AdamantineSendTransactionActionInput(
                walletId = "wallet-evidence-test",
                deviceId = "device-evidence-test",
                sessionId = "session-evidence-test",
                toAddress = "DExampleSafeAddressForEvidenceOnly",
                amountSatoshis = 100_000L,
                feePerKb = 1_000L,
                selectedInputCount = 2,
                selectedInputTotalSatoshis = 150_000L,
                estimatedFeeSatoshis = 500L,
                changeSatoshis = 49_500L,
                availableUtxoCount = 5,
                assetUtxoCount = 1,
                actionNonce = "nonce-evidence-test"
            )
        )

        return requireNotNull(result.request)
    }

    private fun context(): AdamantineEvidenceProviderContext {
        val result = AdamantineEvidenceProviderContextFactory.fromWalletActionRequest(actionRequest())
        assertTrue(result.built)
        return requireNotNull(result.context)
    }

    @Test
    fun `context factory builds evidence context from safe wallet action request`() {
        val request = actionRequest()
        val result = AdamantineEvidenceProviderContextFactory.fromWalletActionRequest(request)

        assertTrue(result.built)
        val context = requireNotNull(result.context)
        assertEquals(request.walletId, context.walletId)
        assertEquals(request.deviceId, context.deviceId)
        assertEquals(request.appId, context.appId)
        assertEquals(request.sessionId, context.sessionId)
        assertEquals(request.action, context.action)
        assertEquals(request.intent, context.intent)
        assertEquals(request.fields["request_id"], context.requestId)
        assertEquals(request.fields["request_context_hash"], context.requestContextHash)
    }

    @Test
    fun `context factory rejects tampered request hash`() {
        val request = actionRequest()
        val tampered = request.copy(
            fields = request.fields + mapOf("request_context_hash" to "A".repeat(64))
        )

        val result = AdamantineEvidenceProviderContextFactory.fromWalletActionRequest(tampered)

        assertFalse(result.built)
        assertEquals(REASON_ADAMANTINEOS_REQUEST_INVALID, result.denyDecision?.reasonId)
    }

    @Test
    fun `missing providers create incomplete fail closed evidence bundle`() {
        val bundle = AdamantineEvidenceCollector().collect(context())

        assertFalse(bundle.complete)
        assertFalse(bundle.qid.present)
        assertFalse(bundle.qid.valid)
        assertEquals(REASON_ADAMANTINEOS_QID_EVIDENCE_MISSING, bundle.qid.reasonId)

        assertFalse(bundle.shield.present)
        assertFalse(bundle.shield.valid)
        assertEquals(REASON_ADAMANTINEOS_SHIELD_EVIDENCE_MISSING, bundle.shield.reasonId)

        assertFalse(bundle.adaptiveCore.present)
        assertFalse(bundle.adaptiveCore.valid)
        assertEquals(REASON_ADAMANTINEOS_ADAPTIVE_EVIDENCE_MISSING, bundle.adaptiveCore.reasonId)
    }

    @Test
    fun `configured providers create complete deterministic evidence bundle`() {
        val collector = AdamantineEvidenceCollector(
            qidProvider = StaticAdamantineEvidenceProvider(
                AdamantineEvidenceProviderResult.valid(
                    source = AdamantineEvidenceSource.QID,
                    fields = mapOf("qid_session" to "qid-ok")
                )
            ),
            shieldProvider = StaticAdamantineEvidenceProvider(
                AdamantineEvidenceProviderResult.valid(
                    source = AdamantineEvidenceSource.SHIELD,
                    fields = mapOf("shield_receipt" to "shield-ok")
                )
            ),
            adaptiveCoreProvider = StaticAdamantineEvidenceProvider(
                AdamantineEvidenceProviderResult.valid(
                    source = AdamantineEvidenceSource.ADAPTIVE_CORE,
                    fields = mapOf("risk_report" to "adaptive-ok")
                )
            )
        )

        val bundle = collector.collect(context())
        val runtimeMap = bundle.toRuntimeEvidenceMap()

        assertTrue(bundle.complete)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_OK, bundle.qid.reasonId)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_OK, bundle.shield.reasonId)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_OK, bundle.adaptiveCore.reasonId)
        assertTrue(bundle.qid.evidenceHash?.matches(Regex("^[0-9a-f]{64}$")) == true)
        assertTrue(bundle.shield.evidenceHash?.matches(Regex("^[0-9a-f]{64}$")) == true)
        assertTrue(bundle.adaptiveCore.evidenceHash?.matches(Regex("^[0-9a-f]{64}$")) == true)
        assertEquals(3, runtimeMap.size)
        assertNotNull(runtimeMap["qid"])
        assertNotNull(runtimeMap["shield"])
        assertNotNull(runtimeMap["adaptive_core"])
    }

    @Test
    fun `provider returning wrong source fails closed`() {
        val collector = AdamantineEvidenceCollector(
            qidProvider = StaticAdamantineEvidenceProvider(
                AdamantineEvidenceProviderResult.valid(
                    source = AdamantineEvidenceSource.SHIELD,
                    fields = mapOf("shield_receipt" to "wrong-source")
                )
            )
        )

        val bundle = collector.collect(context())

        assertFalse(bundle.complete)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_INVALID, bundle.qid.reasonId)
        assertFalse(bundle.qid.valid)
    }

    @Test
    fun `provider with forbidden wallet material key fails closed`() {
        val collector = AdamantineEvidenceCollector(
            qidProvider = StaticAdamantineEvidenceProvider(
                AdamantineEvidenceProviderResult.valid(
                    source = AdamantineEvidenceSource.QID,
                    fields = mapOf("private_key" to "redacted")
                )
            )
        )

        val bundle = collector.collect(context())

        assertFalse(bundle.complete)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_INVALID, bundle.qid.reasonId)
        assertFalse(bundle.qid.valid)
    }

    @Test
    fun `provider exception fails closed as unavailable`() {
        val collector = AdamantineEvidenceCollector(
            qidProvider = AdamantineEvidenceProvider {
                throw IllegalStateException("provider offline")
            }
        )

        val bundle = collector.collect(context())

        assertFalse(bundle.complete)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_UNAVAILABLE, bundle.qid.reasonId)
        assertFalse(bundle.qid.valid)
    }
}
