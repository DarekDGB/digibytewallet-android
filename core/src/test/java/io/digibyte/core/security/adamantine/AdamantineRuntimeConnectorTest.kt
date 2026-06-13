package io.digibyte.core.security.adamantine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdamantineRuntimeConnectorTest {
    private fun actionRequest(): AdamantineWalletActionRequest {
        val result = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(
            AdamantineSendTransactionActionInput(
                walletId = "wallet-runtime-test",
                deviceId = "device-runtime-test",
                sessionId = "session-runtime-test",
                toAddress = "DExampleSafeAddressForRuntimeOnly",
                amountSatoshis = 100_000L,
                feePerKb = 1_000L,
                selectedInputCount = 2,
                selectedInputTotalSatoshis = 150_000L,
                estimatedFeeSatoshis = 500L,
                changeSatoshis = 49_500L,
                availableUtxoCount = 5,
                assetUtxoCount = 1,
                actionNonce = "nonce-runtime-test"
            )
        )

        return requireNotNull(result.request)
    }

    private fun runtimeContextProvider(): AdamantineRuntimeCallContextProvider =
        AdamantineRuntimeCallContextProvider {
            AdamantineRuntimeCallContext(
                nowUnixSeconds = 1_706_985_600L,
                issuedAt = "2024-02-03T20:00:00Z",
                expiresAt = "2024-02-03T20:01:00Z",
                maxSkewSeconds = 0,
                nonceStore = "mobile-runtime-test",
                nonceValue = "runtime-nonce-1",
                audit = mapOf(
                    "client_version" to "test",
                    "platform" to "android"
                )
            )
        }

    private fun completeEvidenceCollector(): AdamantineEvidenceCollector =
        AdamantineEvidenceCollector(
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

    private fun responseFor(
        requestId: String,
        status: String = "allow",
        reasonId: String = REASON_OK_ALLOW,
        allowed: Boolean = true,
        artifacts: Map<String, Any?> = mapOf("executor_result" to "EXECUTED")
    ): Map<String, Any?> {
        val payload = AdamantineTestPayloads.executionResponseV2(
            status = status,
            reasonId = reasonId,
            allowed = allowed,
            artifacts = artifacts
        ).toMutableMap()

        payload["request_id"] = requestId
        return payload
    }

    @Test
    fun `runtime connector denies when runtime context is not wired`() {
        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = DisabledAdamantineExecutionRuntimeHost,
            runtimeContextProvider = null,
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.DENY, decision.status)
        assertEquals(REASON_ADAMANTINEOS_RUNTIME_NOT_WIRED, decision.reasonId)
    }

    @Test
    fun `runtime connector injects request evidence and maps allow response`() {
        val request = actionRequest()
        val runtime = CapturingRuntimeHost { payload ->
            responseFor(requestId = payload["request_id"] as String)
        }

        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = runtime,
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(request)

        assertEquals(AdamantineDecisionStatus.ALLOW, decision.status)
        assertEquals(REASON_OK_ALLOW, decision.reasonId)
        assertEquals(1, runtime.calls)

        val captured = requireNotNull(runtime.lastPayload)
        assertEquals("execution_request_v2", captured["v"])
        assertEquals(request.fields["request_id"], captured["request_id"])
        assertEquals(request.intent, captured["intent"])

        val payload = captured["payload"] as Map<*, *>
        val evidence = payload["evidence"] as Map<*, *>

        assertNotNull(evidence["qid"])
        assertNotNull(evidence["shield"])
        assertNotNull(evidence["oracle"])
        assertFalse(evidence.containsKey("adaptive_core"))
    }

    @Test
    fun `missing evidence fails closed before runtime call`() {
        val runtime = CapturingRuntimeHost { payload ->
            responseFor(requestId = payload["request_id"] as String)
        }

        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = runtime,
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = AdamantineEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.DENY, decision.status)
        assertEquals(REASON_ADAMANTINEOS_QID_EVIDENCE_MISSING, decision.reasonId)
        assertEquals(0, runtime.calls)
    }

    @Test
    fun `runtime deny response maps to wallet deny`() {
        val runtime = CapturingRuntimeHost { payload ->
            responseFor(
                requestId = payload["request_id"] as String,
                status = "deny",
                reasonId = "DENY_POLICY",
                allowed = false,
                artifacts = mapOf("error" to "policy denied")
            )
        }

        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = runtime,
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.DENY, decision.status)
        assertEquals("DENY_POLICY", decision.reasonId)
        assertEquals(1, runtime.calls)
    }

    @Test
    fun `runtime human review response maps to require human confirmation`() {
        val runtime = CapturingRuntimeHost { payload ->
            responseFor(
                requestId = payload["request_id"] as String,
                status = "deny",
                reasonId = "DENY_POLICY",
                allowed = false,
                artifacts = mapOf(
                    "final_policy" to AdamantineTestPayloads.finalPolicyArtifact()
                )
            )
        }

        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = runtime,
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.REQUIRE_HUMAN_CONFIRMATION, decision.status)
        assertEquals("DENY_POLICY", decision.reasonId)
        assertEquals(FINAL_POLICY_HUMAN_REVIEW_REQUIRED, decision.finalPolicyState)
    }

    @Test
    fun `runtime exception fails closed`() {
        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = AdamantineExecutionRuntimeHost { _, _ ->
                throw IllegalStateException("runtime offline")
            },
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.DENY, decision.status)
        assertEquals(REASON_ADAMANTINEOS_EVIDENCE_UNAVAILABLE, decision.reasonId)
    }

    @Test
    fun `malformed runtime response fails closed`() {
        val runtime = CapturingRuntimeHost {
            mapOf("v" to "execution_response_v2")
        }

        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = runtime,
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.DENY, decision.status)
        assertEquals(REASON_ADAMANTINEOS_RESPONSE_INVALID, decision.reasonId)
    }

    @Test
    fun `runtime request id mismatch fails closed`() {
        val runtime = CapturingRuntimeHost {
            responseFor(requestId = "wrong-request-id")
        }

        val boundary = AdamantineRuntimeDecisionBoundary(
            runtimeHost = runtime,
            runtimeContextProvider = runtimeContextProvider(),
            evidenceCollector = completeEvidenceCollector()
        )

        val decision = boundary.evaluate(actionRequest())

        assertEquals(AdamantineDecisionStatus.DENY, decision.status)
        assertEquals(REASON_ADAMANTINEOS_RESPONSE_INVALID, decision.reasonId)
    }

    private class CapturingRuntimeHost(
        private val responder: (Map<String, Any?>) -> Map<String, Any?>
    ) : AdamantineExecutionRuntimeHost {
        var calls: Int = 0
        var lastPayload: Map<String, Any?>? = null
        var lastNow: Long? = null

        override fun evaluateExecutionRequestV2(
            payload: Map<String, Any?>,
            nowUnixSeconds: Long
        ): Map<String, Any?> {
            calls += 1
            lastPayload = payload
            lastNow = nowUnixSeconds
            return responder(payload)
        }
    }
}
