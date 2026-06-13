package io.digibyte.core.security.adamantine

/**
 * Runtime connector boundary for AdamantineOS execution_request_v2 / execution_response_v2.
 *
 * This layer is connector-only. It does not sign, broadcast, create
 * transactions, access keys, read seed material, or perform network calls by
 * itself. A maintainer must provide the runtime host, timebox/nonce context,
 * and evidence providers explicitly.
 */
data class AdamantineRuntimeCallContext(
    val nowUnixSeconds: Long,
    val issuedAt: String,
    val expiresAt: String,
    val maxSkewSeconds: Int = 0,
    val nonceStore: String,
    val nonceValue: String,
    val authorityClass: String = "wallet",
    val authorityScope: Map<String, String> = emptyMap(),
    val audit: Map<String, String> = emptyMap()
)

fun interface AdamantineRuntimeCallContextProvider {
    fun contextFor(request: AdamantineWalletActionRequest): AdamantineRuntimeCallContext?
}

fun interface AdamantineExecutionRuntimeHost {
    fun evaluateExecutionRequestV2(
        payload: Map<String, Any?>,
        nowUnixSeconds: Long
    ): Map<String, Any?>
}

object DisabledAdamantineExecutionRuntimeHost : AdamantineExecutionRuntimeHost {
    override fun evaluateExecutionRequestV2(
        payload: Map<String, Any?>,
        nowUnixSeconds: Long
    ): Map<String, Any?> {
        throw IllegalStateException("AdamantineOS runtime host is not wired")
    }
}

object AdamantineExecutionRequestV2Builder {
    private val isoUtcSeconds = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")

    fun build(
        request: AdamantineWalletActionRequest,
        evidenceBundle: AdamantineEvidenceBundle,
        runtimeContext: AdamantineRuntimeCallContext
    ): Map<String, Any?>? {
        if (runtimeContext.nowUnixSeconds < 0L) return null
        if (!isoUtcSeconds.matches(runtimeContext.issuedAt)) return null
        if (!isoUtcSeconds.matches(runtimeContext.expiresAt)) return null
        if (runtimeContext.maxSkewSeconds < 0) return null
        if (runtimeContext.nonceStore.isBlank()) return null
        if (runtimeContext.nonceValue.isBlank()) return null
        if (runtimeContext.authorityClass.isBlank()) return null
        if (!evidenceBundle.complete) return null

        val requestId = request.fields["request_id"] ?: return null
        val requestContextHash = request.fields["request_context_hash"] ?: return null

        val audit = runtimeContext.audit.toSortedMap()
        val payload = sortedMapOf<String, Any?>(
            "v" to "execution_request_v2",
            "request_id" to requestId,
            "intent" to request.intent,
            "context" to sortedMapOf(
                "wallet_id" to request.walletId,
                "device_id" to request.deviceId,
                "app_id" to request.appId,
                "session_id" to request.sessionId,
                "action" to request.action,
                "fields" to request.fields.toSortedMap()
            ),
            "authority" to sortedMapOf(
                "class" to runtimeContext.authorityClass,
                "scope" to buildAuthorityScope(request, requestContextHash, runtimeContext.authorityScope)
            ),
            "timebox" to sortedMapOf(
                "issued_at" to runtimeContext.issuedAt,
                "expires_at" to runtimeContext.expiresAt,
                "max_skew_seconds" to runtimeContext.maxSkewSeconds
            ),
            "nonce" to sortedMapOf(
                "value" to runtimeContext.nonceValue,
                "store" to runtimeContext.nonceStore,
                "mode" to "single_use"
            ),
            "payload" to sortedMapOf(
                "evidence" to sortedMapOf(
                    "qid" to evidenceBundle.qid.asSummaryMap(),
                    "oracle" to evidenceBundle.adaptiveCore.asSummaryMap(),
                    "shield" to evidenceBundle.shield.asSummaryMap()
                ),
                "body" to sortedMapOf(
                    "wallet_action" to request.action,
                    "wallet_intent" to request.intent,
                    "request_context_hash" to requestContextHash,
                    "native_execution_position" to request.fields["native_execution_position"]
                )
            )
        )

        if (audit.isNotEmpty()) payload["audit"] = audit
        return payload
    }

    private fun buildAuthorityScope(
        request: AdamantineWalletActionRequest,
        requestContextHash: String,
        extraScope: Map<String, String>
    ): Map<String, String> = (sortedMapOf(
        "wallet_id" to request.walletId,
        "device_id" to request.deviceId,
        "app_id" to request.appId,
        "session_id" to request.sessionId,
        "action" to request.action,
        "intent" to request.intent,
        "request_context_hash" to requestContextHash
    ) + extraScope.toSortedMap()).toSortedMap()
}

class AdamantineRuntimeDecisionBoundary(
    private val runtimeHost: AdamantineExecutionRuntimeHost = DisabledAdamantineExecutionRuntimeHost,
    private val runtimeContextProvider: AdamantineRuntimeCallContextProvider? = null,
    private val evidenceCollector: AdamantineEvidenceCollector = AdamantineEvidenceCollector()
) : AdamantineWalletDecisionBoundary {
    override fun evaluate(request: AdamantineWalletActionRequest): AdamantineDecision {
        AdamantineWalletAdapterInvariants.validate(request)?.let { return it }

        if (request.action == ADAMANTINE_ACTION_SEND_TRANSACTION) {
            AdamantineWalletActionFieldAllowlist.validate(request)?.let { return it }
        }

        val providerContext = AdamantineEvidenceProviderContextFactory.fromWalletActionRequest(request)
        val evidenceContext = providerContext.context
            ?: return providerContext.denyDecision ?: AdamantineDecision.deny(REASON_ADAMANTINEOS_EVIDENCE_INVALID)

        val runtimeContext = runtimeContextProvider?.contextFor(request)
            ?: return AdamantineDecision.deny(REASON_ADAMANTINEOS_RUNTIME_NOT_WIRED)

        val evidenceBundle = evidenceCollector.collect(evidenceContext)
        if (!evidenceBundle.complete) {
            return AdamantineDecision.deny(firstEvidenceFailureReason(evidenceBundle))
        }

        val executionRequest = AdamantineExecutionRequestV2Builder.build(
            request = request,
            evidenceBundle = evidenceBundle,
            runtimeContext = runtimeContext
        ) ?: return AdamantineDecision.deny(REASON_ADAMANTINEOS_EVIDENCE_INVALID)

        val response = try {
            runtimeHost.evaluateExecutionRequestV2(executionRequest, runtimeContext.nowUnixSeconds)
        } catch (_: Throwable) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_EVIDENCE_UNAVAILABLE)
        }

        if (response["request_id"] != request.fields["request_id"]) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_RESPONSE_INVALID)
        }

        val validation = AdamantineExecutionResponseV2Validator.validate(response)
        if (!validation.valid) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_RESPONSE_INVALID)
        }

        return AdamantineExecutionResponseMapper.fromExecutionResponseV2(response)
    }

    private fun firstEvidenceFailureReason(bundle: AdamantineEvidenceBundle): String =
        listOf(bundle.qid, bundle.shield, bundle.adaptiveCore)
            .firstOrNull { !it.present || !it.valid }
            ?.reasonId
            ?: REASON_ADAMANTINEOS_EVIDENCE_INVALID
}

const val REASON_ADAMANTINEOS_RUNTIME_NOT_WIRED = "DENY_NOT_WIRED"
