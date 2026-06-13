package io.digibyte.core.security.adamantine

internal object AdamantineTestPayloads {
    fun executionResponseV2(
        status: String = "allow",
        reasonId: String = REASON_OK_ALLOW,
        allowed: Boolean = true,
        protectionMode: String = "full",
        contextHash: String = "a".repeat(64),
        artifacts: Map<String, Any?> = mapOf("executor_result" to "EXECUTED"),
        metrics: Map<String, Any?>? = null
    ): Map<String, Any?> {
        val gateReason = if (allowed) REASON_OK_ALLOW else reasonId
        val payload = mutableMapOf<String, Any?>(
            "v" to "execution_response_v2",
            "request_id" to "req-local-test",
            "status" to status,
            "reason_id" to reasonId,
            "context_hash" to contextHash,
            "decision" to mapOf(
                "intent" to "authorize",
                "action" to "send",
                "allowed" to allowed,
                "protection_mode" to protectionMode,
                "gates" to mapOf(
                    "tva" to mapOf("allowed" to allowed, "reason_id" to gateReason),
                    "eqc" to mapOf("allowed" to allowed, "reason_id" to gateReason),
                    "wsqk" to mapOf("allowed" to allowed, "reason_id" to gateReason)
                ),
                "timebox" to mapOf(
                    "valid" to true,
                    "issued_at" to "2024-02-03T20:00:00Z",
                    "expires_at" to "2024-02-03T20:01:00Z",
                    "max_skew_seconds" to 0,
                    "reason_id" to REASON_OK_ALLOW
                ),
                "nonce" to mapOf(
                    "consumed" to allowed,
                    "store" to "tva",
                    "value" to "n1",
                    "reason_id" to gateReason
                ),
                "evidence" to mapOf(
                    "qid" to mapOf("present" to true, "valid" to allowed, "reason_id" to gateReason),
                    "shield" to mapOf("present" to true, "valid" to allowed, "reason_id" to gateReason),
                    "oracle" to mapOf("present" to true, "valid" to allowed, "reason_id" to gateReason)
                ),
                "policy" to mapOf(
                    "mode" to "STRICT_FAIL_CLOSED",
                    "override_allowed" to false,
                    "reason_id" to gateReason
                )
            )
        )
        if (artifacts.isNotEmpty()) payload["artifacts"] = artifacts
        if (metrics != null) payload["metrics"] = metrics
        return payload
    }

    fun finalPolicyArtifact(
        state: String = FINAL_POLICY_HUMAN_REVIEW_REQUIRED,
        outcome: String = "HUMAN_REVIEW_REQUIRED",
        finalApproval: Boolean = false,
        handoffAllowed: Boolean = false,
        stoppedAt: String = "human",
        dominantReasonIds: List<String> = listOf("DENY_POLICY")
    ): Map<String, Any?> = mapOf(
        "state" to state,
        "outcome" to outcome,
        "final_approval" to finalApproval,
        "handoff_allowed" to handoffAllowed,
        "stopped_at" to stoppedAt,
        "evaluation_order" to listOf(
            "shield",
            "wsqk_v2",
            "qid",
            "adaptive_core",
            "ai_gateway",
            "replay",
            "wallet_policy",
            "human"
        ),
        "dominant_reason_ids" to dominantReasonIds
    )
}
