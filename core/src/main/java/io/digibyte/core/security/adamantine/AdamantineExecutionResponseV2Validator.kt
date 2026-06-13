package io.digibyte.core.security.adamantine

/**
 * Strict local validator for AdamantineOS execution_response_v2 payloads.
 *
 * This validator intentionally performs only contract validation. It does not
 * execute wallet actions, does not reach native/JNI code, does not sign, does
 * not broadcast, and does not trust unknown response fields.
 */
data class AdamantineExecutionResponseValidationResult(
    val valid: Boolean,
    val reasonId: String,
    val message: String
) {
    companion object {
        fun valid(): AdamantineExecutionResponseValidationResult =
            AdamantineExecutionResponseValidationResult(
                valid = true,
                reasonId = REASON_OK_ALLOW,
                message = "execution_response_v2 valid"
            )

        fun invalid(message: String): AdamantineExecutionResponseValidationResult =
            AdamantineExecutionResponseValidationResult(
                valid = false,
                reasonId = REASON_ADAMANTINEOS_RESPONSE_INVALID,
                message = message
            )
    }
}

object AdamantineExecutionResponseV2Validator {
    private const val VERSION = "execution_response_v2"

    private val lowercaseHex64 = Regex("^[0-9a-f]{64}$")
    private val isoUtcSeconds = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")
    private val reasonIdShape = Regex("^[A-Z][A-Z0-9_]*$")

    private val topLevelRequiredKeys = setOf(
        "v",
        "request_id",
        "status",
        "reason_id",
        "context_hash",
        "decision"
    )
    private val topLevelAllowedKeys = topLevelRequiredKeys + setOf("artifacts", "metrics")

    private val decisionRequiredKeys = setOf(
        "intent",
        "action",
        "allowed",
        "protection_mode",
        "gates",
        "timebox",
        "nonce",
        "evidence",
        "policy"
    )
    private val decisionAllowedKeys = decisionRequiredKeys

    private val gateRequiredKeys = setOf("tva", "eqc", "wsqk")
    private val gateAllowedKeys = gateRequiredKeys
    private val gateResultRequiredKeys = setOf("allowed", "reason_id")
    private val gateResultAllowedKeys = gateResultRequiredKeys

    private val timeboxRequiredKeys = setOf(
        "valid",
        "issued_at",
        "expires_at",
        "max_skew_seconds",
        "reason_id"
    )
    private val timeboxAllowedKeys = timeboxRequiredKeys

    private val nonceRequiredKeys = setOf("consumed", "store", "value", "reason_id")
    private val nonceAllowedKeys = nonceRequiredKeys

    private val evidenceRequiredKeys = setOf("qid", "shield", "oracle")
    private val evidenceAllowedKeys = evidenceRequiredKeys
    private val evidenceSummaryRequiredKeys = setOf("present", "valid", "reason_id")
    private val evidenceSummaryAllowedKeys = evidenceSummaryRequiredKeys

    private val policyRequiredKeys = setOf("mode", "override_allowed", "reason_id")
    private val policyAllowedKeys = policyRequiredKeys

    private val allowedStatuses = setOf("allow", "deny", "error")
    private val allowedProtectionModes = setOf("legacy", "minimal", "full")

    private val allowedArtifactKeys = setOf(
        "error",
        "evidence",
        "executor_result",
        "final_policy",
        "final_policy_invariant",
        "shield_adapter_message",
        "shield_adapter_reason"
    )

    private val finalPolicyRequiredKeys = setOf(
        "state",
        "outcome",
        "final_approval",
        "handoff_allowed",
        "stopped_at",
        "evaluation_order",
        "dominant_reason_ids"
    )
    private val finalPolicyAllowedKeys = finalPolicyRequiredKeys

    private val finalPolicyStates = setOf(
        "ALLOW_FINAL_ADAMANTINEOS_DECISION",
        "HUMAN_REVIEW_REQUIRED",
        "DENY_MISSING_EVIDENCE",
        "DENY_EVIDENCE_REJECTED",
        "DENY_AUTHORITY_BYPASS",
        "DENY_HANDOFF_BLOCKED",
        "DENY_REPLAY_GATE",
        "DENY_WALLET_POLICY_GATE",
        "DENY_HUMAN_GATE",
        "DENY_GATE_SHAPE_INVALID",
        "DENY_CONTEXT_MISMATCH",
        "DENY_REASON_ID_INVALID"
    )

    private val finalPolicyInvariantRequiredKeys = setOf("status", "reason", "original_state")
    private val finalPolicyInvariantAllowedKeys = finalPolicyInvariantRequiredKeys

    private val adamantineReasonIds = setOf(
        "TVA_MISSING_CONTEXT",
        "TVA_MISSING_VERDICT",
        "TVA_MISSING_AUTHORITY",
        "TVA_VERDICT_NOT_ALLOW",
        "TVA_AUTHORITY_WALLET_MISMATCH",
        "TVA_AUTHORITY_ACTION_MISMATCH",
        "TVA_AUTHORITY_CONTEXT_HASH_MISMATCH",
        "TVA_MISSING_NOW",
        "TVA_INVALID_TIME_WINDOW",
        "TVA_AUTHORITY_NOT_YET_VALID",
        "TVA_AUTHORITY_EXPIRED",
        "TVA_MISSING_NONCE_STORE",
        "TVA_NONCE_REPLAY",
        "TVA_INVALID_NONCE",
        "TVA_WSQK_V2_REQUIRED",
        "TVA_WSQK_V2_EVIDENCE_FAMILY_MISMATCH",
        "TVA_WSQK_V2_QUANTUM_POSTURE_MISMATCH",
        "TVA_WSQK_V2_PROOF_BINDINGS_HASH_MISMATCH",
        "EQC_MISSING_WALLET_ID",
        "EQC_MISSING_ACTION",
        "EQC_MISSING_NOW",
        "EQC_MISSING_QID_SESSION",
        "EQC_QID_SESSION_EXPIRED",
        "EQC_QID_SESSION_NOT_YET_VALID",
        "EQC_INVALID_QID_PROOF",
        "QID_REPLAY_PROOF_MISSING",
        "QID_REPLAY_PROOF_INVALID",
        "QID_REPLAY_WALLET_MISMATCH",
        "QID_REPLAY_SUBJECT_MISMATCH",
        "QID_REPLAY_DEVICE_MISMATCH",
        "QID_REPLAY_PROOF_HASH_MISMATCH",
        "QID_REPLAY_NONCE_MISMATCH",
        "QID_NONCE_REPLAY",
        "EQC_MISSING_RISK_REPORT",
        "EQC_RISK_CONTEXT_HASH_MISMATCH",
        "EQC_RISK_SCORE_BELOW_THRESHOLD",
        "EQC_INVALID_RISK_REPORT",
        "EQC_MISSING_ORACLE",
        "EQC_MISSING_SHIELD_BUNDLE",
        "EQC_INVALID_SHIELD_BUNDLE",
        "EQC_SHIELD_CONTEXT_HASH_MISMATCH",
        "EQC_SHIELD_STALE",
        "EQC_CONFLICTING_EVIDENCE",
        "UNKNOWN_EXTERNAL_REASON",
        "EVIDENCE_OK",
        "WSQK_MISSING_WALLET_ID",
        "WSQK_MISSING_ACTION",
        "WSQK_MISSING_CONTEXT_HASH",
        "WSQK_MISSING_NOW",
        "WSQK_INVALID_TTL",
        "WSQK_INVALID_NONCE",
        "WSQK_V2_INVALID_EVIDENCE_FAMILIES",
        "WSQK_V2_UNKNOWN_EVIDENCE_FAMILY",
        "WSQK_V2_INVALID_QUANTUM_POSTURE",
        "WSQK_V2_AUTHORITY_MAPPING_MISSING_FIELD",
        "WSQK_V2_AUTHORITY_MAPPING_INVALID_FIELD",
        "WSQK_QID_POSTURE_MISMATCH",
        "WSQK_QID_HYBRID_REQUIRED",
        "WSQK_QID_BINDING_INVALID",
        "OK_ALLOW",
        "DENY_SCHEMA_INVALID",
        "DENY_UNKNOWN_FIELD",
        "DENY_VERSION_MISMATCH",
        "DENY_INTENT_UNSUPPORTED",
        "DENY_PAYLOAD_INVALID",
        "DENY_TIMEBOX_INVALID",
        "DENY_TIMEBOX_EXPIRED",
        "DENY_TIMEBOX_NOT_YET_VALID",
        "DENY_TIMEBOX_SKEW_EXCEEDED",
        "DENY_NONCE_INVALID",
        "DENY_NONCE_REPLAY",
        "DENY_NONCE_STORE_ERROR",
        "DENY_AUTHORITY_INVALID",
        "DENY_AUTHORITY_INSUFFICIENT",
        "DENY_POLICY",
        "DENY_EQC",
        "DENY_WSQK",
        "DENY_TVA",
        "DENY_ADAPTER_INVALID",
        "DENY_ADAPTER_UNAVAILABLE",
        "ERR_INTERNAL",
        "ERR_UNHANDLED",
        "DENY_NOT_WIRED"
    )

    fun validate(payload: Map<String, Any?>): AdamantineExecutionResponseValidationResult {
        validateKeys("response", payload, topLevelRequiredKeys, topLevelAllowedKeys)?.let { return it }

        val version = payload["v"] as? String
            ?: return invalid("response.v must be a string")
        if (version != VERSION) return invalid("response.v must equal $VERSION")

        requireNonBlankString(payload["request_id"], "response.request_id")?.let { return it }

        val status = payload["status"] as? String
            ?: return invalid("response.status must be a string")
        if (status !in allowedStatuses) return invalid("response.status must be allow, deny, or error")

        val reasonId = payload["reason_id"] as? String
            ?: return invalid("response.reason_id must be a string")
        validateRegistryReasonId(reasonId, "response.reason_id")?.let { return it }

        val contextHash = payload["context_hash"] as? String
            ?: return invalid("response.context_hash must be a string")
        validateContextHash(contextHash, "response.context_hash")?.let { return it }

        val decision = asObject(payload["decision"], "response.decision") ?: return invalid("response.decision must be an object")
        validateDecision(decision, status, reasonId)?.let { return it }

        val artifacts = payload["artifacts"]
        if (artifacts != null) {
            val artifactObject = asObject(artifacts, "response.artifacts")
                ?: return invalid("response.artifacts must be an object")
            validateArtifacts(artifactObject)?.let { return it }
        }

        val metrics = payload["metrics"]
        if (metrics != null) {
            val metricsObject = asObject(metrics, "response.metrics")
                ?: return invalid("response.metrics must be an object")
            validateMetrics(metricsObject)?.let { return it }
        }

        return AdamantineExecutionResponseValidationResult.valid()
    }

    private fun validateDecision(
        decision: Map<*, *>,
        status: String,
        reasonId: String
    ): AdamantineExecutionResponseValidationResult? {
        validateKeys("decision", decision, decisionRequiredKeys, decisionAllowedKeys)?.let { return it }

        requireNonBlankString(decision["intent"], "decision.intent")?.let { return it }
        requireNonBlankString(decision["action"], "decision.action")?.let { return it }

        val allowed = decision["allowed"] as? Boolean
            ?: return invalid("decision.allowed must be boolean")

        if (status == "allow" && !allowed) return invalid("status allow requires decision.allowed true")
        if (status != "allow" && allowed) return invalid("status deny/error requires decision.allowed false")
        if (status == "allow" && reasonId != REASON_OK_ALLOW) return invalid("allow requires OK_ALLOW reason_id")
        if (status == "deny" && reasonId == REASON_OK_ALLOW) return invalid("deny must not use OK_ALLOW reason_id")
        if (status == "error" && !reasonId.startsWith("ERR_")) return invalid("error status requires ERR_* reason_id")

        val protectionMode = decision["protection_mode"] as? String
            ?: return invalid("decision.protection_mode must be a string")
        if (protectionMode !in allowedProtectionModes) {
            return invalid("decision.protection_mode must be legacy, minimal, or full")
        }

        val gates = asObject(decision["gates"], "decision.gates")
            ?: return invalid("decision.gates must be an object")
        validateGates(gates)?.let { return it }

        val timebox = asObject(decision["timebox"], "decision.timebox")
            ?: return invalid("decision.timebox must be an object")
        validateTimebox(timebox)?.let { return it }

        val nonce = asObject(decision["nonce"], "decision.nonce")
            ?: return invalid("decision.nonce must be an object")
        validateNonce(nonce)?.let { return it }

        val evidence = asObject(decision["evidence"], "decision.evidence")
            ?: return invalid("decision.evidence must be an object")
        validateEvidence(evidence)?.let { return it }

        val policy = asObject(decision["policy"], "decision.policy")
            ?: return invalid("decision.policy must be an object")
        validatePolicy(policy)?.let { return it }

        return null
    }

    private fun validateGates(gates: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys("decision.gates", gates, gateRequiredKeys, gateAllowedKeys)?.let { return it }
        for (gateName in gateRequiredKeys) {
            val gate = asObject(gates[gateName], "decision.gates.$gateName")
                ?: return invalid("decision.gates.$gateName must be an object")
            validateKeys("decision.gates.$gateName", gate, gateResultRequiredKeys, gateResultAllowedKeys)?.let { return it }
            if (gate["allowed"] !is Boolean) return invalid("decision.gates.$gateName.allowed must be boolean")
            val gateReason = gate["reason_id"] as? String
                ?: return invalid("decision.gates.$gateName.reason_id must be string")
            validateRegistryReasonId(gateReason, "decision.gates.$gateName.reason_id")?.let { return it }
        }
        return null
    }

    private fun validateTimebox(timebox: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys("decision.timebox", timebox, timeboxRequiredKeys, timeboxAllowedKeys)?.let { return it }
        if (timebox["valid"] !is Boolean) return invalid("decision.timebox.valid must be boolean")

        val issuedAt = timebox["issued_at"] as? String
            ?: return invalid("decision.timebox.issued_at must be string")
        if (!isoUtcSeconds.matches(issuedAt)) return invalid("decision.timebox.issued_at must be UTC ISO seconds")

        val expiresAt = timebox["expires_at"] as? String
            ?: return invalid("decision.timebox.expires_at must be string")
        if (!isoUtcSeconds.matches(expiresAt)) return invalid("decision.timebox.expires_at must be UTC ISO seconds")

        val skew = timebox["max_skew_seconds"]
        if (skew !is Int || skew < 0) return invalid("decision.timebox.max_skew_seconds must be non-negative int")

        val reason = timebox["reason_id"] as? String
            ?: return invalid("decision.timebox.reason_id must be string")
        validateRegistryReasonId(reason, "decision.timebox.reason_id")?.let { return it }
        return null
    }

    private fun validateNonce(nonce: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys("decision.nonce", nonce, nonceRequiredKeys, nonceAllowedKeys)?.let { return it }
        if (nonce["consumed"] !is Boolean) return invalid("decision.nonce.consumed must be boolean")
        requireNonBlankString(nonce["store"], "decision.nonce.store")?.let { return it }
        requireNonBlankString(nonce["value"], "decision.nonce.value")?.let { return it }
        val reason = nonce["reason_id"] as? String
            ?: return invalid("decision.nonce.reason_id must be string")
        validateRegistryReasonId(reason, "decision.nonce.reason_id")?.let { return it }
        return null
    }

    private fun validateEvidence(evidence: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys("decision.evidence", evidence, evidenceRequiredKeys, evidenceAllowedKeys)?.let { return it }
        for (source in evidenceRequiredKeys) {
            val summary = asObject(evidence[source], "decision.evidence.$source")
                ?: return invalid("decision.evidence.$source must be an object")
            validateKeys(
                "decision.evidence.$source",
                summary,
                evidenceSummaryRequiredKeys,
                evidenceSummaryAllowedKeys
            )?.let { return it }
            if (summary["present"] !is Boolean) return invalid("decision.evidence.$source.present must be boolean")
            if (summary["valid"] !is Boolean) return invalid("decision.evidence.$source.valid must be boolean")
            val reason = summary["reason_id"] as? String
                ?: return invalid("decision.evidence.$source.reason_id must be string")
            validateRegistryReasonId(reason, "decision.evidence.$source.reason_id")?.let { return it }
        }
        return null
    }

    private fun validatePolicy(policy: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys("decision.policy", policy, policyRequiredKeys, policyAllowedKeys)?.let { return it }
        requireNonBlankString(policy["mode"], "decision.policy.mode")?.let { return it }
        if (policy["override_allowed"] !is Boolean) return invalid("decision.policy.override_allowed must be boolean")
        val reason = policy["reason_id"] as? String
            ?: return invalid("decision.policy.reason_id must be string")
        validateRegistryReasonId(reason, "decision.policy.reason_id")?.let { return it }
        return null
    }

    private fun validateArtifacts(artifacts: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        val artifactKeys = stringKeySet(artifacts, "response.artifacts") ?: return invalid("response.artifacts keys must be strings")
        val unknown = artifactKeys - allowedArtifactKeys
        if (unknown.isNotEmpty()) return invalid("response.artifacts contains unknown keys: ${unknown.sorted()}")

        for (key in artifactKeys) {
            if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                return invalid("response.artifacts contains forbidden wallet-material key")
            }
        }

        validateNoForbiddenArtifactKeys(artifacts)?.let { return it }

        val finalPolicy = artifacts["final_policy"]
        if (finalPolicy != null) {
            val finalPolicyObject = asObject(finalPolicy, "response.artifacts.final_policy")
                ?: return invalid("response.artifacts.final_policy must be an object")
            validateFinalPolicyArtifact(finalPolicyObject)?.let { return it }
        }

        val finalPolicyInvariant = artifacts["final_policy_invariant"]
        if (finalPolicyInvariant != null) {
            val invariantObject = asObject(finalPolicyInvariant, "response.artifacts.final_policy_invariant")
                ?: return invalid("response.artifacts.final_policy_invariant must be an object")
            validateFinalPolicyInvariantArtifact(invariantObject)?.let { return it }
        }

        return null
    }

    private fun validateFinalPolicyArtifact(finalPolicy: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys(
            "response.artifacts.final_policy",
            finalPolicy,
            finalPolicyRequiredKeys,
            finalPolicyAllowedKeys
        )?.let { return it }

        val state = finalPolicy["state"] as? String
            ?: return invalid("response.artifacts.final_policy.state must be string")
        if (state !in finalPolicyStates) return invalid("response.artifacts.final_policy.state is unknown")

        requireNonBlankString(finalPolicy["outcome"], "response.artifacts.final_policy.outcome")?.let { return it }
        if (finalPolicy["final_approval"] !is Boolean) {
            return invalid("response.artifacts.final_policy.final_approval must be boolean")
        }
        if (finalPolicy["handoff_allowed"] !is Boolean) {
            return invalid("response.artifacts.final_policy.handoff_allowed must be boolean")
        }
        requireNonBlankString(finalPolicy["stopped_at"], "response.artifacts.final_policy.stopped_at")?.let { return it }

        val order = finalPolicy["evaluation_order"] as? List<*>
            ?: return invalid("response.artifacts.final_policy.evaluation_order must be list")
        if (order.any { it !is String || it.isBlank() }) {
            return invalid("response.artifacts.final_policy.evaluation_order entries must be non-empty strings")
        }

        val dominant = finalPolicy["dominant_reason_ids"] as? List<*>
            ?: return invalid("response.artifacts.final_policy.dominant_reason_ids must be list")
        if (dominant.any { it !is String || !reasonIdShape.matches(it) }) {
            return invalid("response.artifacts.final_policy.dominant_reason_ids entries must be reason-shaped strings")
        }

        return null
    }

    private fun validateFinalPolicyInvariantArtifact(invariant: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        validateKeys(
            "response.artifacts.final_policy_invariant",
            invariant,
            finalPolicyInvariantRequiredKeys,
            finalPolicyInvariantAllowedKeys
        )?.let { return it }
        if (invariant["status"] != "fail_closed") {
            return invalid("response.artifacts.final_policy_invariant.status must be fail_closed")
        }
        requireNonBlankString(invariant["reason"], "response.artifacts.final_policy_invariant.reason")?.let { return it }
        val originalState = invariant["original_state"] as? String
            ?: return invalid("response.artifacts.final_policy_invariant.original_state must be string")
        if (originalState !in finalPolicyStates) {
            return invalid("response.artifacts.final_policy_invariant.original_state is unknown")
        }
        return null
    }

    private fun validateMetrics(metrics: Map<*, *>): AdamantineExecutionResponseValidationResult? {
        val keys = stringKeySet(metrics, "response.metrics") ?: return invalid("response.metrics keys must be strings")
        for (key in keys) {
            if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                return invalid("response.metrics contains forbidden wallet-material key")
            }
            val value = metrics[key]
            if (value !is Int || value < 0) {
                return invalid("response.metrics values must be non-negative integers")
            }
        }
        return null
    }

    private fun validateNoForbiddenArtifactKeys(value: Any?): AdamantineExecutionResponseValidationResult? {
        when (value) {
            is Map<*, *> -> {
                for ((key, child) in value) {
                    if (key !is String) return invalid("artifact nested keys must be strings")
                    if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                        return invalid("artifact contains forbidden wallet-material key")
                    }
                    validateNoForbiddenArtifactKeys(child)?.let { return it }
                }
            }
            is List<*> -> {
                for (child in value) validateNoForbiddenArtifactKeys(child)?.let { return it }
            }
        }
        return null
    }

    private fun validateRegistryReasonId(
        reasonId: String,
        field: String
    ): AdamantineExecutionResponseValidationResult? {
        if (reasonId.isBlank()) return invalid("$field must be non-empty")
        if (!reasonIdShape.matches(reasonId)) return invalid("$field must be uppercase reason_id shape")
        if (reasonId !in adamantineReasonIds) return invalid("$field is not in AdamantineOS reason registry")
        return null
    }

    private fun validateContextHash(value: String, field: String): AdamantineExecutionResponseValidationResult? {
        if (!lowercaseHex64.matches(value)) return invalid("$field must be 64 lowercase hex characters")
        return null
    }

    private fun requireNonBlankString(value: Any?, field: String): AdamantineExecutionResponseValidationResult? {
        if (value !is String || value.isBlank()) return invalid("$field must be non-empty string")
        return null
    }

    private fun asObject(value: Any?, field: String): Map<*, *>? {
        if (value !is Map<*, *>) return null
        stringKeySet(value, field) ?: return null
        return value
    }

    private fun validateKeys(
        name: String,
        obj: Map<*, *>,
        required: Set<String>,
        allowed: Set<String>
    ): AdamantineExecutionResponseValidationResult? {
        val keys = stringKeySet(obj, name) ?: return invalid("$name keys must be strings")
        val missing = required - keys
        if (missing.isNotEmpty()) return invalid("$name missing required keys: ${missing.sorted()}")
        val unknown = keys - allowed
        if (unknown.isNotEmpty()) return invalid("$name contains unknown keys: ${unknown.sorted()}")
        return null
    }

    private fun stringKeySet(obj: Map<*, *>, name: String): Set<String>? {
        val keys = mutableSetOf<String>()
        for (key in obj.keys) {
            if (key !is String) return null
            if (key.isBlank()) return null
            keys += key
        }
        return keys
    }

    private fun invalid(message: String): AdamantineExecutionResponseValidationResult =
        AdamantineExecutionResponseValidationResult.invalid(message)
}
