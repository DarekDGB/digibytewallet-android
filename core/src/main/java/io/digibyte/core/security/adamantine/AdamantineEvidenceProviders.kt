package io.digibyte.core.security.adamantine

/**
 * Wallet-side evidence provider scaffolding for AdamantineOS.
 *
 * This layer collects safe evidence summaries only. It does not call a live
 * AdamantineOS runtime, does not access keys, does not sign, does not broadcast,
 * and does not alter wallet execution by itself.
 */
enum class AdamantineEvidenceSource(
    val wireName: String,
    val missingReasonId: String
) {
    QID("qid", REASON_ADAMANTINEOS_QID_EVIDENCE_MISSING),
    SHIELD("shield", REASON_ADAMANTINEOS_SHIELD_EVIDENCE_MISSING),
    ADAPTIVE_CORE("adaptive_core", REASON_ADAMANTINEOS_ADAPTIVE_EVIDENCE_MISSING)
}

data class AdamantineEvidenceProviderContext(
    val walletId: String,
    val deviceId: String,
    val appId: String,
    val sessionId: String,
    val action: String,
    val intent: String,
    val requestId: String,
    val requestContextHash: String
)

data class AdamantineEvidenceProviderContextBuildResult(
    val context: AdamantineEvidenceProviderContext?,
    val denyDecision: AdamantineDecision?
) {
    val built: Boolean
        get() = context != null && denyDecision == null

    companion object {
        fun built(context: AdamantineEvidenceProviderContext): AdamantineEvidenceProviderContextBuildResult =
            AdamantineEvidenceProviderContextBuildResult(context = context, denyDecision = null)

        fun deny(reasonId: String): AdamantineEvidenceProviderContextBuildResult =
            AdamantineEvidenceProviderContextBuildResult(
                context = null,
                denyDecision = AdamantineDecision.deny(reasonId)
            )
    }
}

object AdamantineEvidenceProviderContextFactory {
    private val lowercaseHex64 = Regex("^[0-9a-f]{64}$")

    fun fromWalletActionRequest(
        request: AdamantineWalletActionRequest
    ): AdamantineEvidenceProviderContextBuildResult {
        AdamantineWalletAdapterInvariants.validate(request)?.let {
            return AdamantineEvidenceProviderContextBuildResult.deny(it.reasonId)
        }

        if (request.action == ADAMANTINE_ACTION_SEND_TRANSACTION) {
            AdamantineWalletActionFieldAllowlist.validate(request)?.let {
                return AdamantineEvidenceProviderContextBuildResult.deny(it.reasonId)
            }
        }

        val requestId = request.fields["request_id"]
            ?: return AdamantineEvidenceProviderContextBuildResult.deny(REASON_ADAMANTINEOS_EVIDENCE_INVALID)
        val requestContextHash = request.fields["request_context_hash"]
            ?: return AdamantineEvidenceProviderContextBuildResult.deny(REASON_ADAMANTINEOS_EVIDENCE_INVALID)

        if (!lowercaseHex64.matches(requestId)) {
            return AdamantineEvidenceProviderContextBuildResult.deny(REASON_ADAMANTINEOS_EVIDENCE_INVALID)
        }
        if (!lowercaseHex64.matches(requestContextHash)) {
            return AdamantineEvidenceProviderContextBuildResult.deny(REASON_ADAMANTINEOS_EVIDENCE_INVALID)
        }

        return AdamantineEvidenceProviderContextBuildResult.built(
            AdamantineEvidenceProviderContext(
                walletId = request.walletId,
                deviceId = request.deviceId,
                appId = request.appId,
                sessionId = request.sessionId,
                action = request.action,
                intent = request.intent,
                requestId = requestId,
                requestContextHash = requestContextHash
            )
        )
    }
}

data class AdamantineEvidenceProviderResult(
    val source: AdamantineEvidenceSource,
    val present: Boolean,
    val valid: Boolean,
    val reasonId: String,
    val evidenceHash: String? = null,
    val fields: Map<String, String> = emptyMap()
) {
    fun asSummaryMap(): Map<String, Any?> = mapOf(
        "source" to source.wireName,
        "present" to present,
        "valid" to valid,
        "reason_id" to reasonId,
        "evidence_hash" to evidenceHash,
        "fields" to fields.toSortedMap()
    )

    companion object {
        fun valid(
            source: AdamantineEvidenceSource,
            fields: Map<String, String>
        ): AdamantineEvidenceProviderResult {
            val safeFields = fields.toSortedMap()
            val hash = AdamantineWalletActionCanonicalizer.sha256Hex(
                AdamantineWalletActionCanonicalizer.canonicalize(
                    safeFields + mapOf(
                        "source" to source.wireName,
                        "reason_id" to REASON_ADAMANTINEOS_EVIDENCE_OK
                    )
                )
            )
            return AdamantineEvidenceProviderResult(
                source = source,
                present = true,
                valid = true,
                reasonId = REASON_ADAMANTINEOS_EVIDENCE_OK,
                evidenceHash = hash,
                fields = safeFields
            )
        }

        fun missing(source: AdamantineEvidenceSource): AdamantineEvidenceProviderResult =
            AdamantineEvidenceProviderResult(
                source = source,
                present = false,
                valid = false,
                reasonId = source.missingReasonId
            )

        fun invalid(
            source: AdamantineEvidenceSource,
            reasonId: String = REASON_ADAMANTINEOS_EVIDENCE_INVALID
        ): AdamantineEvidenceProviderResult = AdamantineEvidenceProviderResult(
            source = source,
            present = true,
            valid = false,
            reasonId = reasonId
        )
    }
}

fun interface AdamantineEvidenceProvider {
    fun collect(context: AdamantineEvidenceProviderContext): AdamantineEvidenceProviderResult
}

class MissingAdamantineEvidenceProvider(
    private val source: AdamantineEvidenceSource
) : AdamantineEvidenceProvider {
    override fun collect(context: AdamantineEvidenceProviderContext): AdamantineEvidenceProviderResult =
        AdamantineEvidenceProviderResult.missing(source)
}

class StaticAdamantineEvidenceProvider(
    private val result: AdamantineEvidenceProviderResult
) : AdamantineEvidenceProvider {
    override fun collect(context: AdamantineEvidenceProviderContext): AdamantineEvidenceProviderResult = result
}

data class AdamantineEvidenceBundle(
    val qid: AdamantineEvidenceProviderResult,
    val shield: AdamantineEvidenceProviderResult,
    val adaptiveCore: AdamantineEvidenceProviderResult
) {
    val complete: Boolean
        get() = listOf(qid, shield, adaptiveCore).all { it.present && it.valid }

    fun toRuntimeEvidenceMap(): Map<String, Any?> = mapOf(
        AdamantineEvidenceSource.QID.wireName to qid.asSummaryMap(),
        AdamantineEvidenceSource.SHIELD.wireName to shield.asSummaryMap(),
        AdamantineEvidenceSource.ADAPTIVE_CORE.wireName to adaptiveCore.asSummaryMap()
    )
}

class AdamantineEvidenceCollector(
    private val qidProvider: AdamantineEvidenceProvider = MissingAdamantineEvidenceProvider(AdamantineEvidenceSource.QID),
    private val shieldProvider: AdamantineEvidenceProvider = MissingAdamantineEvidenceProvider(AdamantineEvidenceSource.SHIELD),
    private val adaptiveCoreProvider: AdamantineEvidenceProvider = MissingAdamantineEvidenceProvider(AdamantineEvidenceSource.ADAPTIVE_CORE)
) {
    fun collect(context: AdamantineEvidenceProviderContext): AdamantineEvidenceBundle =
        AdamantineEvidenceBundle(
            qid = collectOne(AdamantineEvidenceSource.QID, qidProvider, context),
            shield = collectOne(AdamantineEvidenceSource.SHIELD, shieldProvider, context),
            adaptiveCore = collectOne(AdamantineEvidenceSource.ADAPTIVE_CORE, adaptiveCoreProvider, context)
        )

    private fun collectOne(
        expectedSource: AdamantineEvidenceSource,
        provider: AdamantineEvidenceProvider,
        context: AdamantineEvidenceProviderContext
    ): AdamantineEvidenceProviderResult {
        val result = try {
            provider.collect(context)
        } catch (_: Throwable) {
            return AdamantineEvidenceProviderResult.invalid(
                source = expectedSource,
                reasonId = REASON_ADAMANTINEOS_EVIDENCE_UNAVAILABLE
            )
        }

        return AdamantineEvidenceProviderResultValidator.validate(result, expectedSource)
    }
}

object AdamantineEvidenceProviderResultValidator {
    private val lowercaseHex64 = Regex("^[0-9a-f]{64}$")
    private val reasonIdShape = Regex("^[A-Z][A-Z0-9_]*$")

    fun validate(
        result: AdamantineEvidenceProviderResult,
        expectedSource: AdamantineEvidenceSource
    ): AdamantineEvidenceProviderResult {
        if (result.source != expectedSource) {
            return AdamantineEvidenceProviderResult.invalid(expectedSource)
        }
        if (!reasonIdShape.matches(result.reasonId)) {
            return AdamantineEvidenceProviderResult.invalid(expectedSource)
        }
        if (result.present && result.valid && result.reasonId != REASON_ADAMANTINEOS_EVIDENCE_OK) {
            return AdamantineEvidenceProviderResult.invalid(expectedSource)
        }
        if ((!result.present || !result.valid) && result.reasonId == REASON_ADAMANTINEOS_EVIDENCE_OK) {
            return AdamantineEvidenceProviderResult.invalid(expectedSource)
        }
        if (result.present && result.valid) {
            val hash = result.evidenceHash
                ?: return AdamantineEvidenceProviderResult.invalid(expectedSource)
            if (!lowercaseHex64.matches(hash)) {
                return AdamantineEvidenceProviderResult.invalid(expectedSource)
            }
        }

        for ((key, value) in result.fields) {
            if (key.isBlank() || value.isBlank()) return AdamantineEvidenceProviderResult.invalid(expectedSource)
            if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                return AdamantineEvidenceProviderResult.invalid(expectedSource)
            }
            if (value.contains('\n') || value.contains('\r') || value.contains('\u0000')) {
                return AdamantineEvidenceProviderResult.invalid(expectedSource)
            }
        }

        return result.copy(fields = result.fields.toSortedMap())
    }
}

const val REASON_ADAMANTINEOS_EVIDENCE_OK = "EVIDENCE_OK"
const val REASON_ADAMANTINEOS_QID_EVIDENCE_MISSING = "EQC_MISSING_QID_SESSION"
const val REASON_ADAMANTINEOS_SHIELD_EVIDENCE_MISSING = "EQC_MISSING_SHIELD_BUNDLE"
const val REASON_ADAMANTINEOS_ADAPTIVE_EVIDENCE_MISSING = "EQC_MISSING_RISK_REPORT"
const val REASON_ADAMANTINEOS_EVIDENCE_INVALID = "DENY_ADAPTER_INVALID"
const val REASON_ADAMANTINEOS_EVIDENCE_UNAVAILABLE = "DENY_ADAPTER_UNAVAILABLE"
