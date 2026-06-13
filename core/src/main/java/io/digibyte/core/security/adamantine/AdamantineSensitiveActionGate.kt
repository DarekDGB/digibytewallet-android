package io.digibyte.core.security.adamantine

import java.security.MessageDigest

/**
 * Generic AdamantineOS gate for sensitive wallet actions beyond transaction send.
 *
 * This gate carries only safe metadata. It must never receive seed phrases,
 * mnemonics, private keys, signatures, raw transactions, serialized
 * transactions, PINs, passwords, auth tokens, or native wallet memory.
 */
data class AdamantineSensitiveActionGateContext(
    val walletId: String,
    val deviceId: String,
    val sessionId: String,
    val actionNonce: String,
    val network: String = ADAMANTINE_DEFAULT_NETWORK,
    val appId: String = ADAMANTINE_DEFAULT_APP_ID
)

fun interface AdamantineSensitiveActionContextProvider {
    fun contextFor(action: AdamantineSensitiveActionInput): AdamantineSensitiveActionGateContext?
}

data class AdamantineSensitiveActionInput(
    val action: String,
    val intent: String,
    val purpose: String,
    val safeFields: Map<String, String> = emptyMap()
) {
    companion object {
        fun wipeWallet(reason: String = "user_requested_wipe"): AdamantineSensitiveActionInput =
            AdamantineSensitiveActionInput(
                action = ADAMANTINE_ACTION_WIPE_WALLET,
                intent = ADAMANTINE_INTENT_WALLET_ADMIN,
                purpose = reason,
                safeFields = mapOf(
                    "destructive" to "true",
                    "requires_user_confirmation" to "true"
                )
            )

        fun recoverWallet(
            creationTimestamp: Long,
            mnemonicWordCount: Int
        ): AdamantineSensitiveActionInput =
            AdamantineSensitiveActionInput(
                action = ADAMANTINE_ACTION_RECOVER_WALLET,
                intent = ADAMANTINE_INTENT_WALLET_RECOVERY,
                purpose = "recover_wallet_from_mnemonic",
                safeFields = mapOf(
                    "creation_timestamp" to creationTimestamp.toString(),
                    "recovery_word_count" to mnemonicWordCount.toString()
                )
            )

        fun digiIdAuthenticate(
            domain: String,
            callbackHost: String,
            nonce: String,
            isUnsecure: Boolean
        ): AdamantineSensitiveActionInput = AdamantineSensitiveActionInput(
            action = ADAMANTINE_ACTION_DIGIID_AUTHENTICATE,
            intent = ADAMANTINE_INTENT_IDENTITY_AUTH,
            purpose = "digiid_authenticate",
            safeFields = mapOf(
                "domain" to domain,
                "callback_host" to callbackHost,
                "nonce_hash" to sha256Hex(nonce),
                "is_unsecure" to isUnsecure.toString()
            )
        )

        fun messageSigning(
            message: String,
            purpose: String,
            addressFormat: Int
        ): AdamantineSensitiveActionInput = AdamantineSensitiveActionInput(
            action = ADAMANTINE_ACTION_SIGN_MESSAGE,
            intent = ADAMANTINE_INTENT_MESSAGE_SIGNING,
            purpose = purpose,
            safeFields = mapOf(
                "message_hash" to sha256Hex(message),
                "message_length" to message.length.toString(),
                "address_format" to addressFormat.toString()
            )
        )

        private fun sha256Hex(value: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
            return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }
        }
    }
}

sealed class AdamantineSensitiveActionGateResult {
    data class Allow(
        val reasonId: String,
        val request: AdamantineWalletActionRequest? = null,
        val decision: AdamantineDecision? = null,
        val configured: Boolean = true
    ) : AdamantineSensitiveActionGateResult()

    data class Deny(
        val reasonId: String,
        val request: AdamantineWalletActionRequest? = null,
        val decision: AdamantineDecision? = null
    ) : AdamantineSensitiveActionGateResult()

    data class RequireHumanConfirmation(
        val reasonId: String,
        val request: AdamantineWalletActionRequest,
        val decision: AdamantineDecision
    ) : AdamantineSensitiveActionGateResult()
}

class AdamantineSensitiveActionGate(
    private val boundary: AdamantineWalletDecisionBoundary,
    private val contextProvider: AdamantineSensitiveActionContextProvider?
) {
    companion object {
        fun notConfigured(): AdamantineSensitiveActionGate = AdamantineSensitiveActionGate(
            boundary = DisabledAdamantineWalletDecisionBoundary,
            contextProvider = null
        )
    }

    fun evaluate(input: AdamantineSensitiveActionInput): AdamantineSensitiveActionGateResult {
        validateInput(input)?.let {
            return AdamantineSensitiveActionGateResult.Deny(reasonId = it)
        }

        val context = contextProvider?.contextFor(input)
            ?: return AdamantineSensitiveActionGateResult.Allow(
                reasonId = REASON_ADAMANTINEOS_SENSITIVE_GATE_NOT_CONFIGURED,
                configured = false
            )

        val request = buildRequest(input, context)

        AdamantineWalletAdapterInvariants.validate(request)?.let {
            return AdamantineSensitiveActionGateResult.Deny(reasonId = it.reasonId, decision = it)
        }

        AdamantineSensitiveActionFieldAllowlist.validate(request)?.let {
            return AdamantineSensitiveActionGateResult.Deny(
                reasonId = it.reasonId,
                request = request,
                decision = it
            )
        }

        val decision = try {
            boundary.evaluate(request)
        } catch (_: Throwable) {
            AdamantineDecision.deny(REASON_ADAMANTINEOS_SENSITIVE_GATE_BOUNDARY_ERROR)
        }

        return when (decision.status) {
            AdamantineDecisionStatus.ALLOW -> AdamantineSensitiveActionGateResult.Allow(
                reasonId = decision.reasonId,
                request = request,
                decision = decision
            )

            AdamantineDecisionStatus.DENY -> AdamantineSensitiveActionGateResult.Deny(
                reasonId = decision.reasonId,
                request = request,
                decision = decision
            )

            AdamantineDecisionStatus.REQUIRE_HUMAN_CONFIRMATION ->
                AdamantineSensitiveActionGateResult.RequireHumanConfirmation(
                    reasonId = decision.reasonId,
                    request = request,
                    decision = decision
                )
        }
    }

    private fun buildRequest(
        input: AdamantineSensitiveActionInput,
        context: AdamantineSensitiveActionGateContext
    ): AdamantineWalletActionRequest {
        val deterministicFields = (input.safeFields + mapOf(
            "action_nonce" to context.actionNonce,
            "action_version" to ADAMANTINE_SENSITIVE_ACTION_REQUEST_VERSION,
            "app_id" to context.appId,
            "device_id" to context.deviceId,
            "native_execution_position" to nativeExecutionPosition(input.action),
            "network" to context.network,
            "purpose" to input.purpose,
            "session_id" to context.sessionId,
            "wallet_id" to context.walletId
        )).toSortedMap()

        val requestId = AdamantineWalletActionCanonicalizer.sha256Hex(
            AdamantineWalletActionCanonicalizer.canonicalize(deterministicFields)
        )

        val contextHash = AdamantineWalletActionCanonicalizer.sha256Hex(
            AdamantineWalletActionCanonicalizer.canonicalize(
                deterministicFields + mapOf("request_id" to requestId)
            )
        )

        val fields = (deterministicFields + mapOf(
            "request_id" to requestId,
            "request_context_hash" to contextHash
        )).toSortedMap()

        return AdamantineWalletActionRequest(
            walletId = context.walletId,
            deviceId = context.deviceId,
            appId = context.appId,
            sessionId = context.sessionId,
            action = input.action,
            intent = input.intent,
            fields = fields
        )
    }

    private fun validateInput(input: AdamantineSensitiveActionInput): String? {
        if (input.action !in ADAMANTINE_SENSITIVE_ACTIONS) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.intent.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.purpose.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID

        for ((key, value) in input.safeFields) {
            if (key.isBlank() || value.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
            if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                return REASON_ADAMANTINEOS_FORBIDDEN_WALLET_MATERIAL
            }
            if (value.contains('\n') || value.contains('\r') || value.contains('\u0000')) {
                return REASON_ADAMANTINEOS_REQUEST_INVALID
            }
        }

        return null
    }

    private fun nativeExecutionPosition(action: String): String = when (action) {
        ADAMANTINE_ACTION_WIPE_WALLET -> "before_wallet_wipe"
        ADAMANTINE_ACTION_RECOVER_WALLET -> "before_wallet_recover"
        ADAMANTINE_ACTION_DIGIID_AUTHENTICATE -> "before_digiid_sign_callback"
        ADAMANTINE_ACTION_SIGN_MESSAGE -> "before_message_signing"
        else -> "before_sensitive_execution"
    }
}

object AdamantineSensitiveActionFieldAllowlist {
    private val commonRequiredFields = setOf(
        "action_nonce",
        "action_version",
        "app_id",
        "device_id",
        "native_execution_position",
        "network",
        "purpose",
        "request_context_hash",
        "request_id",
        "session_id",
        "wallet_id"
    )

    private val actionSpecificFields = mapOf(
        ADAMANTINE_ACTION_WIPE_WALLET to setOf("destructive", "requires_user_confirmation"),
        ADAMANTINE_ACTION_RECOVER_WALLET to setOf("creation_timestamp", "recovery_word_count"),
        ADAMANTINE_ACTION_DIGIID_AUTHENTICATE to setOf("callback_host", "domain", "is_unsecure", "nonce_hash"),
        ADAMANTINE_ACTION_SIGN_MESSAGE to setOf("address_format", "message_hash", "message_length")
    )

    private val lowercaseHex64 = Regex("^[0-9a-f]{64}$")

    fun validate(request: AdamantineWalletActionRequest): AdamantineDecision? {
        val specific = actionSpecificFields[request.action]
            ?: return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)

        val required = commonRequiredFields + specific
        val fieldKeys = request.fields.keys

        val missing = required - fieldKeys
        if (missing.isNotEmpty()) return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)

        val unknown = fieldKeys - required
        if (unknown.isNotEmpty()) return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)

        for ((key, value) in request.fields) {
            if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                return AdamantineDecision.deny(REASON_ADAMANTINEOS_FORBIDDEN_WALLET_MATERIAL)
            }
            if (value.isBlank()) return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
            if (value.contains('\n') || value.contains('\r') || value.contains('\u0000')) {
                return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
            }
        }

        if (request.fields["action_version"] != ADAMANTINE_SENSITIVE_ACTION_REQUEST_VERSION) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }
        if (!lowercaseHex64.matches(request.fields["request_id"].orEmpty())) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }
        if (!lowercaseHex64.matches(request.fields["request_context_hash"].orEmpty())) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }
        if (request.action == ADAMANTINE_ACTION_SIGN_MESSAGE &&
            !lowercaseHex64.matches(request.fields["message_hash"].orEmpty())
        ) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }
        if (request.action == ADAMANTINE_ACTION_DIGIID_AUTHENTICATE &&
            !lowercaseHex64.matches(request.fields["nonce_hash"].orEmpty())
        ) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }

        return null
    }
}

const val ADAMANTINE_ACTION_WIPE_WALLET = "wipe_wallet"
const val ADAMANTINE_ACTION_RECOVER_WALLET = "recover_wallet"
const val ADAMANTINE_ACTION_DIGIID_AUTHENTICATE = "digiid_authenticate"
const val ADAMANTINE_ACTION_SIGN_MESSAGE = "sign_message"

const val ADAMANTINE_INTENT_WALLET_ADMIN = "wallet_admin"
const val ADAMANTINE_INTENT_WALLET_RECOVERY = "wallet_recovery"
const val ADAMANTINE_INTENT_IDENTITY_AUTH = "identity_auth"
const val ADAMANTINE_INTENT_MESSAGE_SIGNING = "message_signing"

const val ADAMANTINE_SENSITIVE_ACTION_REQUEST_VERSION = "adamantine_sensitive_action_request_v1"
const val REASON_ADAMANTINEOS_SENSITIVE_GATE_NOT_CONFIGURED = "ADAMANTINEOS_SENSITIVE_GATE_NOT_CONFIGURED"
const val REASON_ADAMANTINEOS_SENSITIVE_GATE_BOUNDARY_ERROR = "DENY_ADAMANTINEOS_SENSITIVE_GATE_BOUNDARY_ERROR"

private val ADAMANTINE_SENSITIVE_ACTIONS = setOf(
    ADAMANTINE_ACTION_WIPE_WALLET,
    ADAMANTINE_ACTION_RECOVER_WALLET,
    ADAMANTINE_ACTION_DIGIID_AUTHENTICATE,
    ADAMANTINE_ACTION_SIGN_MESSAGE
)
