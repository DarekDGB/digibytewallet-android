package io.digibyte.core.security.adamantine

import java.security.MessageDigest

/**
 * Builds AdamantineOS wallet-action requests from safe wallet metadata only.
 *
 * This builder must never receive seed phrases, mnemonics, private keys,
 * signatures, raw transactions, serialized transactions, or native wallet
 * memory. It prepares deterministic request metadata for a future gate before
 * create/sign/broadcast wiring.
 */
data class AdamantineSendTransactionActionInput(
    val walletId: String,
    val deviceId: String,
    val sessionId: String,
    val toAddress: String,
    val amountSatoshis: Long,
    val feePerKb: Long,
    val selectedInputCount: Int,
    val selectedInputTotalSatoshis: Long,
    val estimatedFeeSatoshis: Long,
    val changeSatoshis: Long,
    val availableUtxoCount: Int,
    val assetUtxoCount: Int = 0,
    val network: String = ADAMANTINE_DEFAULT_NETWORK,
    val appId: String = ADAMANTINE_DEFAULT_APP_ID,
    val actionNonce: String
)

data class AdamantineWalletActionRequestBuildResult(
    val request: AdamantineWalletActionRequest?,
    val denyDecision: AdamantineDecision?
) {
    val built: Boolean
        get() = request != null && denyDecision == null

    companion object {
        fun built(request: AdamantineWalletActionRequest): AdamantineWalletActionRequestBuildResult =
            AdamantineWalletActionRequestBuildResult(request = request, denyDecision = null)

        fun deny(reasonId: String): AdamantineWalletActionRequestBuildResult =
            AdamantineWalletActionRequestBuildResult(
                request = null,
                denyDecision = AdamantineDecision.deny(reasonId)
            )

        fun deny(decision: AdamantineDecision): AdamantineWalletActionRequestBuildResult =
            AdamantineWalletActionRequestBuildResult(request = null, denyDecision = decision)
    }
}

object AdamantineWalletActionRequestBuilder {
    fun buildSendTransactionRequest(
        input: AdamantineSendTransactionActionInput
    ): AdamantineWalletActionRequestBuildResult {
        validateSendTransactionInput(input)?.let { return AdamantineWalletActionRequestBuildResult.deny(it) }

        val deterministicFields = sortedMapOf(
            "action_nonce" to input.actionNonce,
            "action_version" to ADAMANTINE_WALLET_ACTION_REQUEST_VERSION,
            "amount_satoshis" to input.amountSatoshis.toString(),
            "app_id" to input.appId,
            "asset_utxo_count" to input.assetUtxoCount.toString(),
            "available_utxo_count" to input.availableUtxoCount.toString(),
            "change_satoshis" to input.changeSatoshis.toString(),
            "device_id" to input.deviceId,
            "estimated_fee_satoshis" to input.estimatedFeeSatoshis.toString(),
            "fee_per_kb" to input.feePerKb.toString(),
            "native_execution_position" to ADAMANTINE_NATIVE_POSITION_BEFORE_CREATE_SIGN_BROADCAST,
            "network" to input.network,
            "selected_input_count" to input.selectedInputCount.toString(),
            "selected_input_total_satoshis" to input.selectedInputTotalSatoshis.toString(),
            "session_id" to input.sessionId,
            "to_address" to input.toAddress,
            "wallet_id" to input.walletId
        )

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

        val request = AdamantineWalletActionRequest(
            walletId = input.walletId,
            deviceId = input.deviceId,
            appId = input.appId,
            sessionId = input.sessionId,
            action = ADAMANTINE_ACTION_SEND_TRANSACTION,
            intent = ADAMANTINE_INTENT_WALLET_SEND,
            fields = fields
        )

        AdamantineWalletAdapterInvariants.validate(request)?.let {
            return AdamantineWalletActionRequestBuildResult.deny(it)
        }
        AdamantineWalletActionFieldAllowlist.validate(request)?.let {
            return AdamantineWalletActionRequestBuildResult.deny(it)
        }

        return AdamantineWalletActionRequestBuildResult.built(request)
    }

    private fun validateSendTransactionInput(input: AdamantineSendTransactionActionInput): String? {
        if (input.walletId.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.deviceId.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.appId.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.sessionId.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.network.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.actionNonce.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.toAddress.isBlank()) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.toAddress.any { it.isWhitespace() }) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.amountSatoshis <= 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.feePerKb <= 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.selectedInputCount <= 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.availableUtxoCount < input.selectedInputCount) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.assetUtxoCount < 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.selectedInputTotalSatoshis <= 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.estimatedFeeSatoshis < 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.changeSatoshis < 0) return REASON_ADAMANTINEOS_REQUEST_INVALID
        if (input.selectedInputTotalSatoshis < input.amountSatoshis + input.estimatedFeeSatoshis) {
            return REASON_ADAMANTINEOS_REQUEST_INVALID
        }
        if (input.changeSatoshis > input.selectedInputTotalSatoshis) return REASON_ADAMANTINEOS_REQUEST_INVALID
        return null
    }
}

object AdamantineWalletActionFieldAllowlist {
    private val sendTransactionRequiredFields = setOf(
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

    fun validate(request: AdamantineWalletActionRequest): AdamantineDecision? {
        val required = when (request.action) {
            ADAMANTINE_ACTION_SEND_TRANSACTION -> sendTransactionRequiredFields
            else -> return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }

        val fieldKeys = request.fields.keys
        val missing = required - fieldKeys
        if (missing.isNotEmpty()) return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)

        val unknown = fieldKeys - required
        if (unknown.isNotEmpty()) {
            if (unknown.any { AdamantineWalletAdapterInvariants.isForbiddenFieldName(it) }) {
                return AdamantineDecision.deny(REASON_ADAMANTINEOS_FORBIDDEN_WALLET_MATERIAL)
            }
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }

        for ((key, value) in request.fields) {
            if (AdamantineWalletAdapterInvariants.isForbiddenFieldName(key)) {
                return AdamantineDecision.deny(REASON_ADAMANTINEOS_FORBIDDEN_WALLET_MATERIAL)
            }
            if (value.isBlank()) return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
            if (value.contains('\n') || value.contains('\r') || value.contains('\u0000')) {
                return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
            }
        }

        if (request.fields["action_version"] != ADAMANTINE_WALLET_ACTION_REQUEST_VERSION) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }
        if (request.fields["native_execution_position"] != ADAMANTINE_NATIVE_POSITION_BEFORE_CREATE_SIGN_BROADCAST) {
            return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        }

        validateHexField(request, "request_id")?.let { return it }
        validateHexField(request, "request_context_hash")?.let { return it }

        return null
    }

    private fun validateHexField(request: AdamantineWalletActionRequest, field: String): AdamantineDecision? {
        val value = request.fields[field] ?: return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        if (!LOWERCASE_HEX_64.matches(value)) return AdamantineDecision.deny(REASON_ADAMANTINEOS_REQUEST_INVALID)
        return null
    }
}

object AdamantineWalletActionCanonicalizer {
    fun canonicalize(fields: Map<String, String>): String =
        fields.toSortedMap().entries.joinToString(separator = "|") { (key, value) ->
            "${key}=${value}"
        }

    fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString(separator = "") { byte -> "%02x".format(byte) }
    }
}

const val ADAMANTINE_ACTION_SEND_TRANSACTION = "send_transaction"
const val ADAMANTINE_DEFAULT_APP_ID = "io.digibyte"
const val ADAMANTINE_DEFAULT_NETWORK = "mainnet"
const val ADAMANTINE_INTENT_WALLET_SEND = "wallet_send"
const val ADAMANTINE_NATIVE_POSITION_BEFORE_CREATE_SIGN_BROADCAST = "before_create_sign_broadcast"
const val ADAMANTINE_WALLET_ACTION_REQUEST_VERSION = "adamantine_wallet_action_request_v1"

private val LOWERCASE_HEX_64 = Regex("^[0-9a-f]{64}$")
