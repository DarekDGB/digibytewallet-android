package io.digibyte.core.security.adamantine

/**
 * Send-flow gate for AdamantineOS wallet-action decisions.
 *
 * This gate is intentionally placed before native create/sign/broadcast wiring.
 * It only receives safe transaction metadata and never receives seed phrases,
 * private keys, signatures, unsigned transactions, signed transactions, raw
 * transactions, serialized transactions, or native wallet memory.
 */
data class AdamantineSendTransactionGateInput(
    val toAddress: String,
    val amountSatoshis: Long,
    val feePerKb: Long,
    val selectedInputCount: Int,
    val selectedInputTotalSatoshis: Long,
    val estimatedFeeSatoshis: Long,
    val changeSatoshis: Long,
    val availableUtxoCount: Int,
    val assetUtxoCount: Int
)

data class AdamantineSendTransactionGateContext(
    val walletId: String,
    val deviceId: String,
    val sessionId: String,
    val actionNonce: String,
    val network: String = ADAMANTINE_DEFAULT_NETWORK,
    val appId: String = ADAMANTINE_DEFAULT_APP_ID
)

fun interface AdamantineSendTransactionContextProvider {
    /**
     * Returns runtime-safe identity/session metadata for the send gate.
     *
     * Returning null means the AdamantineOS send gate is not configured for this
     * wallet instance yet, so the current PR remains optional and does not change
     * existing wallet execution unless a maintainer wires a context provider.
     */
    fun contextForSend(input: AdamantineSendTransactionGateInput): AdamantineSendTransactionGateContext?
}

sealed class AdamantineSendTransactionGateResult {
    data class Allow(
        val reasonId: String,
        val request: AdamantineWalletActionRequest? = null,
        val decision: AdamantineDecision? = null,
        val configured: Boolean = true
    ) : AdamantineSendTransactionGateResult()

    data class Deny(
        val reasonId: String,
        val request: AdamantineWalletActionRequest? = null,
        val decision: AdamantineDecision? = null
    ) : AdamantineSendTransactionGateResult()

    data class RequireHumanConfirmation(
        val reasonId: String,
        val request: AdamantineWalletActionRequest,
        val decision: AdamantineDecision
    ) : AdamantineSendTransactionGateResult()
}

class AdamantineSendTransactionGate(
    private val boundary: AdamantineWalletDecisionBoundary,
    private val contextProvider: AdamantineSendTransactionContextProvider?
) {
    companion object {
        /**
         * Safe optional default for the current PR stack.
         *
         * The boundary is not invoked unless a maintainer supplies a context
         * provider. This keeps existing wallet send behaviour unchanged while the
         * branch introduces the reviewable send-flow gate structure.
         */
        fun notConfigured(): AdamantineSendTransactionGate = AdamantineSendTransactionGate(
            boundary = DisabledAdamantineWalletDecisionBoundary,
            contextProvider = null
        )
    }

    fun evaluate(input: AdamantineSendTransactionGateInput): AdamantineSendTransactionGateResult {
        val context = contextProvider?.contextForSend(input)
            ?: return AdamantineSendTransactionGateResult.Allow(
                reasonId = REASON_ADAMANTINEOS_SEND_GATE_NOT_CONFIGURED,
                configured = false
            )

        val buildResult = AdamantineWalletActionRequestBuilder.buildSendTransactionRequest(
            AdamantineSendTransactionActionInput(
                walletId = context.walletId,
                deviceId = context.deviceId,
                sessionId = context.sessionId,
                toAddress = input.toAddress,
                amountSatoshis = input.amountSatoshis,
                feePerKb = input.feePerKb,
                selectedInputCount = input.selectedInputCount,
                selectedInputTotalSatoshis = input.selectedInputTotalSatoshis,
                estimatedFeeSatoshis = input.estimatedFeeSatoshis,
                changeSatoshis = input.changeSatoshis,
                availableUtxoCount = input.availableUtxoCount,
                assetUtxoCount = input.assetUtxoCount,
                network = context.network,
                appId = context.appId,
                actionNonce = context.actionNonce
            )
        )

        val request = buildResult.request
        if (request == null) {
            return AdamantineSendTransactionGateResult.Deny(
                reasonId = buildResult.denyDecision?.reasonId ?: REASON_ADAMANTINEOS_REQUEST_INVALID,
                decision = buildResult.denyDecision
            )
        }

        val decision = try {
            boundary.evaluate(request)
        } catch (_: Throwable) {
            AdamantineDecision.deny(REASON_ADAMANTINEOS_SEND_GATE_BOUNDARY_ERROR)
        }

        return when (decision.status) {
            AdamantineDecisionStatus.ALLOW -> AdamantineSendTransactionGateResult.Allow(
                reasonId = decision.reasonId,
                request = request,
                decision = decision
            )

            AdamantineDecisionStatus.DENY -> AdamantineSendTransactionGateResult.Deny(
                reasonId = decision.reasonId,
                request = request,
                decision = decision
            )

            AdamantineDecisionStatus.REQUIRE_HUMAN_CONFIRMATION ->
                AdamantineSendTransactionGateResult.RequireHumanConfirmation(
                    reasonId = decision.reasonId,
                    request = request,
                    decision = decision
                )
        }
    }
}

const val REASON_ADAMANTINEOS_SEND_GATE_NOT_CONFIGURED = "ADAMANTINEOS_SEND_GATE_NOT_CONFIGURED"
const val REASON_ADAMANTINEOS_SEND_GATE_BOUNDARY_ERROR = "DENY_ADAMANTINEOS_SEND_GATE_BOUNDARY_ERROR"
