package io.digibyte.core

import io.digibyte.core.bridge.NativeBridge
import io.digibyte.core.db.entity.UtxoEntity
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGate
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGateInput
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGateResult

sealed class TxResult {
    data class Success(val txid: String) : TxResult()
    data class Error(val message: String) : TxResult()

    data class AdamantineDenied(
        val reasonId: String,
        val message: String = "AdamantineOS denied send: $reasonId"
    ) : TxResult()

    data class AdamantineHumanConfirmationRequired(
        val reasonId: String,
        val message: String = "AdamantineOS requires human confirmation: $reasonId"
    ) : TxResult()
}

interface TransactionNativeGateway {
    fun isValidAddress(address: String): Boolean
    fun createTransaction(toAddress: String, amountSatoshis: Long, feePerKb: Long): ByteArray?
    fun signTransaction(unsignedTx: ByteArray): ByteArray?
    fun publishTransaction(signedTx: ByteArray): String?
}

object NativeBridgeTransactionNativeGateway : TransactionNativeGateway {
    override fun isValidAddress(address: String): Boolean = NativeBridge.isValidAddress(address)

    override fun createTransaction(
        toAddress: String,
        amountSatoshis: Long,
        feePerKb: Long
    ): ByteArray? = NativeBridge.createTransaction(toAddress, amountSatoshis, feePerKb)

    override fun signTransaction(unsignedTx: ByteArray): ByteArray? = NativeBridge.signTransaction(unsignedTx)

    override fun publishTransaction(signedTx: ByteArray): String? = NativeBridge.publishTransaction(signedTx)
}

class TransactionBuilder(
    private val coinSelector: CoinSelector,
    private val utxoManager: UtxoManager,
    private val nativeGateway: TransactionNativeGateway = NativeBridgeTransactionNativeGateway,
    private val adamantineSendGate: AdamantineSendTransactionGate = AdamantineSendTransactionGate.notConfigured()
) {
    /**
     * Build, sign, and broadcast a transaction.
     *
     * AdamantineOS DENY / REQUIRE_HUMAN_CONFIRMATION states are returned as
     * explicit domain states, not plain generic errors, so UI can show a clear
     * protection state without adding a bypass path.
     */
    suspend fun sendTransaction(
        toAddress: String,
        amountSatoshis: Long,
        feePerKb: Long,
        spendableUtxos: List<UtxoEntity>
    ): TxResult {
        if (!nativeGateway.isValidAddress(toAddress)) {
            return TxResult.Error("Invalid DigiByte address")
        }

        if (amountSatoshis <= 0) {
            return TxResult.Error("Amount must be positive")
        }

        val selection = coinSelector.selectCoins(spendableUtxos, amountSatoshis, feePerKb)
            ?: return TxResult.Error("Insufficient balance")

        val gateResult = adamantineSendGate.evaluate(
            AdamantineSendTransactionGateInput(
                toAddress = toAddress,
                amountSatoshis = amountSatoshis,
                feePerKb = feePerKb,
                selectedInputCount = selection.inputs.size,
                selectedInputTotalSatoshis = selection.inputs.sumOf { it.satoshis },
                estimatedFeeSatoshis = selection.fee,
                changeSatoshis = selection.change,
                availableUtxoCount = spendableUtxos.count { !it.isAsset && !it.spent },
                assetUtxoCount = spendableUtxos.count { it.isAsset && !it.spent }
            )
        )

        when (gateResult) {
            is AdamantineSendTransactionGateResult.Allow -> Unit

            is AdamantineSendTransactionGateResult.Deny -> {
                return TxResult.AdamantineDenied(gateResult.reasonId)
            }

            is AdamantineSendTransactionGateResult.RequireHumanConfirmation -> {
                return TxResult.AdamantineHumanConfirmationRequired(gateResult.reasonId)
            }
        }

        val unsignedTx = nativeGateway.createTransaction(toAddress, amountSatoshis, feePerKb)
            ?: return TxResult.Error("Failed to create transaction")

        val signedTx = nativeGateway.signTransaction(unsignedTx)
            ?: return TxResult.Error("Failed to sign transaction")

        val txid = nativeGateway.publishTransaction(signedTx)
            ?: return TxResult.Error("Failed to broadcast transaction")

        for (input in selection.inputs) {
            utxoManager.markSpent(input.txid, input.vout)
        }

        return TxResult.Success(txid)
    }
}
