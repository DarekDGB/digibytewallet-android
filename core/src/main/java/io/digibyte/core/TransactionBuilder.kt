package io.digibyte.core

import io.digibyte.core.bridge.NativeBridge
import io.digibyte.core.db.entity.UtxoEntity
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGate
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGateInput
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGateResult

sealed class TxResult {
    data class Success(val txid: String) : TxResult()
    data class Error(val message: String) : TxResult()
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
     * Returns txid on success, error message on failure.
     */
    suspend fun sendTransaction(
        toAddress: String,
        amountSatoshis: Long,
        feePerKb: Long,
        spendableUtxos: List<UtxoEntity>
    ): TxResult {
        // Validate address
        if (!nativeGateway.isValidAddress(toAddress)) {
            return TxResult.Error("Invalid DigiByte address")
        }

        // Validate amount
        if (amountSatoshis <= 0) {
            return TxResult.Error("Amount must be positive")
        }

        // Select coins (asset UTXOs are excluded by CoinSelector)
        val selection = coinSelector.selectCoins(spendableUtxos, amountSatoshis, feePerKb)
            ?: return TxResult.Error("Insufficient balance")

        // AdamantineOS send-flow gate. If configured, this is the last stop
        // before native create/sign/broadcast. It receives only safe metadata,
        // never unsigned tx, signed tx, signatures, seed, or key material.
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
                return TxResult.Error("AdamantineOS denied send: ${gateResult.reasonId}")
            }

            is AdamantineSendTransactionGateResult.RequireHumanConfirmation -> {
                return TxResult.Error("AdamantineOS requires human confirmation: ${gateResult.reasonId}")
            }
        }

        // Create unsigned transaction via C core
        val unsignedTx = nativeGateway.createTransaction(toAddress, amountSatoshis, feePerKb)
            ?: return TxResult.Error("Failed to create transaction")

        // Sign via C core (uses RFC 6979 deterministic nonces)
        val signedTx = nativeGateway.signTransaction(unsignedTx)
            ?: return TxResult.Error("Failed to sign transaction")

        // Broadcast via C core
        val txid = nativeGateway.publishTransaction(signedTx)
            ?: return TxResult.Error("Failed to broadcast transaction")

        // Mark inputs as spent
        for (input in selection.inputs) {
            utxoManager.markSpent(input.txid, input.vout)
        }

        return TxResult.Success(txid)
    }
}
