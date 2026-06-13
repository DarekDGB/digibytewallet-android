package io.digibyte.ui.wallet

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import io.digibyte.core.PriceProvider
import io.digibyte.core.TransactionBuilder
import io.digibyte.core.TxResult
import io.digibyte.core.UtxoManager
import io.digibyte.core.bridge.NativeBridge
import io.digibyte.core.model.DigiByteUri
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.Locale
import javax.inject.Inject

sealed class SendState {
    data object Idle : SendState()
    data object Confirming : SendState()
    data object Sending : SendState()
    data class Success(val txid: String) : SendState()
    data class Error(val message: String) : SendState()

    data class AdamantineDenied(
        val reasonId: String,
        val message: String
    ) : SendState()

    data class AdamantineHumanConfirmationRequired(
        val reasonId: String,
        val message: String
    ) : SendState()
}

/** Fee tiers in sat/KB. Used as fallback when native returns 0. */
private val FEE_DEFAULTS = longArrayOf(100_000L, 75_000L, 50_000L)

@HiltViewModel
class SendViewModel @Inject constructor(
    private val transactionBuilder: TransactionBuilder,
    private val utxoManager: UtxoManager,
    private val priceProvider: PriceProvider
) : ViewModel() {

    val address = MutableStateFlow("")

    private val _addressValid = MutableStateFlow<Boolean?>(null)
    val addressValid: StateFlow<Boolean?> = _addressValid.asStateFlow()

    val amountDgb = MutableStateFlow("")

    val amountFiat = MutableStateFlow("")

    val selectedFeeTier = MutableStateFlow(1)

    val feeEstimate: StateFlow<Long> = selectedFeeTier.map { tier ->
        val native = NativeBridge.getEstimatedFee(tier)
        if (native > 0) native else FEE_DEFAULTS[tier]
    }.stateIn(viewModelScope, SharingStarted.Eagerly, FEE_DEFAULTS[1])

    private val _sendState = MutableStateFlow<SendState>(SendState.Idle)
    val sendState: StateFlow<SendState> = _sendState.asStateFlow()

    private val _validationError = MutableStateFlow<String?>(null)
    val validationError: StateFlow<String?> = _validationError.asStateFlow()

    fun onAddressChanged(value: String) {
        address.value = value.trim()
        _addressValid.value = if (value.isBlank()) null
        else NativeBridge.isValidAddress(value.trim())
        _validationError.value = null
    }

    fun onAmountDgbChanged(value: String) {
        amountDgb.value = value
        _validationError.value = null

        viewModelScope.launch {
            val dgb = value.toDoubleOrNull() ?: return@launch
            runCatching {
                val price = priceProvider.fetchPrice()
                val fiat = dgb * price.priceUsd
                amountFiat.value = NumberFormat.getNumberInstance(Locale.US).apply {
                    minimumFractionDigits = 2
                    maximumFractionDigits = 2
                }.format(fiat)
            }
        }
    }

    fun onAmountFiatChanged(value: String) {
        amountFiat.value = value
        _validationError.value = null

        viewModelScope.launch {
            val fiat = value.toDoubleOrNull() ?: return@launch
            runCatching {
                val price = priceProvider.fetchPrice()
                if (price.priceUsd <= 0.0) return@launch
                val dgb = fiat / price.priceUsd
                amountDgb.value = NumberFormat.getNumberInstance(Locale.US).apply {
                    minimumFractionDigits = 2
                    maximumFractionDigits = 8
                }.format(dgb)
            }
        }
    }

    fun applyScannedUri(raw: String) {
        val uri = DigiByteUri.parse(raw) ?: return
        onAddressChanged(uri.address)
        uri.amount?.let { sats ->
            val dgb = sats / 100_000_000.0
            onAmountDgbChanged(
                NumberFormat.getNumberInstance(Locale.US).apply {
                    minimumFractionDigits = 0
                    maximumFractionDigits = 8
                }.format(dgb)
            )
        }
    }

    fun amountSatoshis(): Long? {
        val dgb = amountDgb.value.replace(",", "").toDoubleOrNull() ?: return null
        if (dgb <= 0.0) return null
        return (dgb * 100_000_000).toLong()
    }

    fun requestConfirm() {
        val addr = address.value
        val sats = amountSatoshis()

        if (addr.isBlank() || _addressValid.value != true) {
            _validationError.value = "Enter a valid DigiByte address"
            return
        }
        if (sats == null || sats <= 0) {
            _validationError.value = "Enter a valid amount"
            return
        }

        _sendState.value = SendState.Confirming
    }

    fun cancelConfirm() {
        if (_sendState.value is SendState.Confirming) {
            _sendState.value = SendState.Idle
        }
    }

    fun send() {
        val addr = address.value
        val sats = amountSatoshis() ?: run {
            _sendState.value = SendState.Error("Invalid amount")
            return
        }
        val feePerKb = feeEstimate.value

        _sendState.value = SendState.Sending

        viewModelScope.launch {
            val utxos = utxoManager.getSpendableUtxos().first()
            val result = transactionBuilder.sendTransaction(addr, sats, feePerKb, utxos)
            _sendState.value = when (result) {
                is TxResult.Success -> SendState.Success(result.txid)
                is TxResult.Error -> SendState.Error(result.message)

                is TxResult.AdamantineDenied -> SendState.AdamantineDenied(
                    reasonId = result.reasonId,
                    message = result.message
                )

                is TxResult.AdamantineHumanConfirmationRequired ->
                    SendState.AdamantineHumanConfirmationRequired(
                        reasonId = result.reasonId,
                        message = result.message
                    )
            }
        }
    }

    fun resetState() {
        _sendState.value = SendState.Idle
        _validationError.value = null
    }

    fun feeTierLabel(tier: Int): String = when (tier) {
        0 -> "Next Block"
        1 -> "5 Minutes"
        else -> "Economy"
    }

    fun feeTierSatPerKb(tier: Int): Long {
        val native = NativeBridge.getEstimatedFee(tier)
        return if (native > 0) native else FEE_DEFAULTS[tier]
    }
}
