package io.digibyte.core

import io.digibyte.core.db.dao.AssetBalance
import io.digibyte.core.db.dao.UtxoDao
import io.digibyte.core.db.entity.UtxoEntity
import io.digibyte.core.security.adamantine.AdamantineDecision
import io.digibyte.core.security.adamantine.AdamantineSendTransactionContextProvider
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGate
import io.digibyte.core.security.adamantine.AdamantineSendTransactionGateContext
import io.digibyte.core.security.adamantine.AdamantineWalletDecisionBoundary
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransactionBuilderAdamantineSendGateTest {
    private fun utxo(
        txid: String,
        satoshis: Long,
        isAsset: Boolean = false,
        spent: Boolean = false
    ): UtxoEntity = UtxoEntity(
        txid = txid,
        vout = 0,
        scriptPubKey = byteArrayOf(),
        satoshis = satoshis,
        blockHeight = 1000,
        isAsset = isAsset,
        spent = spent
    )

    private fun contextProvider(): AdamantineSendTransactionContextProvider =
        AdamantineSendTransactionContextProvider {
            AdamantineSendTransactionGateContext(
                walletId = "wallet-builder-test",
                deviceId = "device-builder-test",
                sessionId = "session-builder-test",
                actionNonce = "nonce-builder-test"
            )
        }

    @Test
    fun `not configured AdamantineOS gate preserves existing send flow`() = runTest {
        val native = FakeNativeGateway()
        val dao = FakeUtxoDao()
        val builder = TransactionBuilder(
            coinSelector = CoinSelector(),
            utxoManager = UtxoManager(dao),
            nativeGateway = native,
            adamantineSendGate = AdamantineSendTransactionGate.notConfigured()
        )

        val result = builder.sendTransaction(
            toAddress = "DValidAddressForUnitTestOnly",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            spendableUtxos = listOf(utxo("tx1", 150_000L))
        )

        assertTrue(result is TxResult.Success)
        assertEquals(1, native.createCalls)
        assertEquals(1, native.signCalls)
        assertEquals(1, native.publishCalls)
        assertEquals(listOf("tx1:0"), dao.markSpentCalls)
    }

    @Test
    fun `allow decision reaches native create sign broadcast`() = runTest {
        val native = FakeNativeGateway()
        val dao = FakeUtxoDao()
        val builder = TransactionBuilder(
            coinSelector = CoinSelector(),
            utxoManager = UtxoManager(dao),
            nativeGateway = native,
            adamantineSendGate = AdamantineSendTransactionGate(
                boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.allow() },
                contextProvider = contextProvider()
            )
        )

        val result = builder.sendTransaction(
            toAddress = "DValidAddressForUnitTestOnly",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            spendableUtxos = listOf(utxo("tx1", 150_000L))
        )

        assertTrue(result is TxResult.Success)
        assertEquals(1, native.createCalls)
        assertEquals(1, native.signCalls)
        assertEquals(1, native.publishCalls)
        assertEquals(listOf("tx1:0"), dao.markSpentCalls)
    }

    @Test
    fun `deny decision returns Adamantine denied state and stops before native create sign broadcast`() = runTest {
        val native = FakeNativeGateway()
        val dao = FakeUtxoDao()
        val builder = TransactionBuilder(
            coinSelector = CoinSelector(),
            utxoManager = UtxoManager(dao),
            nativeGateway = native,
            adamantineSendGate = AdamantineSendTransactionGate(
                boundary = AdamantineWalletDecisionBoundary { AdamantineDecision.deny("DENY_POLICY") },
                contextProvider = contextProvider()
            )
        )

        val result = builder.sendTransaction(
            toAddress = "DValidAddressForUnitTestOnly",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            spendableUtxos = listOf(utxo("tx1", 150_000L))
        )

        assertTrue(result is TxResult.AdamantineDenied)
        assertEquals("DENY_POLICY", (result as TxResult.AdamantineDenied).reasonId)
        assertEquals(0, native.createCalls)
        assertEquals(0, native.signCalls)
        assertEquals(0, native.publishCalls)
        assertTrue(dao.markSpentCalls.isEmpty())
    }

    @Test
    fun `human confirmation decision returns review state and stops before native create sign broadcast`() = runTest {
        val native = FakeNativeGateway()
        val dao = FakeUtxoDao()
        val builder = TransactionBuilder(
            coinSelector = CoinSelector(),
            utxoManager = UtxoManager(dao),
            nativeGateway = native,
            adamantineSendGate = AdamantineSendTransactionGate(
                boundary = AdamantineWalletDecisionBoundary {
                    AdamantineDecision.requireHumanConfirmation("DENY_POLICY")
                },
                contextProvider = contextProvider()
            )
        )

        val result = builder.sendTransaction(
            toAddress = "DValidAddressForUnitTestOnly",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            spendableUtxos = listOf(utxo("tx1", 150_000L))
        )

        assertTrue(result is TxResult.AdamantineHumanConfirmationRequired)
        assertEquals(
            "DENY_POLICY",
            (result as TxResult.AdamantineHumanConfirmationRequired).reasonId
        )
        assertEquals(0, native.createCalls)
        assertEquals(0, native.signCalls)
        assertEquals(0, native.publishCalls)
        assertTrue(dao.markSpentCalls.isEmpty())
    }

    @Test
    fun `invalid address stops before coin selection gate and native create`() = runTest {
        val native = FakeNativeGateway(validAddress = false)
        val dao = FakeUtxoDao()
        val boundaryInvoked = mutableListOf<Boolean>()
        val builder = TransactionBuilder(
            coinSelector = CoinSelector(),
            utxoManager = UtxoManager(dao),
            nativeGateway = native,
            adamantineSendGate = AdamantineSendTransactionGate(
                boundary = AdamantineWalletDecisionBoundary {
                    boundaryInvoked += true
                    AdamantineDecision.allow()
                },
                contextProvider = contextProvider()
            )
        )

        val result = builder.sendTransaction(
            toAddress = "invalid",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            spendableUtxos = listOf(utxo("tx1", 150_000L))
        )

        assertTrue(result is TxResult.Error)
        assertEquals(0, native.createCalls)
        assertTrue(boundaryInvoked.isEmpty())
        assertTrue(dao.markSpentCalls.isEmpty())
    }

    @Test
    fun `asset utxos are not selected and gate receives only selected non asset counts`() = runTest {
        val native = FakeNativeGateway()
        val dao = FakeUtxoDao()
        val observedSelectedCounts = mutableListOf<String>()
        val builder = TransactionBuilder(
            coinSelector = CoinSelector(),
            utxoManager = UtxoManager(dao),
            nativeGateway = native,
            adamantineSendGate = AdamantineSendTransactionGate(
                boundary = AdamantineWalletDecisionBoundary { request ->
                    observedSelectedCounts += listOf(
                        request.fields["selected_input_count"],
                        request.fields["asset_utxo_count"]
                    ).joinToString(":")
                    AdamantineDecision.allow()
                },
                contextProvider = contextProvider()
            )
        )

        val result = builder.sendTransaction(
            toAddress = "DValidAddressForUnitTestOnly",
            amountSatoshis = 100_000L,
            feePerKb = 1_000L,
            spendableUtxos = listOf(
                utxo("asset1", 1_000_000L, isAsset = true),
                utxo("tx1", 150_000L)
            )
        )

        assertTrue(result is TxResult.Success)
        assertEquals(listOf("1:1"), observedSelectedCounts)
        assertEquals(listOf("tx1:0"), dao.markSpentCalls)
        assertFalse(dao.markSpentCalls.contains("asset1:0"))
    }

    private class FakeNativeGateway(
        private val validAddress: Boolean = true,
        private val createResult: ByteArray? = byteArrayOf(1, 2, 3),
        private val signResult: ByteArray? = byteArrayOf(4, 5, 6),
        private val publishResult: String? = "fake-txid"
    ) : TransactionNativeGateway {
        var createCalls: Int = 0
        var signCalls: Int = 0
        var publishCalls: Int = 0

        override fun isValidAddress(address: String): Boolean = validAddress

        override fun createTransaction(
            toAddress: String,
            amountSatoshis: Long,
            feePerKb: Long
        ): ByteArray? {
            createCalls += 1
            return createResult
        }

        override fun signTransaction(unsignedTx: ByteArray): ByteArray? {
            signCalls += 1
            return signResult
        }

        override fun publishTransaction(signedTx: ByteArray): String? {
            publishCalls += 1
            return publishResult
        }
    }

    private class FakeUtxoDao : UtxoDao {
        val markSpentCalls = mutableListOf<String>()

        override fun getSpendableDigiByteUtxos(): Flow<List<UtxoEntity>> = flowOf(emptyList())
        override fun getAssetUtxos(): Flow<List<UtxoEntity>> = flowOf(emptyList())
        override fun getDigiByteBalance(): Flow<Long> = flowOf(0L)
        override suspend fun insertAll(utxos: List<UtxoEntity>) = Unit

        override suspend fun markSpent(txid: String, vout: Int) {
            markSpentCalls += "$txid:$vout"
        }

        override suspend fun deleteAll() = Unit
        override fun getAssetBalances(): Flow<List<AssetBalance>> = flowOf(emptyList())
    }
}
