package io.digibyte.core.security.adamantine

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AdamantineSensitiveActionWiringTest {
    @Test
    fun `wallet recovery is gated before native recovery`() {
        val source = findSource("core/src/main/java/io/digibyte/core/WalletManager.kt").readText()
        val method = source.substringBetween("fun recoverWallet(", "    /**\n     * Restore wallet")

        assertOrder(
            method,
            "AdamantineSensitiveActionInput.recoverWallet(",
            "NativeBridge.recoverWallet(mnemonic, creationTimestamp)",
            "WalletManager.recoverWallet must evaluate AdamantineOS before NativeBridge.recoverWallet"
        )
        assertTrue(
            "Recovery gate must pass only word count metadata, not the mnemonic body",
            method.contains("mnemonic.safeRecoveryWordCount()")
        )
    }

    @Test
    fun `wallet wipe is gated before native lock and destructive deletion`() {
        val source = findSource("core/src/main/java/io/digibyte/core/WalletManager.kt").readText()
        val method = source.substringBetween("suspend fun wipeWallet()", "    // ── Seed persistence")

        assertOrder(
            method,
            "AdamantineSensitiveActionInput.wipeWallet()",
            "NativeBridge.lockSession()",
            "WalletManager.wipeWallet must evaluate AdamantineOS before native lock and destructive deletion"
        )
        assertOrder(
            method,
            "AdamantineSensitiveActionInput.wipeWallet()",
            "prefs.edit().clear().commit()",
            "WalletManager.wipeWallet must evaluate AdamantineOS before seed ciphertext deletion"
        )
    }

    @Test
    fun `Digi-ID signing is gated before native signMessage`() {
        val source = findSource("core/src/main/java/io/digibyte/core/digiid/DigiIdManager.kt").readText()

        assertOrder(
            source,
            "AdamantineSensitiveActionInput.digiIdAuthenticate(",
            "NativeBridge.signMessage(request.rawUri, 0)",
            "DigiIdManager must evaluate AdamantineOS before Digi-ID signing"
        )
        assertTrue(
            "Digi-ID gate must use nonce metadata instead of signature material",
            source.contains("nonce = request.nonce")
        )
    }

    @Test
    fun `chat message signing is gated before native signMessage and websocket send`() {
        val source = findSource("app/src/main/java/io/digibyte/ui/hub/ChatViewModel.kt").readText()
        val method = source.substringBetween("fun sendMessage(content: String)", "    fun sendTypingIndicator()")

        assertOrder(
            method,
            "blockReasonForMessageSigning(",
            "NativeBridge.signMessage(content, 1)",
            "ChatViewModel must evaluate AdamantineOS before chat message signing"
        )
        assertOrder(
            method,
            "blockReasonForMessageSigning(",
            "hubWebSocket.sendMessage",
            "ChatViewModel must evaluate AdamantineOS before sending a signed message"
        )
    }

    @Test
    fun `forum create and reply signing are gated before native signMessage`() {
        val source = findSource("app/src/main/java/io/digibyte/ui/hub/ForumViewModel.kt").readText()

        assertOrder(
            source,
            "purpose = \"hub_forum_create_thread\"",
            "NativeBridge.signMessage(signContent, 1)",
            "ForumViewModel.createThread must evaluate AdamantineOS before signing"
        )
        assertOrder(
            source,
            "purpose = \"hub_forum_reply\"",
            "NativeBridge.signMessage(content, 1)",
            "ForumViewModel.replyToThread must evaluate AdamantineOS before signing"
        )
    }

    @Test
    fun `Hilt module provides the shared sensitive action gate`() {
        val source = findSource("app/src/main/java/io/digibyte/di/AppModule.kt").readText()

        assertTrue(
            "AppModule must provide AdamantineSensitiveActionGate",
            source.contains("fun provideAdamantineSensitiveActionGate(): AdamantineSensitiveActionGate")
        )
        assertTrue(
            "Default PR9 wiring must remain not configured until a maintainer wires runtime context",
            source.contains("AdamantineSensitiveActionGate.notConfigured()")
        )
        assertTrue(
            "WalletManager provider must receive the AdamantineSensitiveActionGate",
            source.contains("WalletManager(context, ksm, um, adamantineSensitiveActionGate)")
        )
        assertTrue(
            "DigiIdManager provider must receive the AdamantineSensitiveActionGate",
            source.contains("DigiIdManager(client, historyDao, digiScopeClient, adamantineSensitiveActionGate)")
        )
    }

    private fun assertOrder(source: String, first: String, second: String, message: String) {
        val firstIndex = source.indexOf(first)
        val secondIndex = source.indexOf(second)
        assertTrue("Missing first marker `$first`: $message", firstIndex >= 0)
        assertTrue("Missing second marker `$second`: $message", secondIndex >= 0)
        assertTrue(message, firstIndex < secondIndex)
    }

    private fun String.substringBetween(startMarker: String, endMarker: String): String {
        val start = indexOf(startMarker)
        val end = indexOf(endMarker, start.coerceAtLeast(0))
        assertTrue("Missing start marker `$startMarker`", start >= 0)
        assertTrue("Missing end marker `$endMarker`", end > start)
        return substring(start, end)
    }

    private fun findSource(path: String): File {
        val candidates = listOf(path, "../$path", "../../$path")
        return candidates.map { File(it) }.firstOrNull { it.exists() }
            ?: candidates.map { File(System.getProperty("user.dir"), it) }.firstOrNull { it.exists() }
            ?: throw IllegalStateException("$path not found")
    }
}
