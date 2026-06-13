package io.digibyte.core.security.adamantine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdamantineExecutionResponseV2ValidatorTest {
    @Test
    fun `valid strict execution response v2 passes`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(metrics = mapOf("gate_count" to 3))
        )

        assertTrue(result.message, result.valid)
    }

    @Test
    fun `unknown top-level field fails closed`() {
        val payload = AdamantineTestPayloads.executionResponseV2() + mapOf("extra" to "nope")

        val result = AdamantineExecutionResponseV2Validator.validate(payload)

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `missing request id fails closed`() {
        val payload = AdamantineTestPayloads.executionResponseV2().toMutableMap()
        payload.remove("request_id")

        val result = AdamantineExecutionResponseV2Validator.validate(payload)

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `uppercase context hash fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(contextHash = "A".repeat(64))
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `short context hash fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(contextHash = "a".repeat(63))
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `unknown decision field fails closed`() {
        val payload = AdamantineTestPayloads.executionResponseV2().toMutableMap()
        val decision = (payload["decision"] as Map<*, *>).toMutableMap()
        decision["extra"] = "nope"
        payload["decision"] = decision

        val result = AdamantineExecutionResponseV2Validator.validate(payload)

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `allow status with false allowed fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(status = "allow", reasonId = REASON_OK_ALLOW, allowed = false)
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `deny status with OK_ALLOW reason fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(status = "deny", reasonId = REASON_OK_ALLOW, allowed = false)
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `error status with non ERR reason fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(status = "error", reasonId = "DENY_POLICY", allowed = false)
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `unknown reason id fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(status = "deny", reasonId = "DENY_RANDOM_UNKNOWN", allowed = false)
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `invalid protection mode fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(protectionMode = "god_mode")
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `missing gate fails closed`() {
        val payload = AdamantineTestPayloads.executionResponseV2().toMutableMap()
        val decision = (payload["decision"] as Map<*, *>).toMutableMap()
        val gates = (decision["gates"] as Map<*, *>).toMutableMap()
        gates.remove("wsqk")
        decision["gates"] = gates
        payload["decision"] = decision

        val result = AdamantineExecutionResponseV2Validator.validate(payload)

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `unknown artifact key fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(
                artifacts = mapOf("random_artifact" to "nope")
            )
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `artifact with forbidden wallet material key fails closed`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(
                artifacts = mapOf("evidence" to mapOf("private_key" to "redacted"))
            )
        )

        assertFalse(result.message, result.valid)
    }

    @Test
    fun `metrics must be integer counts only`() {
        val result = AdamantineExecutionResponseV2Validator.validate(
            AdamantineTestPayloads.executionResponseV2(metrics = mapOf("duration_ms" to "100"))
        )

        assertFalse(result.message, result.valid)
    }
}
