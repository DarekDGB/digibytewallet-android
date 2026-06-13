package io.digibyte.ui.wallet

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.digibyte.ui.theme.DigiByteAccent
import io.digibyte.ui.theme.DigiByteRed

@Composable
internal fun AdamantineSendProtectionCard(
    sendState: SendState,
    modifier: Modifier = Modifier
) {
    val title: String
    val body: String
    val reasonId: String
    val critical: Boolean

    when (sendState) {
        is SendState.AdamantineDenied -> {
            title = "AdamantineOS blocked this send"
            body = "The transaction was stopped before native create, sign, or broadcast execution."
            reasonId = sendState.reasonId
            critical = true
        }

        is SendState.AdamantineHumanConfirmationRequired -> {
            title = "AdamantineOS requires human confirmation"
            body = "The transaction was stopped before native execution. A later layer must route confirmation back through AdamantineOS before this can continue."
            reasonId = sendState.reasonId
            critical = false
        }

        else -> return
    }

    val accent = if (critical) DigiByteRed else DigiByteAccent

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = accent.copy(alpha = 0.10f)
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                color = accent,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "Reason: $reasonId",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}
