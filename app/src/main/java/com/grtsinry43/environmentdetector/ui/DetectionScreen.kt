package com.grtsinry43.environmentdetector.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.grtsinry43.environmentdetector.security.DetectionItem
import com.grtsinry43.environmentdetector.security.DetectionResult
import com.grtsinry43.environmentdetector.security.DetectionType
import java.text.SimpleDateFormat
import java.util.*

/**
 * Main detection screen with Material Design 3
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetectionScreen(
    uiState: DetectionUiState,
    onFullDetectionClick: () -> Unit,
    onQuickDetectionClick: () -> Unit,
    onReset: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Environment Detector") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        },
        modifier = modifier
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            when (uiState) {
                is DetectionUiState.Idle -> IdleContent(
                    onFullDetectionClick = onFullDetectionClick,
                    onQuickDetectionClick = onQuickDetectionClick
                )
                is DetectionUiState.Loading -> LoadingContent()
                is DetectionUiState.Success -> ResultContent(
                    result = uiState.result,
                    onReset = onReset
                )
                is DetectionUiState.Error -> ErrorContent(
                    message = uiState.message,
                    onReset = onReset
                )
            }
        }
    }
}

/**
 * Idle state - showing detection buttons
 */
@Composable
private fun IdleContent(
    onFullDetectionClick: () -> Unit,
    onQuickDetectionClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Header icon with animation
        val infiniteTransition = rememberInfiniteTransition(label = "pulse")
        val scale by infiniteTransition.animateFloat(
            initialValue = 1f,
            targetValue = 1.1f,
            animationSpec = infiniteRepeatable(
                animation = tween(1000, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "scale"
        )

        Icon(
            imageVector = Icons.Default.Security,
            contentDescription = null,
            modifier = Modifier
                .size(120.dp)
                .scale(scale),
            tint = MaterialTheme.colorScheme.primary
        )

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "Security Environment Detector",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurface
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Detect potential security risks in your device environment",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(48.dp))

        // Full Detection Button
        FilledTonalButton(
            onClick = onFullDetectionClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer
            )
        ) {
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = null,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = "Full Detection",
                style = MaterialTheme.typography.titleMedium
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Quick Detection Button
        OutlinedButton(
            onClick = onQuickDetectionClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
        ) {
            Icon(
                imageVector = Icons.Default.FlashOn,
                contentDescription = null,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = "Quick Detection",
                style = MaterialTheme.typography.titleMedium
            )
        }
    }
}

/**
 * Loading state with circular progress
 */
@Composable
private fun LoadingContent() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(64.dp),
            strokeWidth = 6.dp
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Scanning environment...",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onSurface
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "This may take a few seconds",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/**
 * Result content showing detection results
 */
@Composable
private fun ResultContent(
    result: DetectionResult,
    onReset: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        // Results header
        ResultHeader(
            isClean = result.isClean,
            timestamp = result.timestamp,
            detectionTimeMs = result.detectionTimeMs
        )

        // Results list
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(result.detectionItems) { item ->
                DetectionItemCard(item)
            }
        }

        // Bottom action button
        Surface(
            tonalElevation = 3.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Button(
                onClick = onReset,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .height(56.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = null
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Scan Again")
            }
        }
    }
}

/**
 * Result header showing overall status
 */
@Composable
private fun ResultHeader(
    isClean: Boolean,
    timestamp: Long,
    detectionTimeMs: Long
) {
    val backgroundColor = if (isClean) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.errorContainer
    }

    val contentColor = if (isClean) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onErrorContainer
    }

    Surface(
        color = backgroundColor,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = if (isClean) Icons.Default.CheckCircle else Icons.Default.Warning,
                contentDescription = null,
                modifier = Modifier.size(72.dp),
                tint = contentColor
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = if (isClean) "Environment Clean" else "Security Risks Detected",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = contentColor
            )

            Spacer(modifier = Modifier.height(8.dp))

            val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            Text(
                text = "Scanned: ${dateFormat.format(Date(timestamp))}",
                style = MaterialTheme.typography.bodyMedium,
                color = contentColor.copy(alpha = 0.8f)
            )

            Text(
                text = "Duration: ${detectionTimeMs}ms",
                style = MaterialTheme.typography.bodyMedium,
                color = contentColor.copy(alpha = 0.8f)
            )
        }
    }
}

/**
 * Card for individual detection item
 */
@Composable
private fun DetectionItemCard(item: DetectionItem) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (item.isAbnormal) {
                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            }
        ),
        onClick = { if (item.details.isNotEmpty()) expanded = !expanded }
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = getIconForDetectionType(item.type),
                    contentDescription = null,
                    tint = if (item.isAbnormal) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.primary
                    },
                    modifier = Modifier.size(24.dp)
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = item.type.name.replace("_", " "),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )

                    Text(
                        text = item.description,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                // Status badge
                Surface(
                    color = if (item.isAbnormal) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.primary
                    },
                    shape = MaterialTheme.shapes.small
                ) {
                    Text(
                        text = if (item.isAbnormal) "RISK" else "OK",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (item.isAbnormal) {
                            MaterialTheme.colorScheme.onError
                        } else {
                            MaterialTheme.colorScheme.onPrimary
                        },
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            // Expandable details
            AnimatedVisibility(
                visible = expanded && item.details.isNotEmpty(),
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Column(
                    modifier = Modifier.padding(top = 12.dp)
                ) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

                    Text(
                        text = "Details:",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    item.details.forEach { (key, value) ->
                        Row(modifier = Modifier.padding(vertical = 2.dp)) {
                            Text(
                                text = "$key: ",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = value,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * Error content
 */
@Composable
private fun ErrorContent(
    message: String,
    onReset: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Error,
            contentDescription = null,
            modifier = Modifier.size(72.dp),
            tint = MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "Detection Failed",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = message,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = onReset,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
        ) {
            Icon(imageVector = Icons.Default.Refresh, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Try Again")
        }
    }
}

/**
 * Get icon for detection type
 */
private fun getIconForDetectionType(type: DetectionType): ImageVector {
    return when (type) {
        DetectionType.ROOT -> Icons.Default.AdminPanelSettings
        DetectionType.HOOK_XPOSED, DetectionType.HOOK_LSPOSED,
        DetectionType.HOOK_RIRU, DetectionType.HOOK_ZYGISK,
        DetectionType.HOOK_SUBSTRATE, DetectionType.HOOK_FRIDA -> Icons.Default.Extension
        DetectionType.SHIZUKU -> Icons.Default.Settings
        DetectionType.DEVELOPER_OPTIONS, DetectionType.ADB_ENABLED -> Icons.Default.DeveloperMode
        DetectionType.EMULATOR, DetectionType.VIRTUAL_MACHINE -> Icons.Default.PhoneAndroid
        DetectionType.PACKAGE_INSTALLER -> Icons.Default.InstallMobile
        DetectionType.SIGNATURE -> Icons.Default.Verified
        DetectionType.DEBUGGABLE -> Icons.Default.BugReport
        DetectionType.INTEGRITY -> Icons.Default.Security
        DetectionType.ERROR -> Icons.Default.Error
    }
}
