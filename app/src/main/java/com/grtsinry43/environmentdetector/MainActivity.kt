package com.grtsinry43.environmentdetector

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import com.grtsinry43.environmentdetector.ui.DetectionScreen
import com.grtsinry43.environmentdetector.ui.DetectionViewModel
import com.grtsinry43.environmentdetector.ui.theme.EnvironmentDetectorTheme

class MainActivity : ComponentActivity() {

    private val viewModel: DetectionViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            EnvironmentDetectorTheme {
                val uiState by viewModel.uiState.collectAsState()

                DetectionScreen(
                    uiState = uiState,
                    onFullDetectionClick = { viewModel.startFullDetection() },
                    onQuickDetectionClick = { viewModel.startQuickDetection() },
                    onReset = { viewModel.reset() },
                    modifier = Modifier.fillMaxSize()
                )
            }
        }
    }
}