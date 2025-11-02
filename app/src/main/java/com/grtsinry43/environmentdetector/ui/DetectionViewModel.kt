package com.grtsinry43.environmentdetector.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.grtsinry43.environmentdetector.security.DetectionResult
import com.grtsinry43.environmentdetector.security.EnvironmentDetector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for managing detection state
 */
class DetectionViewModel(application: Application) : AndroidViewModel(application) {

    private val detector = EnvironmentDetector.getInstance(application)

    private val _uiState = MutableStateFlow<DetectionUiState>(DetectionUiState.Idle)
    val uiState: StateFlow<DetectionUiState> = _uiState.asStateFlow()

    /**
     * Start full detection
     */
    fun startFullDetection() {
        viewModelScope.launch {
            _uiState.value = DetectionUiState.Loading
            try {
                val result = detector.performFullDetection()
                _uiState.value = DetectionUiState.Success(result)
            } catch (e: Exception) {
                _uiState.value = DetectionUiState.Error(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Start quick detection
     */
    fun startQuickDetection() {
        viewModelScope.launch {
            _uiState.value = DetectionUiState.Loading
            try {
                val result = detector.performQuickDetection()
                _uiState.value = DetectionUiState.Success(result)
            } catch (e: Exception) {
                _uiState.value = DetectionUiState.Error(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Reset to idle state
     */
    fun reset() {
        _uiState.value = DetectionUiState.Idle
    }
}

/**
 * UI State for detection screen
 */
sealed class DetectionUiState {
    object Idle : DetectionUiState()
    object Loading : DetectionUiState()
    data class Success(val result: DetectionResult) : DetectionUiState()
    data class Error(val message: String) : DetectionUiState()
}
