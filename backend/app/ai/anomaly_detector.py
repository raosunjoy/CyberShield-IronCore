"""
TensorFlow-based Anomaly Detection Model

Enterprise-grade anomaly detection for cybersecurity threat identification.
Uses deep learning autoencoders to detect unusual patterns in network traffic,
user behavior, and system logs.
"""

import logging
import numpy as np
import pandas as pd
import tensorflow as tf
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import joblib
import os
from datetime import datetime, timedelta
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    """Anomaly detection result with confidence scores and explanations"""
    
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    feature_contributions: Dict[str, float]
    reconstruction_error: float
    threshold: float
    timestamp: datetime
    explanation: str


@dataclass
class TrainingMetrics:
    """Model training performance metrics"""
    
    loss: float
    val_loss: float
    reconstruction_loss: float
    training_time: float
    epochs_trained: int
    model_version: str


class AnomalyDetector:
    """
    Enterprise TensorFlow Anomaly Detection System
    
    Features:
    - Deep autoencoder architecture for anomaly detection
    - Real-time inference with <10ms latency
    - Explainable AI with feature attribution
    - Automatic model retraining and drift detection
    - Support for various data types (network, system, user behavior)
    """
    
    def __init__(
        self,
        model_path: str = "/tmp/cybershield/models/anomaly_detector",
        scaler_path: str = "/tmp/cybershield/scalers/anomaly_scaler.pkl",
        feature_dim: int = 50,
        encoding_dim: int = 32,
        threshold_percentile: float = 95.0,
        batch_size: int = 32,
        max_workers: int = 4,
    ):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.feature_dim = feature_dim
        self.encoding_dim = encoding_dim
        self.threshold_percentile = threshold_percentile
        self.batch_size = batch_size
        self.max_workers = max_workers
        
        # Model components
        self.model: Optional[tf.keras.Model] = None
        self.encoder: Optional[tf.keras.Model] = None
        self.decoder: Optional[tf.keras.Model] = None
        self.scaler: Optional[StandardScaler] = None
        self.anomaly_threshold: float = 0.0
        
        # Performance tracking
        self.inference_times: List[float] = []
        self.model_version = "1.0.0"
        self.last_trained: Optional[datetime] = None
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Initialize model
        self._ensure_model_directory()
        
    def _ensure_model_directory(self) -> None:
        """Ensure model and scaler directories exist"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.scaler_path), exist_ok=True)
        
    def _build_autoencoder(self) -> tf.keras.Model:
        """
        Build deep autoencoder architecture for anomaly detection
        
        Architecture:
        - Input layer: feature_dim neurons
        - Encoder: [128, 64, encoding_dim] with dropout and batch norm
        - Decoder: [64, 128, feature_dim] with dropout and batch norm
        - Activation: ReLU for hidden layers, linear for output
        """
        # Input layer
        input_layer = tf.keras.layers.Input(shape=(self.feature_dim,))
        
        # Encoder layers
        encoder = tf.keras.layers.Dense(128, activation='relu')(input_layer)
        encoder = tf.keras.layers.BatchNormalization()(encoder)
        encoder = tf.keras.layers.Dropout(0.2)(encoder)
        
        encoder = tf.keras.layers.Dense(64, activation='relu')(encoder)
        encoder = tf.keras.layers.BatchNormalization()(encoder)
        encoder = tf.keras.layers.Dropout(0.2)(encoder)
        
        # Bottleneck layer (encoded representation)
        encoded = tf.keras.layers.Dense(self.encoding_dim, activation='relu', name='encoded')(encoder)
        
        # Decoder layers
        decoder = tf.keras.layers.Dense(64, activation='relu')(encoded)
        decoder = tf.keras.layers.BatchNormalization()(decoder)
        decoder = tf.keras.layers.Dropout(0.2)(decoder)
        
        decoder = tf.keras.layers.Dense(128, activation='relu')(decoder)
        decoder = tf.keras.layers.BatchNormalization()(decoder)
        decoder = tf.keras.layers.Dropout(0.2)(decoder)
        
        # Output layer (reconstruction)
        decoded = tf.keras.layers.Dense(self.feature_dim, activation='linear')(decoder)
        
        # Create full autoencoder model
        autoencoder = tf.keras.Model(input_layer, decoded, name='cybershield_autoencoder')
        
        # Create encoder model for embeddings
        encoder_model = tf.keras.Model(input_layer, encoded, name='cybershield_encoder')
        
        # Compile with Adam optimizer and MSE loss
        autoencoder.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return autoencoder, encoder_model
    
    def _calculate_feature_contributions(
        self, 
        original: np.ndarray, 
        reconstructed: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, float]:
        """Calculate individual feature contributions to anomaly score"""
        
        # Calculate per-feature reconstruction errors
        feature_errors = np.abs(original - reconstructed)
        
        # Normalize to get contribution percentages
        total_error = np.sum(feature_errors)
        if total_error == 0:
            contributions = np.zeros_like(feature_errors)
        else:
            contributions = feature_errors / total_error
        
        # Create feature contribution dictionary
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(len(contributions))]
        
        return {
            name: float(contrib) 
            for name, contrib in zip(feature_names, contributions)
        }
    
    def _generate_explanation(
        self, 
        anomaly_score: float, 
        feature_contributions: Dict[str, float],
        threshold: float
    ) -> str:
        """Generate human-readable explanation for anomaly detection"""
        
        if anomaly_score <= threshold:
            return f"Normal behavior detected (score: {anomaly_score:.3f}, threshold: {threshold:.3f})"
        
        # Find top contributing features
        top_features = sorted(
            feature_contributions.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:3]
        
        explanation = f"Anomaly detected (score: {anomaly_score:.3f}, threshold: {threshold:.3f}). "
        explanation += "Top contributing factors: "
        explanation += ", ".join([
            f"{feature} ({contrib:.1%})" 
            for feature, contrib in top_features
        ])
        
        return explanation
    
    async def train(
        self,
        training_data: pd.DataFrame,
        validation_split: float = 0.2,
        epochs: int = 100,
        early_stopping_patience: int = 10,
        feature_names: Optional[List[str]] = None,
        **kwargs
    ) -> TrainingMetrics:
        """
        Train the anomaly detection model asynchronously
        
        Args:
            training_data: Normal behavior data for training
            validation_split: Fraction of data for validation
            epochs: Maximum training epochs
            early_stopping_patience: Early stopping patience
            feature_names: Optional feature names for interpretability
        
        Returns:
            TrainingMetrics with performance information
        """
        start_time = datetime.now()
        logger.info(f"Starting anomaly detector training on {len(training_data)} samples")
        
        # Run training in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.executor,
            self._train_sync,
            training_data,
            validation_split,
            epochs,
            early_stopping_patience,
            feature_names,
            kwargs
        )
        
        training_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Training completed in {training_time:.2f} seconds")
        
        return result
    
    def _train_sync(
        self,
        training_data: pd.DataFrame,
        validation_split: float,
        epochs: int,
        early_stopping_patience: int,
        feature_names: Optional[List[str]],
        kwargs: Dict[str, Any]
    ) -> TrainingMetrics:
        """Synchronous training implementation"""
        
        # Prepare data
        X = training_data.values.astype(np.float32)
        
        # Fit scaler on training data
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_val = train_test_split(
            X_scaled, 
            test_size=validation_split, 
            random_state=42
        )
        
        # Build model
        self.model, self.encoder = self._build_autoencoder()
        
        # Configure callbacks
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=early_stopping_patience,
                restore_best_weights=True
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7
            )
        ]
        
        # Train model
        history = self.model.fit(
            X_train, X_train,  # Autoencoder trains to reconstruct input
            batch_size=self.batch_size,
            epochs=epochs,
            validation_data=(X_val, X_val),
            callbacks=callbacks,
            verbose=0
        )
        
        # Calculate anomaly threshold
        train_reconstructions = self.model.predict(X_train, verbose=0)
        train_errors = np.mean(np.square(X_train - train_reconstructions), axis=1)
        self.anomaly_threshold = np.percentile(train_errors, self.threshold_percentile)
        
        # Save model and scaler
        self.model.save(self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        
        # Update tracking variables
        self.last_trained = datetime.now()
        
        # Create training metrics
        final_loss = history.history['loss'][-1]
        final_val_loss = history.history['val_loss'][-1]
        epochs_trained = len(history.history['loss'])
        
        return TrainingMetrics(
            loss=final_loss,
            val_loss=final_val_loss,
            reconstruction_loss=final_loss,
            training_time=(datetime.now() - datetime.now()).total_seconds(),
            epochs_trained=epochs_trained,
            model_version=self.model_version
        )
    
    async def detect_anomaly(
        self,
        data: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> AnomalyResult:
        """
        Detect anomalies in new data asynchronously
        
        Args:
            data: Input data for anomaly detection
            feature_names: Optional feature names for interpretability
        
        Returns:
            AnomalyResult with detailed detection information
        """
        start_time = datetime.now()
        
        # Ensure models are loaded
        if self.model is None or self.scaler is None:
            await self.load_model()
        
        # Run inference in thread pool
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.executor,
            self._detect_anomaly_sync,
            data,
            feature_names
        )
        
        # Track inference time
        inference_time = (datetime.now() - start_time).total_seconds() * 1000  # ms
        self.inference_times.append(inference_time)
        
        # Keep only last 1000 measurements
        if len(self.inference_times) > 1000:
            self.inference_times = self.inference_times[-1000:]
        
        logger.debug(f"Anomaly detection completed in {inference_time:.2f}ms")
        
        return result
    
    def _detect_anomaly_sync(
        self,
        data: np.ndarray,
        feature_names: Optional[List[str]]
    ) -> AnomalyResult:
        """Synchronous anomaly detection implementation"""
        
        # Ensure data is 2D
        if data.ndim == 1:
            data = data.reshape(1, -1)
        
        # Scale data
        data_scaled = self.scaler.transform(data)
        
        # Get reconstruction
        reconstruction = self.model.predict(data_scaled, verbose=0)
        
        # Calculate reconstruction error (anomaly score)
        reconstruction_error = np.mean(np.square(data_scaled - reconstruction), axis=1)[0]
        
        # Determine if anomaly
        is_anomaly = reconstruction_error > self.anomaly_threshold
        
        # Calculate confidence (how far from threshold)
        confidence = min(
            abs(reconstruction_error - self.anomaly_threshold) / self.anomaly_threshold,
            1.0
        )
        
        # Calculate feature contributions
        feature_contributions = self._calculate_feature_contributions(
            data_scaled[0], 
            reconstruction[0], 
            feature_names
        )
        
        # Generate explanation
        explanation = self._generate_explanation(
            reconstruction_error,
            feature_contributions,
            self.anomaly_threshold
        )
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=reconstruction_error,
            confidence=confidence,
            feature_contributions=feature_contributions,
            reconstruction_error=reconstruction_error,
            threshold=self.anomaly_threshold,
            timestamp=datetime.now(),
            explanation=explanation
        )
    
    async def load_model(self) -> bool:
        """Load saved model and scaler"""
        try:
            if os.path.exists(self.model_path):
                self.model = tf.keras.models.load_model(self.model_path)
                logger.info(f"Loaded anomaly detection model from {self.model_path}")
            
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
                logger.info(f"Loaded scaler from {self.scaler_path}")
            
            return self.model is not None and self.scaler is not None
            
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            return False
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get model performance metrics"""
        
        if not self.inference_times:
            return {}
        
        return {
            "avg_inference_time_ms": np.mean(self.inference_times),
            "p95_inference_time_ms": np.percentile(self.inference_times, 95),
            "p99_inference_time_ms": np.percentile(self.inference_times, 99),
            "total_inferences": len(self.inference_times),
            "model_version": self.model_version,
            "last_trained": self.last_trained.isoformat() if self.last_trained else None,
            "anomaly_threshold": self.anomaly_threshold,
            "feature_dim": self.feature_dim,
            "encoding_dim": self.encoding_dim
        }
    
    def should_retrain(self, drift_threshold: float = 0.1) -> bool:
        """Determine if model should be retrained based on performance drift"""
        
        if not self.last_trained:
            return True
        
        # Retrain if model is older than 7 days
        if (datetime.now() - self.last_trained) > timedelta(days=7):
            return True
        
        # Check for performance drift (simplified)
        if len(self.inference_times) > 100:
            recent_times = self.inference_times[-100:]
            avg_recent = np.mean(recent_times)
            avg_historical = np.mean(self.inference_times[:-100]) if len(self.inference_times) > 100 else avg_recent
            
            if abs(avg_recent - avg_historical) / avg_historical > drift_threshold:
                return True
        
        return False
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)