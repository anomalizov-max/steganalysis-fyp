"""
Machine Learning-based Detection Module
Uses feature extraction and classification for steganography detection
"""

import numpy as np
from PIL import Image
from typing import Dict
from sklearn.ensemble import IsolationForest
import warnings
warnings.filterwarnings('ignore')

class MLDetector:
    """Machine learning-based steganography detector"""
    
    def __init__(self):
        self.name = "ML Detector"
        self.model = None
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize anomaly detection model"""
        # Using Isolation Forest for unsupervised anomaly detection
        # No training data needed - it learns normal patterns
        self.model = IsolationForest(
            contamination=0.1,  # Expected proportion of outliers
            random_state=42,
            n_estimators=100
        )
    
    def analyze(self, image_path: str) -> Dict:
        """
        Perform ML-based analysis
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing detection results
        """
        try:
            img = Image.open(image_path)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            
            # Extract features
            features = self._extract_features(img_array)
            
            # Analyze features
            score = self._analyze_features(features)
            
            return {
                'score': score,
                'suspicious': score > 50,
                'features_extracted': len(features),
                'method': 'ML Detection'
            }
        except Exception as e:
            return {
                'score': 0,
                'error': str(e),
                'method': 'ML Detection'
            }
    
    def _extract_features(self, img_array: np.ndarray) -> np.ndarray:
        """
        Extract statistical features from image for ML analysis
        """
        features = []
        
        # 1. Channel-wise statistics
        for channel in range(3):
            channel_data = img_array[:, :, channel]
            features.extend([
                np.mean(channel_data),
                np.std(channel_data),
                np.median(channel_data),
                np.percentile(channel_data, 25),
                np.percentile(channel_data, 75)
            ])
        
        # 2. LSB plane statistics
        for channel in range(3):
            lsb_plane = img_array[:, :, channel] & 1
            features.extend([
                np.mean(lsb_plane),
                np.std(lsb_plane)
            ])
        
        # 3. Pixel difference statistics (texture analysis)
        for channel in range(3):
            channel_data = img_array[:, :, channel]
            
            # Horizontal differences
            h_diff = np.diff(channel_data, axis=1)
            features.extend([
                np.mean(h_diff),
                np.std(h_diff)
            ])
            
            # Vertical differences
            v_diff = np.diff(channel_data, axis=0)
            features.extend([
                np.mean(v_diff),
                np.std(v_diff)
            ])
        
        # 4. Entropy
        for channel in range(3):
            channel_data = img_array[:, :, channel]
            hist, _ = np.histogram(channel_data, bins=256, range=(0, 256))
            hist = hist / hist.sum()
            entropy = -np.sum(hist * np.log2(hist + 1e-10))
            features.append(entropy)
        
        # 5. Bit plane entropy (LSB through MSB)
        for bit in range(3):  # Check first 3 bit planes
            bit_plane = (img_array[:, :, 0] >> bit) & 1
            unique, counts = np.unique(bit_plane, return_counts=True)
            probs = counts / counts.sum()
            entropy = -np.sum(probs * np.log2(probs + 1e-10))
            features.append(entropy)
        
        return np.array(features)
    
    def _analyze_features(self, features: np.ndarray) -> float:
        """
        Analyze extracted features using multiple methods
        """
        # Method 1: Feature-based heuristics
        heuristic_score = self._heuristic_analysis(features)
        
        # Method 2: Anomaly detection
        anomaly_score = self._anomaly_detection(features)
        
        # Combine scores
        final_score = (heuristic_score * 0.6 + anomaly_score * 0.4)
        
        return round(final_score, 2)
    
    def _heuristic_analysis(self, features: np.ndarray) -> float:
        """
        Rule-based analysis of features
        """
        score = 0
        
        # Check LSB plane statistics (features 15-20)
        lsb_means = features[15:21:2]  # LSB means for each channel
        lsb_stds = features[16:21:2]   # LSB stds for each channel
        
        # Suspicious if LSB mean is close to 0.5 (random distribution)
        for lsb_mean in lsb_means:
            deviation = abs(lsb_mean - 0.5)
            if deviation < 0.15:
                score += 15
        
        # Suspicious if LSB std is high (random noise)
        avg_lsb_std = np.mean(lsb_stds)
        if avg_lsb_std > 0.4:
            score += 20
        
        # Check entropy values (higher entropy = more randomness)
        entropy_features = features[33:36]  # Channel entropies
        avg_entropy = np.mean(entropy_features)
        if avg_entropy > 7.5:  # High entropy
            score += 15
        
        # Check bit plane entropies
        bit_entropies = features[36:39]
        if np.mean(bit_entropies) > 0.98:  # Close to max entropy
            score += 20
        
        return min(score, 100)
    
    def _anomaly_detection(self, features: np.ndarray) -> float:
        """
        Use Isolation Forest to detect anomalies in features
        """
        try:
            # Reshape features for sklearn
            features_reshaped = features.reshape(1, -1)
            
            # Fit and predict (unsupervised)
            self.model.fit(features_reshaped)
            prediction = self.model.predict(features_reshaped)
            anomaly_score_raw = self.model.score_samples(features_reshaped)
            
            # prediction: -1 = anomaly, 1 = normal
            # anomaly_score_raw: more negative = more anomalous
            
            # Convert to 0-100 scale
            if prediction[0] == -1:
                # It's an anomaly
                # Score ranges roughly from -0.5 to 0.5
                # More negative = more anomalous
                normalized_score = min(abs(anomaly_score_raw[0]) * 200, 100)
            else:
                # Normal image
                normalized_score = max(50 - abs(anomaly_score_raw[0]) * 100, 0)
            
            return normalized_score
        except Exception:
            return 0
