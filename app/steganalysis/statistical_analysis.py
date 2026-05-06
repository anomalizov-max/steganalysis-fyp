"""
Statistical Analysis Module
Implements RS Analysis and other statistical steganalysis techniques
"""

import numpy as np
from PIL import Image
from typing import Dict
from scipy import stats

class StatisticalAnalyzer:
    """Performs statistical analysis for steganography detection"""
    
    def __init__(self):
        self.name = "Statistical Analyzer"
    
    def analyze(self, image_path: str) -> Dict:
        """
        Perform statistical analysis on image
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            img = Image.open(image_path)
            
            # Convert to RGB if needed
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            img_array = np.array(img)
            
            # Perform statistical tests
            rs_score = self._rs_analysis(img_array)
            histogram_score = self._histogram_analysis(img_array)
            correlation_score = self._pixel_correlation_analysis(img_array)
            
            # Calculate overall statistical score
            overall_score = self._calculate_statistical_score(
                rs_score, histogram_score, correlation_score
            )
            
            return {
                'score': overall_score,
                'suspicious': overall_score > 50,
                'rs_analysis': rs_score,
                'histogram_analysis': histogram_score,
                'correlation_analysis': correlation_score,
                'method': 'Statistical Analysis'
            }
        except Exception as e:
            return {
                'score': 0,
                'error': str(e),
                'method': 'Statistical Analysis'
            }
    
    def _rs_analysis(self, img_array: np.ndarray) -> float:
        """
        RS (Regular-Singular) Analysis
        Detects steganography by analyzing pixel group statistics
        """
        def flip_lsb(block):
            """Flip LSB of pixels in block"""
            return block ^ 1
        
        def discrimination_function(block):
            """Calculate variation in block"""
            return np.sum(np.abs(np.diff(block.flatten())))
        
        # Work on grayscale or average of RGB
        if len(img_array.shape) == 3:
            gray = np.mean(img_array, axis=2).astype(np.uint8)
        else:
            gray = img_array
        
        # Divide image into blocks
        block_size = 4
        h, w = gray.shape
        blocks = []
        
        for i in range(0, h - block_size, block_size):
            for j in range(0, w - block_size, block_size):
                block = gray[i:i+block_size, j:j+block_size]
                blocks.append(block)
        
        if not blocks:
            return 0
        
        # Count regular and singular groups
        regular_m = 0
        singular_m = 0
        regular_n = 0
        singular_n = 0
        
        for block in blocks[:min(100, len(blocks))]:  # Sample blocks for performance
            f = discrimination_function(block)
            f_m = discrimination_function(flip_lsb(block))
            f_n = discrimination_function(flip_lsb(flip_lsb(block)))
            
            # Classify blocks
            if f_m > f:
                regular_m += 1
            elif f_m < f:
                singular_m += 1
            
            if f_n > f_m:
                regular_n += 1
            elif f_n < f_m:
                singular_n += 1
        
        total = regular_m + singular_m
        if total == 0:
            return 0
        
        # Calculate RS ratio
        rm_ratio = regular_m / total if total > 0 else 0
        sm_ratio = singular_m / total if total > 0 else 0
        
        # In clean images, RM ≈ SM. Large difference suggests steganography
        rs_difference = abs(rm_ratio - sm_ratio)
        
        # Convert to 0-100 score
        score = min(rs_difference * 200, 100)
        
        return score
    
    def _histogram_analysis(self, img_array: np.ndarray) -> float:
        """
        Analyze histogram for anomalies
        Steganography often creates characteristic histogram patterns
        """
        # Calculate histogram for each channel
        histograms = []
        for channel in range(3):
            hist, _ = np.histogram(img_array[:, :, channel], bins=256, range=(0, 256))
            histograms.append(hist)
        
        # Look for pairs of values (PoV) anomaly
        # In LSB embedding, pixel values often come in pairs
        anomaly_scores = []
        
        for hist in histograms:
            pair_differences = []
            for i in range(0, 256, 2):
                if i + 1 < 256:
                    diff = abs(hist[i] - hist[i + 1])
                    pair_differences.append(diff)
            
            # Calculate coefficient of variation
            if pair_differences:
                mean_diff = np.mean(pair_differences)
                std_diff = np.std(pair_differences)
                cv = std_diff / (mean_diff + 1e-10)
                anomaly_scores.append(cv)
        
        # High variation suggests PoV artifacts from steganography
        avg_anomaly = np.mean(anomaly_scores) if anomaly_scores else 0
        score = min(avg_anomaly * 20, 100)
        
        return score
    
    def _pixel_correlation_analysis(self, img_array: np.ndarray) -> float:
        """
        Analyze pixel value correlations
        Steganography often reduces natural correlation between adjacent pixels
        """
        # Calculate correlation for each channel
        correlations = []
        
        for channel in range(3):
            channel_data = img_array[:, :, channel]
            
            # Horizontal correlation
            h_corr = np.corrcoef(
                channel_data[:, :-1].flatten(),
                channel_data[:, 1:].flatten()
            )[0, 1]
            
            # Vertical correlation
            v_corr = np.corrcoef(
                channel_data[:-1, :].flatten(),
                channel_data[1:, :].flatten()
            )[0, 1]
            
            correlations.append((h_corr + v_corr) / 2)
        
        avg_correlation = np.mean(correlations)
        
        # Natural images have high correlation (typically > 0.9)
        # Steganography reduces this
        expected_correlation = 0.95
        correlation_loss = expected_correlation - avg_correlation
        
        # Convert to 0-100 score
        score = min(correlation_loss * 500, 100) if correlation_loss > 0 else 0
        
        return score
    
    def _calculate_statistical_score(self, rs_score: float, hist_score: float,
                                     corr_score: float) -> float:
        """
        Calculate overall statistical analysis score
        """
        weights = {
            'rs': 0.4,
            'histogram': 0.3,
            'correlation': 0.3
        }
        
        total_score = (
            rs_score * weights['rs'] +
            hist_score * weights['histogram'] +
            corr_score * weights['correlation']
        )
        
        return round(total_score, 2)
