"""
LSB (Least Significant Bit) Detection Module
Detects steganography based on LSB manipulation patterns
"""

import numpy as np
from PIL import Image
from typing import Dict, Tuple

class LSBDetector:
    """Detects LSB-based steganography in images"""
    
    def __init__(self):
        self.name = "LSB Detector"
    
    def analyze(self, image_path: str) -> Dict:
        """
        Analyze image for LSB steganography
        
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
            
            # Perform multiple LSB tests
            lsb_distribution = self._check_lsb_distribution(img_array)
            chi_square_lsb = self._chi_square_lsb_test(img_array)
            bit_plane_analysis = self._bit_plane_analysis(img_array)
            
            # Calculate overall score (0-100)
            score = self._calculate_lsb_score(lsb_distribution, chi_square_lsb, bit_plane_analysis)
            
            return {
                'score': score,
                'suspicious': score > 50,
                'lsb_distribution': lsb_distribution,
                'chi_square_result': chi_square_lsb,
                'bit_plane_anomaly': bit_plane_analysis,
                'method': 'LSB Detection'
            }
        except Exception as e:
            return {
                'score': 0,
                'error': str(e),
                'method': 'LSB Detection'
            }
    
    def _check_lsb_distribution(self, img_array: np.ndarray) -> float:
        """
        Check distribution of LSBs across color channels
        LSB should be approximately 50% 0s and 50% 1s in normal images
        """
        lsb_bits = img_array & 1  # Extract LSBs
        
        # Calculate ratio of 1s
        ones_ratio = np.sum(lsb_bits) / lsb_bits.size
        
        # Deviation from expected 0.5
        deviation = abs(ones_ratio - 0.5)
        
        # Score based on deviation (higher deviation = more suspicious)
        # Normal deviation is around 0.0-0.05, embedded data shows 0.05-0.15+
        score = min(deviation * 500, 100)
        
        return score
    
    def _chi_square_lsb_test(self, img_array: np.ndarray) -> float:
        """
        Chi-square test on LSBs
        Tests if LSB plane has expected statistical properties
        """
        lsb_plane = img_array & 1
        
        # Flatten the array
        lsb_flat = lsb_plane.flatten()
        
        # Count pairs of values (PoVs)
        unique, counts = np.unique(lsb_flat, return_counts=True)
        
        # Expected count for uniform distribution
        total = len(lsb_flat)
        expected = total / len(unique)
        
        # Chi-square calculation
        chi_square = np.sum((counts - expected) ** 2 / expected)
        
        # Normalize to 0-100 scale
        score = min(chi_square / 10, 100)
        
        return score
    
    def _bit_plane_analysis(self, img_array: np.ndarray) -> float:
        """
        Analyze bit planes for anomalies
        LSB manipulation often creates visible patterns
        """
        # Extract LSB plane for each channel
        r_lsb = img_array[:, :, 0] & 1
        g_lsb = img_array[:, :, 1] & 1
        b_lsb = img_array[:, :, 2] & 1
        
        # Calculate entropy for each LSB plane
        def calculate_entropy(plane):
            unique, counts = np.unique(plane, return_counts=True)
            probabilities = counts / counts.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            return entropy
        
        r_entropy = calculate_entropy(r_lsb)
        g_entropy = calculate_entropy(g_lsb)
        b_entropy = calculate_entropy(b_lsb)
        
        avg_entropy = (r_entropy + g_entropy + b_entropy) / 3
        
        # High entropy in LSB plane suggests random data (steganography)
        # Maximum entropy for 1-bit data is 1.0
        score = avg_entropy * 100
        
        return score
    
    def _calculate_lsb_score(self, dist_score: float, chi_score: float, 
                            bit_plane_score: float) -> float:
        """
        Calculate weighted overall LSB detection score
        """
        # Weighted average of different tests
        weights = {
            'distribution': 0.3,
            'chi_square': 0.3,
            'bit_plane': 0.4
        }
        
        total_score = (
            dist_score * weights['distribution'] +
            chi_score * weights['chi_square'] +
            bit_plane_score * weights['bit_plane']
        )
        
        return round(total_score, 2)
