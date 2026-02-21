import numpy as np
import tensorflow as tf
import os
import json

class SimpleFileClassifier:
    """
    A simple ML classifier that categorizes files based on their content
    """
    
    def __init__(self, model_path=None):
        self.model = self._build_model()
        self.classes = ['safe', 'suspicious', 'malicious']
        
    def _build_model(self):
        """Build a simple neural network"""
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(10,)),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(3, activation='softmax')
        ])
        model.compile(optimizer='adam',
                     loss='sparse_categorical_crossentropy',
                     metrics=['accuracy'])
        return model
    
    def extract_features(self, file_path):
        """Extract features from file for ML prediction"""
        features = []
        
        # File size (normalized)
        size = os.path.getsize(file_path)
        features.append(min(size / (10*1024*1024), 1.0))  # Normalize to 0-1 (10MB max)
        
        # File extension features
        ext = os.path.splitext(file_path)[1].lower()
        ext_features = {
            '.exe': [1,0,0,0,0,0,0],
            '.bat': [0,1,0,0,0,0,0],
            '.ps1': [0,0,1,0,0,0,0],
            '.dll': [0,0,0,1,0,0,0],
            '.pdf': [0,0,0,0,1,0,0],
            '.txt': [0,0,0,0,0,1,0],
            '.jpg': [0,0,0,0,0,0,1]
        }
        features.extend(ext_features.get(ext, [0,0,0,0,0,0,0]))
        
        # Add placeholder features to reach 10 total
        while len(features) < 10:
            features.append(0)
        
        return np.array([features])
    
    def predict(self, file_path):
        """Predict file safety"""
        try:
            features = self.extract_features(file_path)
            prediction = self.model.predict(features, verbose=0)
            class_idx = np.argmax(prediction[0])
            confidence = float(prediction[0][class_idx])
            
            return {
                'class': self.classes[class_idx],
                'confidence': confidence,
                'scores': {
                    'safe': float(prediction[0][0]),
                    'suspicious': float(prediction[0][1]),
                    'malicious': float(prediction[0][2])
                }
            }
        except Exception as e:
            return {
                'class': 'unknown',
                'confidence': 0,
                'error': str(e)
            }

# Singleton instance
_classifier = None

def get_classifier():
    global _classifier
    if _classifier is None:
        _classifier = SimpleFileClassifier()
    return _classifier