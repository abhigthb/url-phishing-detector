import os
import joblib
import re
from urllib.parse import urlparse

class MLClassifier:
    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path = os.path.join(base_dir, 'model.pkl')
        
        if os.path.exists(model_path) and os.path.getsize(model_path) > 0:
            try:
                self.model = joblib.load(model_path)
            except Exception:
                self.model = None
        else:
            self.model = None

    def extract_features(self, url):
        """
        Transforms a raw URL into a normalized array of numerical 
        features matching the classifier input mapping schema.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        
        # Binary flags mapping
        features = [
            len(url),                             # URL Length
            1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0, # IP presence
            1 if '@' in url else 0,                # At-symbol trigger
            hostname.count('.'),                  # Dot density
            1 if 'https' in parsed.scheme else 0, # Secure layer profile
            hostname.count('-'),                  # Dash count
        ]
        return features

    def predict(self, url):
        """
        Executes inference against the active compiled engine state.
        """
        if not self.model:
            return {"score": 0, "top_features": ["Model not compiled"]}
            
        features = [self.extract_features(url)]
        try:
            prob = self.model.predict_proba(features)[0][1] # Probability of Class 1
            score = round(prob * 100, 2)
            
            # Map top features contextually based on binary triggers
            triggers = []
            features_vec = features[0]
            if features_vec[0] > 100: triggers.append("URL Length Threshold")
            if features_vec[1] == 1: triggers.append("Raw IP Routing")
            if features_vec[2] == 1: triggers.append("Credential Masking Symbol")
            if features_vec[3] > 3: triggers.append("Deep Subdomain Nesting")
            if features_vec[4] == 0: triggers.append("Insecure Protocol (HTTP)")
            
            return {
                "score": score,
                "top_features": triggers if triggers else ["Baseline Signatures Clear"]
            }
        except Exception:
            return {"score": 0, "top_features": ["Inference Exception"]}