import random
import joblib
from sklearn.ensemble import RandomForestClassifier
from core.ml_classifier import MLClassifier

def build_mock_dataset():
    """
    Creates a simulated dataset of 2000 URLs to train the model.
    In a real scenario, this would download from PhishTank / Tranco.
    """
    print("[*] Generating synthetic dataset...")
    X, y = [], []
    extractor = MLClassifier()
    
    # Generate 1000 Phishing URLs
    for _ in range(1000):
        url = f"http://{'192.168.1.1' if random.random() > 0.5 else 'login-update.tk'}/{'a/'*random.randint(2,8)}"
        X.append(extractor.extract_features(url))
        y.append(1)
        
    # Generate 1000 Legit URLs
    for _ in range(1000):
        url = f"https://google.com/{'search' if random.random() > 0.5 else ''}"
        X.append(extractor.extract_features(url))
        y.append(0)
        
    return X, y

def train_and_save():
    X, y = build_mock_dataset()
    print("[*] Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
    clf.fit(X, y)
    
    joblib.dump(clf, '../model.pkl')
    print("[+] Model saved to model.pkl successfully.")

if __name__ == "__main__":
    train_and_save()