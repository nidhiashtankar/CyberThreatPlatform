import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from app.detectors.phishing.features import extract_url_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_rf_model.joblib")

# Synthetic training dataset of typical benign and malicious URLs
SAMPLE_BENIGN_URLS = [
    "https://www.google.com/search?q=cybersecurity",
    "https://github.com/fastapi/fastapi",
    "https://en.wikipedia.org/wiki/Network_security",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.microsoft.com/en-us/security",
    "https://aws.amazon.com/security",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://pypi.org/project/scikit-learn/",
    "https://react.dev/learn",
    "https://www.apple.com/privacy/",
    "https://www.linkedin.com/feed/",
    "https://edition.cnn.com/world",
    "https://news.ycombinator.com/news",
    "https://www.mitre.org/news-insights",
    "https://www.cisa.gov/resources-tools",
    "https://www.sans.org/white-papers/"
]

SAMPLE_PHISHING_URLS = [
    "http://192.168.1.105/login/bank-verify.php",
    "http://paypa1-account-update.xyz/login.html",
    "http://verify-microsoft-security-alert.top/auth/signin.php?user=target",
    "http://google-drive-shared-doc-view.tk/login?token=urgent",
    "http://secure-banking-portal-login.buzz/update/password",
    "http://apple-id-suspended-recovery.club/verify?auth=failed",
    "http://netflix-billing-renew-service.icu/signin",
    "http://amazon-order-confirmation-urgent.cam/verify-card",
    "http://wellsfargo-online-session-restore.work/login.aspx",
    "http://chase-bank-security-verification.vip/signin.php",
    "http://198.51.100.88/secure/paypal-update/index.html",
    "http://dhl-package-tracking-fee-confirm.top/pay",
    "http://meta-facebook-account-locked.xyz/appeal",
    "http://microsoft-office365-invoice-download.tk/doc",
    "http://auth-secure-login-recovery.xyz/reset-password",
    "http://webmail-corporate-session-timeout.buzz/login",
    "http://vpn-portal-credential-sync.club/login"
]


def train_baseline_model() -> RandomForestClassifier:
    """Train and persist a baseline Random Forest classifier for URL classification."""
    X = []
    y = []

    for url in SAMPLE_BENIGN_URLS:
        feat = extract_url_features(url)["feature_vector"]
        X.append(feat)
        y.append(0)

    for url in SAMPLE_PHISHING_URLS:
        feat = extract_url_features(url)["feature_vector"]
        X.append(feat)
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    model = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42)
    model.fit(X, y)

    try:
        joblib.dump(model, MODEL_PATH)
    except Exception as e:
        print(f"Warning: Failed to save model to {MODEL_PATH}: {e}")

    return model


def get_phishing_model() -> RandomForestClassifier:
    """Load existing Random Forest model or train baseline if absent."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            return train_baseline_model()
    return train_baseline_model()
