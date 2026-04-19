from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import socket

import joblib
import requests
import shap
import whois
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

from services.feature_extractor import extract_features


FEATURE_COLUMNS = [
    "UrlLength",
    "NumDots",
    "SubdomainLevel",
    "PathLevel",
    "NumDash",
    "AtSymbol",
    "NumSensitiveWords",
]

FEATURE_REASON_TEXT = {
    "UrlLength": "URL length is unusually high.",
    "NumDots": "URL has many dot separators.",
    "SubdomainLevel": "URL uses multiple subdomain levels.",
    "PathLevel": "URL path has deep nested segments.",
    "NumDash": "URL contains several dash characters.",
    "AtSymbol": "URL includes '@', which can obfuscate destination.",
    "NumSensitiveWords": "URL includes phishing-related sensitive words.",
}

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "model.pkl"
router = APIRouter(tags=["analysis"])


class AnalyzeRequest(BaseModel):
    url: HttpUrl


class AnalyzeResponse(BaseModel):
    url: str
    label: str
    phishing_probability: float
    features: dict[str, int]
    threat_indicators: list[str]
    geolocation: dict[str, str | None]
    domain_age_days: int | None


_model = None
_explainer = None


def get_model():
    global _model, _explainer
    if _model is None:
        if not MODEL_PATH.exists():
            raise HTTPException(status_code=500, detail="Model file not found. Run backend/train.py first.")
        _model = joblib.load(MODEL_PATH)
        _explainer = shap.TreeExplainer(_model)
    return _model, _explainer



def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None



def _fetch_geolocation(ip_address: str | None) -> dict[str, str | None]:
    if not ip_address:
        return {"ip": None, "city": None, "country": None}

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "ip": ip_address,
            "city": data.get("city"),
            "country": data.get("country"),
        }
    except requests.RequestException:
        return {"ip": ip_address, "city": None, "country": None}



def _domain_age_days(hostname: str) -> int | None:
    try:
        domain_info = whois.whois(hostname)
        created = domain_info.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - created).days, 0)
    except Exception:
        return None



def _extract_top_reasons(explainer, feature_vector, predicted_class: int) -> list[str]:
    shap_values = explainer.shap_values(feature_vector)

    if isinstance(shap_values, list):
        class_values = shap_values[predicted_class][0]
    else:
        class_values = shap_values[0]

    ranked = sorted(
        zip(FEATURE_COLUMNS, class_values),
        key=lambda x: abs(x[1]),
        reverse=True,
    )[:3]

    reasons = []
    for feature_name, impact in ranked:
        direction = "increases" if impact >= 0 else "decreases"
        reasons.append(f"{FEATURE_REASON_TEXT[feature_name]} This feature {direction} phishing risk.")
    return reasons


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_url(payload: AnalyzeRequest):
    model, explainer = get_model()

    url_str = str(payload.url)
    features = extract_features(url_str)
    feature_vector = [[features[col] for col in FEATURE_COLUMNS]]

    phishing_probability = float(model.predict_proba(feature_vector)[0][1])
    prediction = int(model.predict(feature_vector)[0])
    label = "Phishing" if prediction == 1 else "Safe"

    hostname = payload.url.host or ""
    ip_address = _resolve_ip(hostname)
    geolocation = _fetch_geolocation(ip_address)
    domain_age_days = _domain_age_days(hostname) if hostname else None

    threat_indicators = _extract_top_reasons(explainer, feature_vector, prediction)

    return AnalyzeResponse(
        url=url_str,
        label=label,
        phishing_probability=round(phishing_probability * 100, 2),
        features=features,
        threat_indicators=threat_indicators,
        geolocation=geolocation,
        domain_age_days=domain_age_days,
    )
