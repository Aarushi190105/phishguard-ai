from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


FEATURE_COLUMNS = [
    "UrlLength",
    "NumDots",
    "SubdomainLevel",
    "PathLevel",
    "NumDash",
    "AtSymbol",
    "NumSensitiveWords",
]
TARGET_COLUMN = "CLASS_LABEL"



def train_model() -> Path:
    backend_dir = Path(__file__).resolve().parent
    csv_path = backend_dir / "Phishing_Legitimate_full.csv"
    model_path = backend_dir / "models" / "model.pkl"

    df = pd.read_csv(csv_path)

    missing = [col for col in FEATURE_COLUMNS + [TARGET_COLUMN] if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in dataset: {missing}")

    x = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(x, y)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    return model_path


if __name__ == "__main__":
    saved_to = train_model()
    print(f"Model trained and saved to: {saved_to}")
