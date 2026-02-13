import pandas as pd
import joblib
import ollama

# -----------------------------
# Load model from Phase 1
# -----------------------------
model = joblib.load("anomaly_model.pkl")

# -----------------------------
# Load login logs
# -----------------------------
df = pd.read_csv("login_logs.csv")

# Same feature engineering as Phase 1
df["country_code"] = df["country"].astype("category").cat.codes
df["device_code"] = df["device"].astype("category").cat.codes
df["user_code"] = df["user"].astype("category").cat.codes

features = df[[
    "user_code",
    "country_code",
    "device_code",
    "hour",
    "failed_attempts"
]]

# -----------------------------
# Detect anomalies
# -----------------------------
df["is_anomaly"] = model.predict(features)
df["is_anomaly"] = df["is_anomaly"].apply(lambda x: 1 if x == -1 else 0)

anomalies = df[df["is_anomaly"] == 1]

print(f"\n🚨 Found {len(anomalies)} suspicious logins")

# -----------------------------
# Function to ask local LLM
# -----------------------------
def explain_with_llm(row):
    prompt = f"""
You are a cybersecurity SOC analyst.

Analyze this suspicious login:

User: {row['user']}
Country: {row['country']}
Device: {row['device']}
Hour: {row['hour']}
Failed Attempts: {row['failed_attempts']}

Answer in this format:

Attack Type:
Severity:
Reason:
Recommended Fix:
"""

    response = ollama.chat(
        model='llama3',
        messages=[{"role": "user", "content": prompt}]
    )

    return response['message']['content']

# -----------------------------
# Send first 2 anomalies
# -----------------------------
for _, row in anomalies.head(2).iterrows():
    print("\n==============================")
    print("🚨 Suspicious Login Event")
    print(row[["user", "country", "device", "hour", "failed_attempts"]])

    explanation = explain_with_llm(row)

    print("\n🤖 AI SOC Explanation:")
    print(explanation)