import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import random

# -----------------------------
# STEP 1: Generate Fake Login Data
# -----------------------------

users = ["alice", "bob", "charlie", "david", "eve"]
countries = ["India", "USA", "UK", "Germany", "France"]
devices = ["Mobile", "Laptop", "Tablet"]

def generate_logs(n=1000):
    data = []
    base_time = datetime.now()

    for _ in range(n):
        user = random.choice(users)

        # Mostly normal logins
        if random.random() > 0.1:
            country = random.choice(countries)
            failed_attempts = np.random.poisson(1)
        else:
            # Simulated attack behavior
            country = "Russia"
            failed_attempts = random.randint(10, 50)

        timestamp = base_time - timedelta(minutes=random.randint(0, 10000))
        hour = timestamp.hour

        data.append([
            user,
            country,
            random.choice(devices),
            hour,
            failed_attempts
        ])

    df = pd.DataFrame(data, columns=[
        "user", "country", "device", "hour", "failed_attempts"
    ])

    return df

df = generate_logs(1200)

# -----------------------------
# STEP 2: Feature Engineering
# -----------------------------

# Convert categorical to numeric
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

df.to_csv('login_logs.csv')
# -----------------------------
# STEP 3: Train Isolation Forest
# -----------------------------

model = IsolationForest(
    n_estimators=100,
    contamination=0.08,  # % of anomalies expected
    random_state=42
)

model.fit(features)

# -----------------------------
# STEP 4: Detect Anomalies
# -----------------------------

df["anomaly_score"] = model.decision_function(features)
df["is_anomaly"] = model.predict(features)

# Convert:
# -1 = anomaly
#  1 = normal
df["is_anomaly"] = df["is_anomaly"].apply(lambda x: 1 if x == -1 else 0)

# -----------------------------
# STEP 5: Show Suspicious Logins
# -----------------------------

anomalies = df[df["is_anomaly"] == 1]

print("\n🚨 Detected Suspicious Logins:\n")
print(anomalies.head(10))

print(f"\nTotal logs: {len(df)}")
print(f"Anomalies detected: {len(anomalies)}")

import joblib
joblib.dump(model, "anomaly_model.pkl")