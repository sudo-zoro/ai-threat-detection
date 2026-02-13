import pandas as pd
import joblib
import ollama
import chromadb
from sentence_transformers import SentenceTransformer

# -----------------------------
# Load ML model
# -----------------------------
model = joblib.load("/home/zoro/code/ai-threat-detector/models/anomaly_model.pkl")

# -----------------------------
# Load login logs
# -----------------------------
df = pd.read_csv("/home/zoro/code/ai-threat-detector/data/login_logs.csv")

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

# Detect anomalies
df["is_anomaly"] = model.predict(features)
df["is_anomaly"] = df["is_anomaly"].apply(lambda x: 1 if x == -1 else 0)

anomalies = df[df["is_anomaly"] == 1]

print(f"\n🚨 Found {len(anomalies)} anomalies")

# -----------------------------
# Load vector DB
# -----------------------------
client = chromadb.PersistentClient(path="./chroma_db")

collection = client.get_collection("security_docs")

embed_model = SentenceTransformer("all-MiniLM-L6-v2")

# -----------------------------
# Retrieve relevant security text
# -----------------------------
def retrieve_context(query):
    embedding = embed_model.encode(query).tolist()

    results = collection.query(
        query_embeddings=[embedding],
        n_results=1
    )

    return results["documents"][0][0]

# -----------------------------
# Explain using LLM + RAG
# -----------------------------
def explain(row):
    query = f"login attack with {row['failed_attempts']} failed attempts"

    context = retrieve_context(query)

    prompt = f"""
You are a cybersecurity SOC analyst.

Use the security knowledge below to analyze the login event.

Security Knowledge:
{context}

Login Event:
User: {row['user']}
Country: {row['country']}
Failed Attempts: {row['failed_attempts']}
Hour: {row['hour']}

Explain:
1) Attack type
2) Severity
3) Why it is suspicious
4) Recommended fix
"""

    response = ollama.chat(
        model="llama3",
        messages=[{"role": "user", "content": prompt}]
    )

    return response["message"]["content"]

# -----------------------------
# Test with first 3 anomalies
# -----------------------------
for _, row in anomalies.head(2).iterrows():
    print("\n=============================")
    print("🚨 Suspicious Login")
    print(row[["user", "country", "failed_attempts"]])

    print("\n🤖 RAG + LLM Analysis:")
    print(explain(row))