import chromadb
from sentence_transformers import SentenceTransformer
import os

# THIS is the correct persistent DB method
client = chromadb.PersistentClient(path="./chroma_db")

collection = client.get_or_create_collection(name="security_docs")

model = SentenceTransformer("all-MiniLM-L6-v2")

docs_path = "./docs"

for file in os.listdir(docs_path):
    if not file.endswith(".txt"):
        continue

    full_path = os.path.join(docs_path, file)

    with open(full_path, "r") as f:
        text = f.read()

    embedding = model.encode(text).tolist()

    collection.add(
        documents=[text],
        embeddings=[embedding],
        ids=[file]
    )

print("✅ Docs ingested into vector DB")