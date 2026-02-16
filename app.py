from __future__ import annotations

import json
import logging
import os
import time
from hashlib import sha256
from typing import Any, Dict

import joblib
import ollama
import pandas as pd
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

import chromadb
try:
    import redis  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    redis = None
from sentence_transformers import SentenceTransformer

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(APP_ROOT, "models", "anomaly_model.pkl")
LOGS_PATH = os.path.join(APP_ROOT, "data", "login_logs.csv")
CHROMA_PATH = os.path.join(APP_ROOT, "rag", "chroma_db")
COLLECTION_NAME = "security_docs"
EMBED_MODEL_NAME = "all-MiniLM-L6-v2"
LLM_MODEL_NAME = "llama3"
REDIS_URL = os.getenv("REDIS_URL")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))


class LoginEvent(BaseModel):
    user: str = Field(..., min_length=1)
    country: str = Field(..., min_length=1)
    device: str = Field(..., min_length=1)
    hour: int = Field(..., ge=0, le=23)
    failed_attempts: int = Field(..., ge=0)


class AnalyzeResponse(BaseModel):
    is_anomaly: bool
    attack_type: str | None
    severity: str | None
    explanation: str | None
    recommended_fix: str | None


class AnalyzeLogItem(BaseModel):
    user: str
    country: str
    device: str
    hour: int
    failed_attempts: int
    is_anomaly: bool
    attack_type: str | None
    severity: str | None
    explanation: str | None
    recommended_fix: str | None
    warning: str | None


class AnalyzeLogsResponse(BaseModel):
    total_anomalies: int
    returned: int
    items: list[AnalyzeLogItem]


app = FastAPI(title="AI Threat Detector")
logger = logging.getLogger("ai_threat_detector")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _load_categories() -> Dict[str, list]:
    df = pd.read_csv(LOGS_PATH)
    return {
        "user": df["user"].astype("category").cat.categories.tolist(),
        "country": df["country"].astype("category").cat.categories.tolist(),
        "device": df["device"].astype("category").cat.categories.tolist(),
    }


def _encode_with_categories(value: str, categories: list) -> int:
    cat = pd.Categorical([value], categories=categories)
    return int(cat.codes[0])


def _build_features(event: LoginEvent, categories: Dict[str, list]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "user_code": [_encode_with_categories(event.user, categories["user"])],
            "country_code": [_encode_with_categories(event.country, categories["country"])],
            "device_code": [_encode_with_categories(event.device, categories["device"])],
            "hour": [event.hour],
            "failed_attempts": [event.failed_attempts],
        }
    )


def _retrieve_context(query: str, collection, embed_model) -> str:
    embedding = embed_model.encode(query).tolist()
    results = collection.query(query_embeddings=[embedding], n_results=1)
    return results["documents"][0][0]


def _ask_llm(prompt: str) -> Dict[str, Any]:
    response = ollama.chat(
        model=LLM_MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
    )
    content = response["message"]["content"]

    # Expect JSON, but be resilient to non-JSON responses.
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Best-effort fallback: return raw text in explanation
    return {"explanation": content}


def _cache_key_for_prompt(prompt: str) -> str:
    digest = sha256(prompt.encode("utf-8")).hexdigest()
    return f"llm:{LLM_MODEL_NAME}:{digest}"


class _Cache:
    def get(self, key: str) -> Any | None:
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        raise NotImplementedError


class _InMemoryCache(_Cache):
    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        if key not in self._store:
            return None
        expires_at, value = self._store[key]
        if time.time() > expires_at:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._store[key] = (time.time() + ttl_seconds, value)


class _RedisCache(_Cache):
    def __init__(self, url: str) -> None:
        if redis is None:
            raise RuntimeError("redis package not installed")
        self._client = redis.Redis.from_url(url)

    def get(self, key: str) -> Any | None:
        raw = self._client.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._client.setex(key, ttl_seconds, json.dumps(value))


# ---- Startup state ----
model = joblib.load(MODEL_PATH)
categories = _load_categories()
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_or_create_collection(name=COLLECTION_NAME)
embed_model = SentenceTransformer(EMBED_MODEL_NAME)
if REDIS_URL:
    cache: _Cache = _RedisCache(REDIS_URL)
    logger.info("Using Redis cache")
else:
    cache = _InMemoryCache()
    logger.info("Using in-memory cache")


@app.get("/health")
def health() -> Dict[str, str]:
    logger.info("Health check requested")
    return {"status": "ok"}


@app.post("/analyze-login", response_model=AnalyzeResponse)
def analyze_login(event: LoginEvent) -> AnalyzeResponse:
    logger.info(
        "Analyze single login: user=%s country=%s device=%s hour=%s failed_attempts=%s",
        event.user,
        event.country,
        event.device,
        event.hour,
        event.failed_attempts,
    )
    features = _build_features(event, categories)
    prediction = model.predict(features)[0]
    is_anomaly = True if prediction == -1 else False

    if not is_anomaly:
        logger.info("Single login result: normal")
        return AnalyzeResponse(
            is_anomaly=False,
            attack_type=None,
            severity=None,
            explanation=None,
            recommended_fix=None,
        )

    query = f"login attack with {event.failed_attempts} failed attempts"
    context = _retrieve_context(query, collection, embed_model)

    prompt = f"""
You are a cybersecurity SOC analyst.

Use the security knowledge below to analyze the login event.

Security Knowledge:
{context}

Login Event:
User: {event.user}
Country: {event.country}
Device: {event.device}
Hour: {event.hour}
Failed Attempts: {event.failed_attempts}

Respond ONLY in valid JSON with these keys:
attack_type, severity, explanation, recommended_fix
"""

    cache_key = _cache_key_for_prompt(prompt)
    llm_result = cache.get(cache_key)
    if llm_result is None:
        try:
            llm_result = _ask_llm(prompt)
            cache.set(cache_key, llm_result, CACHE_TTL_SECONDS)
        except Exception as exc:
            logger.warning("LLM/RAG failed for single login: %s", exc)
            llm_result = {}

    logger.info("Single login result: anomaly")
    return AnalyzeResponse(
        is_anomaly=True,
        attack_type=llm_result.get("attack_type"),
        severity=llm_result.get("severity"),
        explanation=llm_result.get("explanation"),
        recommended_fix=llm_result.get("recommended_fix"),
    )


@app.post("/analyze-logs", response_model=AnalyzeLogsResponse)
def analyze_logs(
    limit: int = Query(10, ge=1, le=1000),
    explain: bool = Query(True),
    min_failed_attempts: int = Query(0, ge=0),
) -> AnalyzeLogsResponse:
    logger.info(
        "Analyze logs batch: limit=%s explain=%s min_failed_attempts=%s",
        limit,
        explain,
        min_failed_attempts,
    )
    df = pd.read_csv(LOGS_PATH)

    df["country_code"] = df["country"].astype("category").cat.codes
    df["device_code"] = df["device"].astype("category").cat.codes
    df["user_code"] = df["user"].astype("category").cat.codes

    features = df[
        [
            "user_code",
            "country_code",
            "device_code",
            "hour",
            "failed_attempts",
        ]
    ]

    df["is_anomaly"] = model.predict(features)
    df["is_anomaly"] = df["is_anomaly"].apply(lambda x: 1 if x == -1 else 0)

    anomalies = df[(df["is_anomaly"] == 1) & (df["failed_attempts"] >= min_failed_attempts)].copy()
    total_anomalies = int(len(anomalies))
    logger.info("Anomalies found: %s", total_anomalies)

    if total_anomalies == 0:
        return AnalyzeLogsResponse(total_anomalies=0, returned=0, items=[])

    anomalies = anomalies.sort_values(by="failed_attempts", ascending=False).head(limit)

    items: list[AnalyzeLogItem] = []
    for _, row in anomalies.iterrows():
        warning = None
        attack_type = None
        severity = None
        explanation = None
        recommended_fix = None

        if explain:
            try:
                query = f"login attack with {row['failed_attempts']} failed attempts"
                context = _retrieve_context(query, collection, embed_model)

                prompt = f"""
You are a cybersecurity SOC analyst.

Use the security knowledge below to analyze the login event.

Security Knowledge:
{context}

Login Event:
User: {row['user']}
Country: {row['country']}
Device: {row['device']}
Hour: {row['hour']}
Failed Attempts: {row['failed_attempts']}

Respond ONLY in valid JSON with these keys:
attack_type, severity, explanation, recommended_fix
"""

                cache_key = _cache_key_for_prompt(prompt)
                llm_result = cache.get(cache_key)
                if llm_result is None:
                    llm_result = _ask_llm(prompt)
                    cache.set(cache_key, llm_result, CACHE_TTL_SECONDS)

                attack_type = llm_result.get("attack_type")
                severity = llm_result.get("severity")
                explanation = llm_result.get("explanation")
                recommended_fix = llm_result.get("recommended_fix")
            except Exception as exc:
                warning = f"LLM/RAG unavailable: {exc}"
                logger.warning(
                    "LLM/RAG failed for user=%s country=%s device=%s hour=%s failed_attempts=%s: %s",
                    row["user"],
                    row["country"],
                    row["device"],
                    row["hour"],
                    row["failed_attempts"],
                    exc,
                )

        items.append(
            AnalyzeLogItem(
                user=row["user"],
                country=row["country"],
                device=row["device"],
                hour=int(row["hour"]),
                failed_attempts=int(row["failed_attempts"]),
                is_anomaly=True,
                attack_type=attack_type,
                severity=severity,
                explanation=explanation,
                recommended_fix=recommended_fix,
                warning=warning,
            )
        )

    return AnalyzeLogsResponse(
        total_anomalies=total_anomalies,
        returned=len(items),
        items=items,
    )
