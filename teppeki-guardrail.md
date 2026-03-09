# teppeki-guardrail 実装ガイド

FastAPI + Cloud Run + Upstash Redis による日本語PIIマスキングプロキシサービスの構築手順。

---

## アーキテクチャ概要

```
[Next.js] ──HTTPS + Bearer──▶ [Cloud Run / FastAPI]
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                   [Presidio      [Upstash      [LiteLLM]
                   + GiNZA]       Redis]            │
                   マスキング    PIIマッピング   Gemini / OpenAI
                                  保存/取得    / Anthropic
                         └────────────┼────────────┘
                                      ▼
                              { reply, pii_summary }
```

**処理フロー:**
1. Next.js から `{ conversation_id, messages, model }` を受信
2. Redis から既存 PII マッピングをロード
3. user / assistant メッセージを全件再マスク（Presidio + GiNZA）
4. マスク済みメッセージで LLM を呼び出し（バッファリング）
5. LLM 成功後、更新済み PII マッピングを Redis に保存（TTL リセット）
6. LLM 応答をアンマスクして `{ reply, pii_summary }` を返却

---

## 1. ディレクトリ構成

```
teppeki-guardrail/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI エントリーポイント・/chat エンドポイント
│   ├── auth.py              # Bearer トークン認証（hmac.compare_digest）
│   ├── masking.py           # マルチターン PII マスキングラッパー
│   ├── redis_client.py      # Upstash Redis セッション管理 + 暗号化
│   ├── llm_client.py        # LiteLLM ラッパー
│   └── models.py            # Pydantic スキーマ
├── redactor/
│   ├── __init__.py
│   ├── redactor.py          # presidio プロジェクトからコピー（解析パイプライン）
│   └── config.py            # presidio プロジェクトからコピー（閾値・パターン）
├── scripts/
│   └── mask_test.py         # マスキング動作確認スクリプト
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## 2. `redactor/` のセットアップ

既存の presidio プロジェクトから最新版をコピーする:

```bash
cp /path/to/presidio/redactor/redactor.py teppeki-guardrail/redactor/redactor.py
cp /path/to/presidio/redactor/config.py   teppeki-guardrail/redactor/config.py
```

`redactor/redactor.py` は解析パイプラインの低レベル関数（`setup_analyzer`, `filter_common_words`, `_merge_ginza_boost_results` 等）を提供する。これらを `app/masking.py` がラップし、マルチターン対応の `redact_text_with_mapping()` を公開する（セクション 9 参照）。

---

## 3. `requirements.txt`

```txt
# Web framework
fastapi==0.115.0
uvicorn[standard]==0.32.0

# PII detection
presidio-analyzer==2.2.355
presidio-anonymizer==2.2.355
ginza==5.2.0
ja-ginza-electra==5.2.0

# Redis
redis[hiredis]==5.2.0
upstash-redis>=1.0.0

# LLM
litellm==1.52.0

# Utilities
pydantic==2.9.0
python-dotenv==1.0.1
cryptography>=42.0.0
```

---

## 4. 環境変数

### `.env.example`

```dotenv
# ── 認証 ──────────────────────────────────────────────────────────────────────
# Next.js → guardrail 間の共有シークレット（Secret Manager で管理）
TEPPEKI_PROXY_API_KEY=your-secret-api-key-here

# ── Redis (Upstash) ──────────────────────────────────────────────────────────
# 本番: Upstash Redis（サーバーレス、VPC 不要、0 リクエスト時はほぼ $0）
UPSTASH_REDIS_REST_URL=https://xxx.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-upstash-token
# Upstash 保存時の暗号化（推奨）: 設定すると PII マッピングを AES 暗号化して保存
# 生成: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# PII_MAPPING_ENCRYPTION_KEY=your-fernet-key
# ローカル開発: REDIS_HOST/REDIS_PORT を設定すると docker redis を使用
# REDIS_HOST=localhost
# REDIS_PORT=6379
REDIS_TTL_SECONDS=86400      # PIIマッピングの保持期間（デフォルト 24 時間）

# ── LLM プロバイダー（LiteLLM 経由）──────────────────────────────────────────
GEMINI_API_KEY=your-gemini-api-key
OPENAI_API_KEY=your-openai-api-key          # 任意
ANTHROPIC_API_KEY=your-anthropic-api-key    # 任意

# ── アプリ設定 ────────────────────────────────────────────────────────────────
LOG_LEVEL=INFO
MAX_MESSAGE_LENGTH=10000     # 1メッセージあたりの最大文字数
MAX_HISTORY_MESSAGES=20      # LLMに渡す直近の会話件数（コンテキストウィンドウ制御）
```

---

## 5. `app/models.py`

```python
from pydantic import BaseModel, Field


class Message(BaseModel):
    role: str    # "user" | "assistant" | "system"
    content: str


class ChatRequest(BaseModel):
    conversation_id: str = Field(..., description="Supabase chat.id（UUID v4）")
    messages: list[Message] = Field(..., min_length=1)
    model: str = Field(default="gemini/gemini-3-flash-preview")


class TokenUsage(BaseModel):
    input: int
    output: int


class PIISummary(BaseModel):
    pii_count: int
    entity_types: list[str]
    tokens_used: TokenUsage


class ChatResponse(BaseModel):
    reply: str
    pii_summary: PIISummary
```

---

## 6. `app/auth.py`

```python
import hmac
import os
from fastapi import Header, HTTPException, status

PROXY_API_KEY = os.environ["TEPPEKI_PROXY_API_KEY"]


async def verify_api_key(authorization: str = Header(...)) -> None:
    """Authorization: Bearer <token> を検証する。"""
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must start with 'Bearer '",
        )
    token = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(token, PROXY_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
```

---

## 7. `app/redis_client.py`

Upstash 使用時、`PII_MAPPING_ENCRYPTION_KEY` を設定すると **保存時のみ暗号化** する。復号は読み込み時のみ。UX（マスキングのビフォーアフター）に変化はない。鍵が設定されているが無効な場合は起動時に `ValueError` で失敗する（サイレントフォールバックを防止）。

```python
"""
PII mapping storage: Upstash Redis (production) or local Redis (development).
Upstash + PII_MAPPING_ENCRYPTION_KEY 時は保存前に暗号化、読み込み後に復号。
"""
import base64
import json
import os
from cryptography.fernet import Fernet, InvalidToken

REDIS_TTL = int(os.environ.get("REDIS_TTL_SECONDS", 86400))
UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
ENCRYPTION_KEY = os.environ.get("PII_MAPPING_ENCRYPTION_KEY")

if UPSTASH_URL and UPSTASH_TOKEN:
    from upstash_redis.asyncio import Redis
    _redis = Redis(url=UPSTASH_URL, token=UPSTASH_TOKEN)
    _use_upstash = True
else:
    import redis.asyncio as aioredis
    REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
    _redis = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    _use_upstash = False

# 鍵が設定されているが無効な場合は起動時に失敗
if ENCRYPTION_KEY and _use_upstash:
    key_bytes = ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
    try:
        _fernet = Fernet(key_bytes)
    except Exception:
        if len(key_bytes) == 32:
            try:
                _fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
            except Exception:
                _fernet = None
        else:
            _fernet = None
    if _fernet is None:
        raise ValueError("PII_MAPPING_ENCRYPTION_KEY is set but invalid. Generate with: "
                         "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')\"")
else:
    _fernet = None


def _encrypt(plain: str) -> str:
    if _fernet is None:
        return plain
    return _fernet.encrypt(plain.encode()).decode()


def _decrypt(cipher: str) -> str:
    if _fernet is None:
        return cipher
    try:
        return _fernet.decrypt(cipher.encode()).decode()
    except (InvalidToken, ValueError):
        return cipher  # 移行前の平文データ


def _key(conversation_id: str) -> str:
    return f"pii:conv:{conversation_id}"


async def load_pii_mapping(conversation_id: str) -> dict[str, str] | None:
    raw = await _redis.get(_key(conversation_id))
    if raw is None:
        return None
    return json.loads(_decrypt(raw))


async def save_pii_mapping(conversation_id: str, mapping: dict[str, str]) -> None:
    plain = json.dumps(mapping, ensure_ascii=False)
    await _redis.set(_key(conversation_id), _encrypt(plain), ex=REDIS_TTL)


async def delete_pii_mapping(conversation_id: str) -> None:
    await _redis.delete(_key(conversation_id))
```

---

## 8. `app/llm_client.py`

```python
import litellm
from app.models import Message, TokenUsage


async def call_llm(model: str, messages: list[Message]) -> tuple[str, TokenUsage]:
    """
    LiteLLM 経由で LLM を呼び出す。
    stream=False でフルバッファリングし、アンマスクの前に完全な応答を得る。
    """
    response = await litellm.acompletion(
        model=model,
        messages=[{"role": m.role, "content": m.content} for m in messages],
        stream=False,
    )
    reply_text = response.choices[0].message.content or ""
    usage = TokenUsage(
        input=response.usage.prompt_tokens,
        output=response.usage.completion_tokens,
    )
    return reply_text, usage
```

---

## 9. `app/masking.py`

`redactor/redactor.py` の低レベル関数をラップし、マルチターン対応の PII マスキング API を提供する。`warmup()` で GiNZA モデルを事前ロードし、`redact_text_with_mapping()` で既存マッピングを引き継いだプレースホルダー番号の一貫性を保証する。

```python
"""
Multi-turn PII masking wrapper around redactor.redactor.

Provides a simplified API for the /chat endpoint:
  redact_text_with_mapping(text, existing_mapping) -> (masked_text, mapping)

The mapping dict uses the format {"<PERSON_1>": "田中太郎", ...} where
placeholder numbers are consistent across turns via existing_mapping.
"""

import re

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from redactor import config
from redactor.redactor import (
    setup_analyzer,
    filter_common_words,
    _get_doc_for_pos,
    _merge_ginza_boost_results,
    _split_location_containing_organization,
    _add_context_based_organization_candidates,
    _add_romaji_person_candidates,
    _add_context_based_password_candidates,
    _boost_scores_when_nearby_same_entity,
    _extend_id_and_secret_to_next_space,
)

# Module-level singletons (initialized during warmup)
_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


def warmup() -> None:
    """GiNZA モデルをロードして初回解析を実行する（コールドスタート回避）。"""
    global _analyzer, _anonymizer
    _analyzer = setup_analyzer()
    _anonymizer = AnonymizerEngine()
    # ウォームアップ（GiNZA の遅延ロードを強制）
    redact_text_with_mapping("ウォームアップ")


def _build_operators(
    existing_mapping: dict[str, str] | None,
) -> tuple[dict, dict[str, str]]:
    """
    既存マッピングと整合するカスタムオペレーターを構築する。

    Returns:
        operators:    Presidio AnonymizerEngine 用オペレーター dict
        new_mapping:  更新済みマッピング {"<PERSON_1>": "田中太郎", ...}
    """
    # 逆引き: 元テキスト -> プレースホルダー
    reverse_map: dict[str, str] = {}
    # エンティティ別カウンター: entity_type -> 最大インデックス
    entity_counters: dict[str, int] = {}

    if existing_mapping:
        for placeholder, original in existing_mapping.items():
            reverse_map[original] = placeholder
            m = re.match(r"<([A-Z_]+)_(\d+)>", placeholder)
            if m:
                entity_type = m.group(1)
                index = int(m.group(2))
                entity_counters[entity_type] = max(
                    entity_counters.get(entity_type, 0), index
                )

    new_mapping: dict[str, str] = dict(existing_mapping) if existing_mapping else {}

    def create_operator(entity_type: str):
        def operator(old_value: str, **kwargs) -> str:
            val = old_value.strip()
            # 既知の PII → 既存プレースホルダーを再利用
            if val in reverse_map:
                return reverse_map[val]
            # 新規 PII → 次の番号を割り当て
            current = entity_counters.get(entity_type, 0)
            new_index = current + 1
            entity_counters[entity_type] = new_index
            placeholder = f"<{entity_type}_{new_index}>"
            reverse_map[val] = placeholder
            new_mapping[placeholder] = val
            return placeholder

        return operator

    operators = {}
    for entity in config.TARGET_ENTITIES:
        operators[entity] = OperatorConfig(
            "custom", {"lambda": create_operator(entity)}
        )

    return operators, new_mapping


def _run_analysis(text: str):
    """Presidio 解析 + GiNZA ブースト + フィルタリングの全パイプラインを実行する。"""
    results = _analyzer.analyze(
        text=text,
        language="ja",
        entities=config.TARGET_ENTITIES,
        allow_list=config.ALLOW_LIST,
        score_threshold=config.DEFAULT_SCORE_THRESHOLD,
    )
    doc = _get_doc_for_pos(text)
    results = _merge_ginza_boost_results(results, doc)
    results = _split_location_containing_organization(results, text)
    results = _add_context_based_organization_candidates(text, results)
    results = _add_romaji_person_candidates(text, results)
    results = _add_context_based_password_candidates(text, results)
    results = _boost_scores_when_nearby_same_entity(results, text)
    results = _extend_id_and_secret_to_next_space(results, text)
    results = filter_common_words(results, text, doc=doc)
    return results


def redact_text_with_mapping(
    text: str,
    existing_mapping: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """
    テキスト中の PII をマスクし、マッピングを返す。

    Args:
        text:             マスク対象テキスト
        existing_mapping: 既存の {"<PERSON_1>": "田中太郎", ...}
                          渡すことでマルチターンのプレースホルダー番号を引き継ぐ
    Returns:
        masked_text:      PII をプレースホルダーに置換したテキスト
        mapping:          更新済みの PII マッピング
    """
    results = _run_analysis(text)
    operators, mapping = _build_operators(existing_mapping)
    anonymized = _anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators,
    )
    return anonymized.text, mapping
```

---

## 10. `app/main.py`

```python
import logging
import os
import re
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()  # ローカル: .env を読み込む / Cloud Run: 既に設定済みなので no-op

from fastapi import Depends, FastAPI, HTTPException, status

from app.auth import verify_api_key
from app.llm_client import call_llm
from app.masking import redact_text_with_mapping, warmup
from app.models import ChatRequest, ChatResponse, PIISummary
from app.redis_client import load_pii_mapping, save_pii_mapping

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

MAX_MESSAGE_LENGTH  = int(os.environ.get("MAX_MESSAGE_LENGTH", 10000))
MAX_HISTORY_MESSAGES = int(os.environ.get("MAX_HISTORY_MESSAGES", 20))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    アプリ起動時に GiNZA モデルをロードしてウォームアップする。
    min-instances=1 と組み合わせることでコールドスタートを回避する。
    """
    logger.info("Loading GiNZA model...")
    warmup()
    logger.info("GiNZA model ready.")
    yield


app = FastAPI(title="teppeki-guardrail", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post(
    "/chat",
    response_model=ChatResponse,
    dependencies=[Depends(verify_api_key)],
)
async def chat(req: ChatRequest) -> ChatResponse:

    # ── 1. 入力バリデーション ──────────────────────────────────────────────────
    for msg in req.messages:
        if len(msg.content) > MAX_MESSAGE_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Message exceeds {MAX_MESSAGE_LENGTH} chars",
            )

    # ── 2. Redis から PII マッピングをロード ───────────────────────────────────
    # None = TTL 失効または未存在、{} = 新規会話
    stored = await load_pii_mapping(req.conversation_id)
    has_history = any(m.role == "assistant" for m in req.messages)

    if stored is None and has_history:
        # TTL 失効: プレースホルダー番号の整合性が保証できない
        # → フロントエンドに会話リセットを促す
        raise HTTPException(status_code=409, detail="session_expired")

    pii_mapping: dict[str, str] = stored or {}

    # ── 3. 会話履歴を直近 N 件にトリム（コンテキストウィンドウ・コスト制御）──
    system_msgs  = [m for m in req.messages if m.role == "system"]
    history_msgs = [m for m in req.messages if m.role != "system"]
    messages_to_process = system_msgs + history_msgs[-MAX_HISTORY_MESSAGES:]

    # ── 4. user・assistant を全件再マスク（system はそのまま通す）────────────
    masked_messages = []
    for msg in messages_to_process:
        if msg.role in ("user", "assistant"):
            masked_text, pii_mapping = redact_text_with_mapping(
                msg.content,
                existing_mapping=pii_mapping,
            )
            masked_messages.append(msg.model_copy(update={"content": masked_text}))
        else:
            masked_messages.append(msg)

    # ── 5. エンティティ種別を収集 ─────────────────────────────────────────────
    entity_types: set[str] = set()
    for placeholder in pii_mapping:
        m = re.match(r"<([A-Z_]+)_\d+>", placeholder)
        if m:
            entity_types.add(m.group(1))

    # ── 6. LLM 呼び出し（Redis 保存は成功後に行う）────────────────────────────
    try:
        masked_reply, token_usage = await call_llm(req.model, masked_messages)
    except Exception as e:
        logger.error(f"LLM error: {e}")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="LLM provider error")

    # ── 7. PII マッピングを Redis に保存（TTL リセット）───────────────────────
    await save_pii_mapping(req.conversation_id, pii_mapping)

    # ── 8. アンマスク ─────────────────────────────────────────────────────────
    reply = masked_reply
    for placeholder, original in pii_mapping.items():
        reply = reply.replace(placeholder, original)

    logger.info(
        f"conv={req.conversation_id} pii={len(pii_mapping)} "
        f"tokens={token_usage.input}+{token_usage.output}"
    )

    return ChatResponse(
        reply=reply,
        pii_summary=PIISummary(
            pii_count=len(pii_mapping),
            entity_types=sorted(entity_types),
            tokens_used=token_usage,
        ),
    )
```

---

## 11. `Dockerfile`

```dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# GiNZA モデルをビルド時にダウンロード（実行時コールドスタートを排除）
RUN python -c "import spacy; spacy.load('ja_ginza_electra')"

COPY . .

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

---

## 12. インフラ構成

### 12-1. Upstash Redis の作成

1. [Upstash Console](https://console.upstash.com/) でアカウント作成
2. **Create Database** → **Global** または **Regional** を選択
3. 作成後、**REST API** タブから **UPSTASH_REDIS_REST_URL** と **UPSTASH_REDIS_REST_TOKEN** を取得

> **無料枠:** 500K commands/月、256MB、10GB 帯域。0 リクエスト時はほぼ $0。

### 12-1-1. Upstash 保存時の暗号化（推奨）

PII マッピング（`{"<PERSON_1>": "田中太郎", ...}`）を Upstash に平文で保存すると、Upstash 側で漏洩した場合に生の顧客情報が露出する。`PII_MAPPING_ENCRYPTION_KEY` を設定すると、**保存時のみ AES 暗号化**し、読み込み時に復号する。

- **UX への影響:** なし（マスキングのビフォーアフター、応答内容は同一）
- **暗号化範囲:** Upstash Redis に送受信するペイロードのみ
- **鍵生成:** `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

### 12-2. イメージのビルドとプッシュ

```bash
gcloud builds submit \
  --tag asia-northeast1-docker.pkg.dev/YOUR_PROJECT/teppeki/guardrail:latest
```

### 12-3. Cloud Run へのデプロイ

```bash
gcloud run deploy teppeki-guardrail \
  --image      asia-northeast1-docker.pkg.dev/YOUR_PROJECT/teppeki/guardrail:latest \
  --region     asia-northeast1 \
  --platform   managed \
  --min-instances 0 \                # コスト削減。初回リクエストで 3〜8 秒のコールドスタートあり
  --max-instances 2 \                # 100 users 規模に最適化
  --memory     2Gi \                # GiNZA モデルに 2GB 必要
  --cpu        2 \
  --timeout    120 \                # LLM バッファリングに備えて 120 秒
  --concurrency 80 \
  --no-allow-unauthenticated \      # 認証は API キーで管理
  --set-env-vars \
    "UPSTASH_REDIS_REST_URL=<YOUR_UPSTASH_URL>,MAX_HISTORY_MESSAGES=20" \
  --set-secrets \
    "TEPPEKI_PROXY_API_KEY=teppeki-proxy-api-key:latest,\
     GEMINI_API_KEY=gemini-api-key:latest,\
     UPSTASH_REDIS_REST_TOKEN=upstash-redis-token:latest,\
     PII_MAPPING_ENCRYPTION_KEY=pii-encryption-key:latest"
```

> **VPC Connector が不要:** Upstash は HTTPS でアクセスするため、VPC 不要。月約 $65 削減。

> **Secret Manager に登録しておくシークレット:**
> ```bash
> echo -n "your-secret" | gcloud secrets create teppeki-proxy-api-key --data-file=-
> echo -n "your-key"    | gcloud secrets create gemini-api-key         --data-file=-
> echo -n "your-token"  | gcloud secrets create upstash-redis-token    --data-file=-
> # PII 暗号化鍵（Fernet 形式）を生成して登録
> KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')")
> echo -n "$KEY" | gcloud secrets create pii-encryption-key --data-file=-
> ```

---

## 13. ローカル開発

```bash
# 1. venv セットアップ
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. GiNZA モデルのダウンロード（初回のみ）
python -m spacy download ja_ginza_electra

# 3. Redis（ローカル開発）
# オプション A: docker redis を使用（REDIS_HOST=localhost がデフォルト）
docker run -d -p 6379:6379 redis:7-alpine
# オプション B: Upstash の URL/Token を .env に設定（本番と同じ）

# 4. 環境変数
cp .env.example .env
# REDIS_HOST=localhost、各APIキーを設定

# 5. サーバー起動
uvicorn app.main:app --reload --port 8080

# 6. 動作確認
curl -s -X POST http://localhost:8080/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-api-key-here" \
  -d '{
    "conversation_id": "550e8400-e29b-41d4-a716-446655440000",
    "messages": [
      {"role": "system",    "content": "あなたは丁寧なアシスタントです。"},
      {"role": "user",      "content": "田中太郎です。090-1234-5678に電話してください。"}
    ],
    "model": "gemini/gemini-3-flash-preview"
  }' | jq .
```

**期待レスポンス:**
```json
{
  "reply": "田中太郎様、090-1234-5678 にご連絡いたします。",
  "pii_summary": {
    "pii_count": 2,
    "entity_types": ["PERSON", "PHONE_NUMBER"],
    "tokens_used": { "input": 42, "output": 28 }
  }
}
```

---

## 14. セキュリティチェックリスト

- [ ] `TEPPEKI_PROXY_API_KEY` は Secret Manager で管理（`.env` はコミットしない）
- [ ] Cloud Run は `--no-allow-unauthenticated`（直接アクセス不可）
- [ ] Upstash Redis のトークンは Secret Manager で管理（本番環境推奨）
- [ ] `PII_MAPPING_ENCRYPTION_KEY` を設定し、Upstash 保存時の暗号化を有効化（推奨）
- [ ] LLM API キーはすべて Secret Manager で管理
- [ ] Cloud Run のリクエストログに PII が含まれないことを確認（`LOG_LEVEL=INFO` でリクエストボディは非出力）
- [ ] Artifact Registry のイメージに対して `roles/artifactregistry.reader` のみ付与

---

## 15. 実装順序（推奨）

```
1. redactor/ コピー
      ↓
2. requirements.txt + Dockerfile ビルド確認
      ↓
3. app/models.py + app/auth.py
      ↓
4. app/redis_client.py → ローカル Redis で load/save 確認
      ↓
5. app/llm_client.py → LiteLLM で Gemini 疎通確認
      ↓
6. app/main.py → /chat エンドポイント統合テスト（curl）
      ↓
7. Upstash Redis 作成（Console で URL/Token 取得）
      ↓
8. Cloud Run デプロイ（VPC 不要、min-instances=0, max-instances=2）
      ↓
9. Next.js 側の route.ts を修正して E2E テスト
```

---

## 参考：関連ドキュメント

| ファイル | 内容 |
|---|---|
| `teppeki-guardrail-implementation.md` | 統合時の既知の問題と対策（11 issues）、Next.js `route.ts` の変更方法 |
| `teppeki-guardrail.md`（本ファイル） | guardrail サービス本体の実装手順 |
