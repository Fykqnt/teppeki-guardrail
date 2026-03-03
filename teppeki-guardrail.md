# teppeki-guardrail 実装ガイド

FastAPI + Cloud Run + Cloud Memorystore (Redis) による日本語PIIマスキングプロキシサービスの構築手順。

---

## アーキテクチャ概要

```
[Next.js] ──HTTPS + Bearer──▶ [Cloud Run / FastAPI]
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                   [Presidio      [Cloud        [LiteLLM]
                   + GiNZA]    Memorystore]        │
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
│   ├── auth.py              # Bearer トークン認証
│   ├── redis_client.py      # Cloud Memorystore セッション管理
│   ├── llm_client.py        # LiteLLM ラッパー
│   └── models.py            # Pydantic スキーマ
├── redactor/
│   ├── __init__.py
│   ├── redactor.py          # presidio プロジェクトからコピー
│   └── config.py            # presidio プロジェクトからコピー
├── tests/
│   ├── test_chat.py
│   └── test_redactor.py
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

`redactor.py` に以下のシグネチャを持つ `redact_text_with_mapping()` が存在することを確認:

```python
def redact_text_with_mapping(
    text: str,
    existing_mapping: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """
    Args:
        text:             マスク対象テキスト
        existing_mapping: 既存の { "<PERSON_1>": "田中太郎", ... }
                          渡すことでマルチターンのプレースホルダー番号を引き継ぐ
    Returns:
        masked_text:      PIIをプレースホルダーに置換したテキスト
        mapping:          更新済みの PII マッピング
    """
```

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

# LLM
litellm==1.52.0

# Utilities
pydantic==2.9.0
python-dotenv==1.0.1
```

---

## 4. 環境変数

### `.env.example`

```dotenv
# ── 認証 ──────────────────────────────────────────────────────────────────────
# Next.js → guardrail 間の共有シークレット（Secret Manager で管理）
TEPPEKI_PROXY_API_KEY=your-secret-api-key-here

# ── Redis (Cloud Memorystore) ──────────────────────────────────────────────────
REDIS_HOST=10.0.0.x          # VPC 内部 IP（Cloud Memorystore のプライマリエンドポイント）
REDIS_PORT=6379
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
    if token != PROXY_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
```

---

## 7. `app/redis_client.py`

```python
import json
import os
import redis.asyncio as aioredis

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_TTL  = int(os.environ.get("REDIS_TTL_SECONDS", 86400))

redis_client = aioredis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
)


def _key(conversation_id: str) -> str:
    return f"pii:conv:{conversation_id}"


async def load_pii_mapping(conversation_id: str) -> dict[str, str] | None:
    """
    PII マッピングを取得する。
    - キーが存在する: dict を返す（空 dict も含む）
    - キーが存在しない / TTL 失効: None を返す
    None と {} を区別することで TTL 失効を検出できる。
    """
    raw = await redis_client.get(_key(conversation_id))
    if raw is None:
        return None
    return json.loads(raw)


async def save_pii_mapping(conversation_id: str, mapping: dict[str, str]) -> None:
    """PII マッピングを保存し、TTL をリセット（ターンごとに 24 時間延長）。"""
    await redis_client.set(
        _key(conversation_id),
        json.dumps(mapping, ensure_ascii=False),
        ex=REDIS_TTL,
    )


async def delete_pii_mapping(conversation_id: str) -> None:
    """会話削除時などに PII マッピングを即時削除する。"""
    await redis_client.delete(_key(conversation_id))
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

## 9. `app/main.py`

```python
import logging
import os
import re
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status

from app.auth import verify_api_key
from app.llm_client import call_llm
from app.models import ChatRequest, ChatResponse, PIISummary
from app.redis_client import load_pii_mapping, save_pii_mapping
from redactor.redactor import redact_text_with_mapping

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
    redact_text_with_mapping("ウォームアップ")
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

## 10. `Dockerfile`

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

## 11. GCP インフラ構成

### 11-1. Cloud Memorystore (Redis) の作成

```bash
gcloud redis instances create teppeki-redis \
  --size=1 \
  --region=asia-northeast1 \
  --redis-version=redis_7_0 \
  --tier=basic \          # 本番環境では standard（レプリケーション有り）
  --network=default       # Cloud Run と同じ VPC

# プライマリエンドポイント IP を確認
gcloud redis instances describe teppeki-redis \
  --region=asia-northeast1 \
  --format="value(host)"
```

### 11-2. VPC Connector の作成（Cloud Run → Memorystore 通信用）

```bash
gcloud compute networks vpc-access connectors create teppeki-connector \
  --region=asia-northeast1 \
  --network=default \
  --range=10.8.0.0/28
```

### 11-3. イメージのビルドとプッシュ

```bash
gcloud builds submit \
  --tag asia-northeast1-docker.pkg.dev/YOUR_PROJECT/teppeki/guardrail:latest
```

### 11-4. Cloud Run へのデプロイ

```bash
gcloud run deploy teppeki-guardrail \
  --image      asia-northeast1-docker.pkg.dev/YOUR_PROJECT/teppeki/guardrail:latest \
  --region     asia-northeast1 \
  --platform   managed \
  --min-instances 1 \               # GiNZA コールドスタート（3〜8秒）を回避
  --max-instances 10 \
  --memory     2Gi \                # GiNZA モデルに 2GB 必要
  --cpu        2 \
  --timeout    120 \                # LLM バッファリングに備えて 120 秒
  --concurrency 80 \
  --no-allow-unauthenticated \      # 認証は API キーで管理
  --set-env-vars \
    "REDIS_HOST=<MEMORYSTORE_IP>,REDIS_PORT=6379,MAX_HISTORY_MESSAGES=20" \
  --set-secrets \
    "TEPPEKI_PROXY_API_KEY=teppeki-proxy-api-key:latest,\
     GEMINI_API_KEY=gemini-api-key:latest" \
  --vpc-connector teppeki-connector
```

> **Secret Manager に登録しておくシークレット:**
> ```bash
> echo -n "your-secret" | gcloud secrets create teppeki-proxy-api-key --data-file=-
> echo -n "your-key"    | gcloud secrets create gemini-api-key         --data-file=-
> ```

---

## 12. ローカル開発

```bash
# 1. venv セットアップ
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. GiNZA モデルのダウンロード（初回のみ）
python -m spacy download ja_ginza_electra

# 3. Redis をローカルで起動
docker run -d -p 6379:6379 redis:7-alpine

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

## 13. セキュリティチェックリスト

- [ ] `TEPPEKI_PROXY_API_KEY` は Secret Manager で管理（`.env` はコミットしない）
- [ ] Cloud Run は `--no-allow-unauthenticated`（直接アクセス不可）
- [ ] Cloud Memorystore は VPC 内のみアクセス可（パブリック IP 無効）
- [ ] Cloud Memorystore の `in-transit encryption` を有効化
- [ ] LLM API キーはすべて Secret Manager で管理
- [ ] Cloud Run のリクエストログに PII が含まれないことを確認（`LOG_LEVEL=INFO` でリクエストボディは非出力）
- [ ] Artifact Registry のイメージに対して `roles/artifactregistry.reader` のみ付与

---

## 14. 実装順序（推奨）

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
7. Cloud Memorystore + VPC Connector 作成
      ↓
8. Cloud Run デプロイ（min-instances=1 確認）
      ↓
9. Next.js 側の route.ts を修正して E2E テスト
```

---

## 参考：関連ドキュメント

| ファイル | 内容 |
|---|---|
| `teppeki-guardrail-implementation.md` | 統合時の既知の問題と対策（11 issues）、Next.js `route.ts` の変更方法 |
| `teppeki-guardrail.md`（本ファイル） | guardrail サービス本体の実装手順 |
