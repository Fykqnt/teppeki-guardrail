# teppeki-guardrail 実装指示書

## 概要

`teppeki-guardrail` は、鉄壁AIチャット（Next.js）とLLMプロバイダーの間に置くPIIマスキング・アンマスキングプロキシサービスです。

> **ドキュメント構成:** 本ファイルは Next.js chat-ui との統合手順・既知の問題と対策。guardrail サービス本体の構築は `teppeki-guardrail.md` を参照。

**アーキテクチャ:**
```
[Next.js] → (HTTPS + Bearer) → [teppeki-guardrail / FastAPI on Cloud Run]
                                        ↓ mask
                                    [Presidio + GiNZA]
                                        ↓ store mapping
                                    [Upstash Redis]
                                        ↓ call LLM
                                    [Gemini / OpenAI / Anthropic]
                                        ↓ unmask response
                                → { reply, pii_summary }
```

**基本方針:**
- プロキシ側でLLM応答を完全バッファリングし、アンマスク後にJSONで返す
- フロントエンド（Next.js）側でReadableStreamを使ってタイプライター効果を模擬
- Redis（Upstash）でセッション（conversation_id）ごとのPIIマッピングを管理（VPC 不要、0 リクエスト時はほぼ $0）
- min-instances=0 でコスト削減（初回リクエストで 3〜8 秒のコールドスタートあり）

---

## 1. ディレクトリ構成

```
teppeki-guardrail/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI エントリーポイント・/chat エンドポイント
│   ├── auth.py              # Bearer トークン認証（hmac.compare_digest）
│   ├── masking.py           # マルチターン PII マスキングラッパー（redactor をラップ）
│   ├── redis_client.py      # Upstash Redis セッション管理 + 暗号化
│   ├── llm_client.py        # LiteLLM ラッパー
│   └── models.py            # Pydantic スキーマ
├── redactor/
│   ├── __init__.py
│   ├── redactor.py          # presidio プロジェクトからコピー（解析パイプライン低レベル関数）
│   └── config.py            # presidio プロジェクトからコピー（閾値・パターン）
├── scripts/
│   └── mask_test.py         # マスキング動作確認スクリプト
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## 2. `redactor/` のセットアップ

presidio プロジェクトの最新版をコピー:

```bash
cp /path/to/presidio/redactor/redactor.py teppeki-guardrail/redactor/redactor.py
cp /path/to/presidio/redactor/config.py   teppeki-guardrail/redactor/config.py
```

`redactor/redactor.py` は解析パイプラインの低レベル関数（`setup_analyzer`, `filter_common_words`, `_merge_ginza_boost_results` 等）を提供する。これらを `app/masking.py` がラップし、マルチターン対応の `redact_text_with_mapping()` を公開する。

`app/masking.py` の公開 API:

```python
def redact_text_with_mapping(
    text: str,
    existing_mapping: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """
    Returns:
        masked_text: PII をプレースホルダーに置換したテキスト
        mapping: { "<PERSON_1>": "田中太郎", ... }
    """
```

> **注意:** `existing_mapping` を渡すことで、会話履歴全体を同じプレースホルダーで再マスクできます（マルチターン一貫性）。

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

# PII 暗号化（Upstash 保存時）
cryptography>=42.0.0

# LLM
litellm==1.52.0
# cp312 wheel あり（Rust ビルド回避）。litellm が 0.13.x を引くため明示
tokenizers>=0.15.0

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

# ── Redis (Upstash) ───────────────────────────────────────────────────────────
# 本番: Upstash Redis（https://console.upstash.com/ で作成）
UPSTASH_REDIS_REST_URL=https://xxx.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-upstash-token
# Upstash 保存時の暗号化（推奨）: 設定すると PII マッピングを AES 暗号化して保存
# 生成: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')"
# PII_MAPPING_ENCRYPTION_KEY=your-fernet-key
# ローカル開発: 上記が未設定の場合は REDIS_HOST/REDIS_PORT で docker redis を使用
# REDIS_HOST=localhost
# REDIS_PORT=6379
REDIS_TTL_SECONDS=86400

# ── LLM プロバイダー（LiteLLM 経由）──────────────────────────────────────────
GEMINI_API_KEY=your-gemini-api-key
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key

# ── アプリ設定 ───────────────────────────────────────────────────────────────
LOG_LEVEL=INFO
MAX_MESSAGE_LENGTH=10000
MAX_HISTORY_MESSAGES=20   # コンテキストウィンドウ制御（issue 7）
```

Cloud Run にはSecret Managerでマウントするか、環境変数として設定します。

---

## 5. `app/models.py`

```python
from pydantic import BaseModel, Field


class Message(BaseModel):
    role: str  # "user" | "assistant" | "system"
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

Upstash 使用時、`PII_MAPPING_ENCRYPTION_KEY` を設定すると **保存時のみ暗号化** する。復号は読み込み時のみ。UX（マスキングのビフォーアフター）に変化はない。鍵が設定されているが無効な場合は起動時に `ValueError` で失敗する。

```python
"""
PII mapping storage: Upstash Redis (production) or local Redis (development).
Upstash: Serverless, pay-per-command. No VPC required. ~$0 when idle.
When PII_MAPPING_ENCRYPTION_KEY is set, PII mapping is encrypted at rest in Upstash.
Local: REDIS_HOST/REDIS_PORT for docker redis (no encryption).
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
        raise ValueError(
            "PII_MAPPING_ENCRYPTION_KEY is set but invalid. "
            'Generate with: python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode(), end=\'\')"'
        )
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
    """
    PII マッピングを取得する。
    - キーが存在する: dict を返す（空 dict も含む）
    - キーが存在しない / TTL 失効: None を返す
    None と {} を区別することで TTL 失効を検出できる。
    """
    raw = await _redis.get(_key(conversation_id))
    if raw is None:
        return None
    raw = _decrypt(raw)
    return json.loads(raw)


async def save_pii_mapping(conversation_id: str, mapping: dict[str, str]) -> None:
    """PII マッピングを保存し、TTL をリセット（ターンごとに 24 時間延長）。"""
    plain = json.dumps(mapping, ensure_ascii=False)
    payload = _encrypt(plain)
    await _redis.set(_key(conversation_id), payload, ex=REDIS_TTL)


async def delete_pii_mapping(conversation_id: str) -> None:
    await _redis.delete(_key(conversation_id))
```

> **競合状態の対策:** 同一会話への同時リクエストは想定しない（チャットUIはリクエスト完了まで次の送信をブロック）。もし必要な場合は `redis_client.setnx` + Luaスクリプトで楽観的ロックを実装してください。

---

## 8. `app/llm_client.py`

```python
import litellm
from app.models import Message, TokenUsage


async def call_llm(
    model: str,
    messages: list[Message],
) -> tuple[str, TokenUsage]:
    """
    LiteLLM経由でLLMを呼び出し、応答テキストとトークン使用量を返す。
    ストリーミングは使用しない（プロキシ側でフルバッファリング）。
    """
    litellm_messages = [
        {"role": m.role, "content": m.content} for m in messages
    ]

    response = await litellm.acompletion(
        model=model,
        messages=litellm_messages,
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

下記コードは全ての既知の問題（issue 1〜11）の修正を反映した最終版です。

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

MAX_MESSAGE_LENGTH = int(os.environ.get("MAX_MESSAGE_LENGTH", 10000))
MAX_HISTORY_MESSAGES = int(os.environ.get("MAX_HISTORY_MESSAGES", 20))


# ── GiNZA モデルをアプリ起動時に1回だけロード（コールドスタート回避）────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
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
    # ── 1. バリデーション ─────────────────────────────────────────────────────
    for msg in req.messages:
        if len(msg.content) > MAX_MESSAGE_LENGTH:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Message exceeds {MAX_MESSAGE_LENGTH} chars",
            )

    # ── 2. Redisから既存PIIマッピングをロード ──────────────────────────────────
    # load_pii_mapping は None（TTL失効）と {} （新規）を区別して返す（issue 3）
    stored_mapping = await load_pii_mapping(req.conversation_id)
    has_assistant_history = any(m.role == "assistant" for m in req.messages)

    if stored_mapping is None and has_assistant_history:
        # TTL失効: 既存の会話履歴があるのにマッピングが消えている
        # プレースホルダーの整合性が保証できないため、会話リセットを促す（issue 3）
        raise HTTPException(
            status_code=409,
            detail="session_expired",
        )

    pii_mapping: dict[str, str] = stored_mapping or {}

    # ── 3. system / 会話履歴を分離し、履歴を直近N件にトリム（issue 7）─────────
    system_messages = [m for m in req.messages if m.role == "system"]
    history_messages = [m for m in req.messages if m.role != "system"]
    trimmed_history = history_messages[-MAX_HISTORY_MESSAGES:]
    messages_to_process = system_messages + trimmed_history

    # ── 4. user・assistant 両方を再マスク（issue 1）──────────────────────────
    masked_messages = []
    for msg in messages_to_process:
        if msg.role in ("user", "assistant"):
            masked_text, pii_mapping = redact_text_with_mapping(
                msg.content,
                existing_mapping=pii_mapping,
            )
            masked_messages.append(msg.model_copy(update={"content": masked_text}))
        else:
            # system メッセージはマスクしない（プロンプトの指示文を保護）
            masked_messages.append(msg)

    # ── 5. エンティティ種別を収集（issue 5: ループ外で1回だけ）────────────────
    entity_types: set[str] = set()
    for placeholder in pii_mapping:
        match = re.match(r"<([A-Z_]+)_\d+>", placeholder)
        if match:
            entity_types.add(match.group(1))

    # ── 6. LLM呼び出し（ストリーミングなし、フルバッファリング）─────────────
    #        Redis保存はLLM成功後に行う（issue 10: 失敗時ロールバック不要にする）
    try:
        masked_reply, token_usage = await call_llm(req.model, masked_messages)
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LLM provider error",
        )

    # ── 7. LLM成功後にPIIマッピングをRedisに保存（TTLリセット）（issue 10）──
    await save_pii_mapping(req.conversation_id, pii_mapping)

    # ── 8. アンマスク（issue 6: 位置ベース置換は redact 側で担保済み）────────
    unmasked_reply = masked_reply
    for placeholder, original in pii_mapping.items():
        unmasked_reply = unmasked_reply.replace(placeholder, original)

    # ── 9. PII統計を構築 ─────────────────────────────────────────────────────
    pii_summary = PIISummary(
        pii_count=len(pii_mapping),
        entity_types=sorted(entity_types),
        tokens_used=token_usage,
    )

    logger.info(
        f"conversation_id={req.conversation_id} "
        f"pii_count={pii_summary.pii_count} "
        f"tokens={token_usage.input}+{token_usage.output}"
    )

    return ChatResponse(reply=unmasked_reply, pii_summary=pii_summary)
```

---

## 10. `Dockerfile`

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# tokenizers>=0.15 は cp312 wheel あり。SudachiPy は linux-aarch64 wheel なし → Rust でソースビルド
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# GiNZA Electra が参照する HuggingFace モデルを Transformers のキャッシュ形式で事前取得
ENV HF_HOME=/opt/hf
ENV TRANSFORMERS_CACHE=/opt/hf/transformers
ENV HF_HUB_CACHE=/opt/hf/hub

# 古い transformers が HF API のリダイレクトを処理できないバグをモンキーパッチで回避
RUN mkdir -p /opt/hf/transformers /opt/hf/hub \
    && python -c "\
import requests; \
_orig = requests.Session.request; \
requests.Session.request = lambda self, method, url, *args, **kwargs: _orig(self, method, 'https://huggingface.co' + url if isinstance(url, str) and url.startswith('/') else url, *args, **kwargs); \
from transformers import AutoConfig, AutoModel; \
AutoConfig.from_pretrained('megagonlabs/transformers-ud-japanese-electra-base-ginza-510'); \
AutoModel.from_pretrained('megagonlabs/transformers-ud-japanese-electra-base-ginza-510'); \
"

# 実行時に HF API へ更新確認に行って MissingSchema エラーが再発するのを防ぐ
ENV TRANSFORMERS_OFFLINE=1
ENV HF_HUB_OFFLINE=1

# GiNZA モデルをビルド時にロード（キャッシュから読み込まれるため成功）
RUN python -c "import spacy; spacy.load('ja_ginza_electra')"

COPY . .

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

---

## 11. Cloud Run デプロイ設定

```bash
# イメージビルド & プッシュ
gcloud builds submit --tag asia-northeast1-docker.pkg.dev/YOUR_PROJECT/teppeki/guardrail:latest

# デプロイ
gcloud run deploy teppeki-guardrail \
  --image asia-northeast1-docker.pkg.dev/YOUR_PROJECT/teppeki/guardrail:latest \
  --region asia-northeast1 \
  --platform managed \
  --min-instances 0 \          # コスト削減。初回で 3〜8 秒コールドスタート
  --max-instances 2 \          # 100 users 規模に最適化
  --memory 2Gi \               # GiNZAモデルに2GB必要
  --cpu 2 \
  --timeout 120 \
  --concurrency 80 \
  --no-allow-unauthenticated \ # Cloud Run IAM認証は不要（APIキーで管理）
  --set-env-vars "UPSTASH_REDIS_REST_URL=<YOUR_UPSTASH_URL>,MAX_HISTORY_MESSAGES=20" \
  --set-secrets "TEPPEKI_PROXY_API_KEY=teppeki-proxy-api-key:latest,GEMINI_API_KEY=gemini-api-key:latest,UPSTASH_REDIS_REST_TOKEN=upstash-redis-token:latest,PII_MAPPING_ENCRYPTION_KEY=pii-encryption-key:latest"
```

> **Upstash Redis 設定:** [console.upstash.com](https://console.upstash.com/) でデータベースを作成し、REST URL と Token を取得。VPC Connector 不要（HTTPS でアクセス）。

> **Upstash 保存時の暗号化（推奨）:** `PII_MAPPING_ENCRYPTION_KEY` を設定すると、PII マッピング（`{"<PERSON_1>": "田中太郎", ...}`）を Upstash に送る直前で AES 暗号化し、読み込み時に復号する。Upstash 側に保存されるのは暗号文のみ。UX（マスキングのビフォーアフター、応答内容）への影響はない。鍵生成: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')"`

---

## 12. Next.js 側の変更（`app/api/chat/route.ts`）

### 12-0. 統合フロー概要

```
[chat-ui フロントエンド]
  │ 1. ユーザーがメッセージ送信
  │ 2. conversation_id = Supabase chat.id（新規作成 or 既存会話）
  │ 3. messages = [user, assistant, ...]（Supabase messages から取得）
  ▼
[Next.js API route /api/chat]
  │ 4. Supabase 認証・レート制限・添付ファイル処理
  │ 5. system プロンプトを先頭に追加
  │ 6. POST { conversation_id, messages, model } → teppeki-guardrail
  ▼
[teppeki-guardrail]
  │ 7. PII マスク → LLM 呼び出し → アンマスク → { reply, pii_summary }
  ▼
[Next.js API route]
  │ 8. 409 session_expired → フロントエンドに会話リセットを促す
  │ 9. 成功時: reply をフェイクストリーミングでクライアントへ送信
  │ 10. ストリーム完了後: アンマスク済み reply を Supabase messages に保存（既存ロジック）
  ▼
[chat-ui フロントエンド]
  │ 11. ストリーム受信 → タイプライター表示
  │ 12. 409 受信時: トースト表示「会話セッションが期限切れです」→ 新規会話開始を促す
```

> **重要（issue 4）:** このファイルは**完全な書き換えではなく**、既存の auth / rate-limit / validation / file-processing コードに対してプロキシ中継レイヤーを重ねる形で実装すること。PDF・Excel のテキスト抽出は Next.js 側で行い、抽出テキストを `messages` に埋め込んでから proxy に送信する。

```typescript
// インポートパスは既存コードのものを使用（issue 4）
import { createClient } from '@/lib/supabase/server'
import { NextRequest } from 'next/server'
import { getSystemPrompt } from '@/lib/ai/prompts'

export const maxDuration = 120  // バッファリング + LLM呼び出しに備えて120秒

const PROXY_URL = process.env.TEPPEKI_GUARDRAIL_URL!
const PROXY_API_KEY = process.env.TEPPEKI_PROXY_API_KEY!

export async function POST(req: NextRequest) {
  // ── 1. Supabase認証（既存コードを流用）────────────────────────────────────
  const supabase = await createClient()  // await が必要（issue 4）
  const { data: { user }, error: authError } = await supabase.auth.getUser()
  if (authError || !user) {
    return new Response('Unauthorized', { status: 401 })
  }

  // ── 2. リクエストパース ───────────────────────────────────────────────────
  const { conversation_id, messages, model = 'gemini/gemini-3-flash-preview' } = await req.json()

  if (!conversation_id || !messages?.length) {
    return new Response('Bad Request', { status: 400 })
  }

  // ── 3. レート制限・使用量チェック（既存ロジックを流用）（issue 4）──────────
  // await checkRateLimit(user.id)
  // await checkUsageLimit(user.id)

  // ── 4. 入力バリデーション / インジェクション検出（既存ロジックを流用）(issue 4)
  // const sanitizedMessages = sanitizeMessages(messages)

  // ── 5. PDF・Excel・添付ファイル処理（既存ロジックを流用）（issue 4）─────────
  // const processedMessages = await processAttachments(messages)

  // ── 6. system プロンプトを先頭に追加（issue 2）───────────────────────────
  const systemMessage = { role: 'system', content: getSystemPrompt(model) }
  const messagesWithSystem = [systemMessage, ...messages]

  // ── 7. teppeki-guardrail へ転送 ────────────────────────────────────────────
  let proxyResponse: Response
  try {
    proxyResponse = await fetch(`${PROXY_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PROXY_API_KEY}`,
      },
      body: JSON.stringify({ conversation_id, messages: messagesWithSystem, model }),
    })
  } catch (e) {
    console.error('Proxy unreachable:', e)
    return new Response('Service Unavailable', { status: 503 })
  }

  // ── 8. セッション失効ハンドリング（issue 3）──────────────────────────────
  if (proxyResponse.status === 409) {
    const body = await proxyResponse.json()
    if (body.detail === 'session_expired') {
      // フロントエンドに会話リセットを促すエラーを返す
      return new Response(
        JSON.stringify({ error: 'session_expired', message: '会話セッションが期限切れです。新しい会話を開始してください。' }),
        { status: 409, headers: { 'Content-Type': 'application/json' } }
      )
    }
  }

  if (!proxyResponse.ok) {
    const errText = await proxyResponse.text()
    console.error('Proxy error:', proxyResponse.status, errText)
    return new Response('Bad Gateway', { status: 502 })
  }

  // ── 9. JSONレスポンスをパース ─────────────────────────────────────────────
  const { reply, pii_summary } = await proxyResponse.json() as {
    reply: string
    pii_summary: {
      pii_count: number
      entity_types: string[]
      tokens_used: { input: number; output: number }
    }
  }

  // ── 10. トークン使用量を記録（既存ロジックを流用）（issue 4）────────────────
  const totalTokens = pii_summary.tokens_used.input + pii_summary.tokens_used.output
  // await incrementApiUsage(user.id, totalTokens)

  // ── 11. フェイクストリーミング（タイプライター効果）──────────────────────
  // ストリーム完了後に Supabase messages へ assistant の reply を保存（既存ロジックを流用）
  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    async start(controller) {
      const chunkSize = 4   // 1チャンク = 4文字
      const delay = 10      // チャンク間隔 = 10ms

      for (let i = 0; i < reply.length; i += chunkSize) {
        controller.enqueue(encoder.encode(reply.slice(i, i + chunkSize)))
        await new Promise(r => setTimeout(r, delay))
      }
      // await saveAssistantMessage(conversation_id, reply)  // 既存の Supabase 保存ロジック
      controller.close()
    },
  })

  return new Response(stream, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  })
}
```

### 必要な環境変数（Next.js `.env.local`）

```dotenv
TEPPEKI_GUARDRAIL_URL=https://teppeki-guardrail-xxxx-an.a.run.app
TEPPEKI_PROXY_API_KEY=your-secret-api-key-here  # プロキシと同じ値
```

### chat-ui 統合時の API コントラクト（要約）

| 項目 | 値 |
|------|-----|
| エンドポイント | `POST /chat` |
| ヘルスチェック | `GET /health` → `{ "status": "ok" }`（接続確認用） |
| 認証 | `Authorization: Bearer <TEPPEKI_PROXY_API_KEY>` |
| リクエスト | `{ conversation_id, messages, model }` |
| 成功レスポンス | `{ reply, pii_summary: { pii_count, entity_types, tokens_used } }` |
| 401 | 認証失敗（API キー不正・欠落） |
| 409 session_expired | TTL 失効時。フロントエンドは会話リセットを促す |
| 422 | メッセージ長超過 |
| 502 | LLM プロバイダーエラー |

- **conversation_id:** Supabase `chat.id`（UUID v4）。新規会話作成時または既存会話継続時に取得。
- **model:** LiteLLM 形式（例: `gemini/gemini-3-flash-preview`, `openai/gpt-4o`）。

### フロントエンド（chat-ui）での 409 session_expired ハンドリング

Next.js API route が 409 を返す場合、レスポンスボディは `{ error: "session_expired", message: "会話セッションが期限切れです。新しい会話を開始してください。" }`。フロントエンドでは以下を実装すること:

1. **fetch/stream のレスポンスで status 409 を検出**
2. **トーストまたはモーダルで `message` を表示**
3. **会話をリセット:** 現在の `conversation_id` を破棄し、新規会話作成（Supabase で新しい `chat` レコード作成）を促す
4. **UI をクリア:** 表示中のメッセージ履歴をリセットし、新規チャット画面へ遷移

### Supabase messages への保存

guardrail はアンマスク済みの `reply` を返す。Next.js 側でストリーム完了後に、その `reply` を Supabase `messages` テーブルに `role: "assistant"` として保存する（既存の chat-ui ロジックを流用）。保存するのは**アンマスク済み**の生テキスト（ユーザーに表示する内容と同じ）。

---

## 13. ローカル開発

```bash
# 1. Python venvセットアップ
cd teppeki-guardrail
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. GiNZAモデルダウンロード（初回のみ）
python -m spacy download ja_ginza_electra

# 3. Redis（ローカル開発）
# オプション A: docker redis（REDIS_HOST 未設定時は localhost がデフォルト）
docker run -d -p 6379:6379 redis:7-alpine
# オプション B: Upstash の URL/Token を .env に設定

# 4. 環境変数設定
cp .env.example .env
# .envを編集してAPIキー等を設定

# 5. 起動
# オプション A: uvicorn（開発時ホットリロード）
uvicorn app.main:app --reload --port 8080
# オプション B: Docker（本番に近い環境）
# docker build -t teppeki-guardrail:test . && docker run -p 8080:8080 --env-file .env teppeki-guardrail:test

# 6. 動作確認
curl -X POST http://localhost:8080/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-api-key-here" \
  -d '{
    "conversation_id": "550e8400-e29b-41d4-a716-446655440000",
    "messages": [{"role": "user", "content": "田中太郎です。電話番号は090-1234-5678です。"}],
    "model": "gemini/gemini-3-flash-preview"
  }'
```

---

## 14. セキュリティチェックリスト

- [ ] `TEPPEKI_PROXY_API_KEY` は Secret Manager で管理（平文コミット禁止）
- [ ] Cloud Run は `--no-allow-unauthenticated`（APIキー認証のみ）
- [ ] Upstash Redis のトークンは Secret Manager で管理（本番環境推奨）
- [ ] `PII_MAPPING_ENCRYPTION_KEY` を設定し、Upstash 保存時の暗号化を有効化（推奨）
- [ ] LLM APIキーはすべて Secret Manager で管理
- [ ] Cloud Run ログに PII が出力されていないことを確認（structuredログ + フィールド除外）

---

## 15. 実装順序（推奨）

| 段階 | 作業 | 参照 |
|------|------|------|
| 1 | guardrail サービス構築 | `teppeki-guardrail.md` セクション 1〜11 |
| 2 | Upstash Redis・Cloud Run デプロイ | `teppeki-guardrail.md` セクション 12 |
| 3 | Next.js route.ts 変更 | 本ファイル セクション 12 |
| 4 | フロントエンド 409 ハンドリング | 本ファイル セクション 12「フロントエンドでの 409 ハンドリング」 |
| 5 | E2E テスト | 両 doc のローカル開発手順 |

1. **`redactor/` コピー** — presidioプロジェクトから最新版を転記
2. **`requirements.txt` + `Dockerfile`** — ビルドが通ることを確認
3. **`app/models.py` + `app/auth.py`** — スキーマと認証
4. **`app/redis_client.py`** — ローカルRedisで動作確認
5. **`app/llm_client.py`** — LiteLLMでGemini疎通確認
6. **`app/main.py`** — `/chat` エンドポイント統合テスト
7. **Upstash Redis 作成** — Console で URL/Token 取得
8. **Cloud Run デプロイ** — VPC 不要、min-instances=0, max-instances=2
9. **Next.js 側の `route.ts` 変更** — E2Eテスト

---

## 16. 統合時の既知の問題と対策

> teppeki-ai-chat (Next.js) と teppeki-guardrail (FastAPI) の統合における既知の問題点と対策。
> セクション 9・12 のコードにはすべての修正が反映済み。

---

### Issue 1 【CRITICAL】: Assistant メッセージが生の PII を LLM に漏洩する

**問題:**
proxy は unmasked なテキストを Next.js に返す。Next.js が次のターンで会話履歴を proxy に送り返すとき、assistant メッセージには生の PII が含まれている。`role == "user"` のみマスクすると assistant メッセージがそのまま LLM に渡ってしまう。

```
ターン1:
  proxy unmask → "山田太郎に連絡しましょう" → Next.js に返却

ターン2:
  Next.js が送信する履歴:
    { role: "user",      content: "山田太郎に連絡して" }        ← マスクされる
    { role: "assistant", content: "山田太郎に連絡しましょう" }  ← マスクされない → PII漏洩
```

**修正:**
`main.py` のマスキングループで user と assistant の両方をマスクする（セクション 9 に反映済み）:

```python
for msg in messages_to_process:
    if msg.role in ("user", "assistant"):
        masked_text, pii_mapping = redact_text_with_mapping(
            msg.content, existing_mapping=pii_mapping,
        )
        masked_messages.append(msg.model_copy(update={"content": masked_text}))
    else:
        masked_messages.append(msg)
```

---

### Issue 2 【IMPORTANT】: system_prompt が API コントラクトに含まれていない

**問題:**
`ChatRequest` スキーマに `system_prompt` フィールドがない。Next.js 側には `lib/ai/prompts.ts` にプロバイダー別のシステムプロンプトが定義されているが、proxy に渡す手段がない。

**修正:**
Next.js 側で `messages` 配列の先頭に `{ role: "system", content: getSystemPrompt(model) }` を prepend して送信する（セクション 12 に反映済み）。`Message` モデルの `role` はすでに `"system"` を許容しているため、proxy 側の変更は不要。

```typescript
const systemMessage = { role: 'system', content: getSystemPrompt(model) }
const messagesWithSystem = [systemMessage, ...messages]
```

---

### Issue 3 【CRITICAL】: Redis TTL 失効後のプレースホルダー番号衝突

**問題:**
24時間以上会話が止まると Redis キーが失効する。次のターンでは空マッピングから再スタートするため、以前の会話履歴に含まれる `<PERSON_1>` と、新たに生成される `<PERSON_1>` が**別人を指す**可能性がある。

```
ターン1（2日前）: "山田太郎" → <PERSON_1>  ← Redis失効済み
ターン2（今日）:  "田中花子" → <PERSON_1>  ← 同じ番号が別人に割り当てられる
LLMに届く履歴: 両方とも <PERSON_1> → モデルが同一人物と誤解
```

**修正:**
`load_pii_mapping()` が `None`（TTL失効）と `{}`（新規）を区別して返すように変更し、`main.py` で失効を検出した場合は HTTP 409 を返してフロントエンドに会話リセットを促す（セクション 7・9・12 に反映済み）。

```python
# redis_client.py: None = 失効/未存在、{} = 新規
async def load_pii_mapping(conversation_id: str) -> dict[str, str] | None: ...

# main.py: 失効検出
if stored_mapping is None and has_assistant_history:
    raise HTTPException(status_code=409, detail="session_expired")
```

---

### Issue 4 【IMPORTANT】: Next.js route.ts の書き換えで既存機能が脱落する

**問題:**
実装指示書のセクション 12 の `route.ts` 例は、現在の実装が持つ以下の機能を省略している:

| 機能 | 現在の route.ts | 対応 |
|------|----------------|------|
| レートリミット (Upstash) | 実装済み | 既存コードを流用 |
| 使用量トラッキング | 実装済み | 既存コードを流用 |
| 入力バリデーション / インジェクション検出 | 実装済み | 既存コードを流用 |
| PDF テキスト抽出 | 実装済み | Next.js 側で処理後に proxy へ送信 |
| Excel テキスト抽出 | 実装済み | 同上 |
| 添付ファイル処理 | マルチモーダル対応 | 同上 |
| インポートパス | `@/lib/supabase/server` | セクション 12 を修正済み |
| `createClient()` | `await createClient()` | セクション 12 を修正済み |

**修正:**
セクション 12 を完全な書き換えとして扱わず、既存の auth / validation / file-processing コードの上にプロキシ中継レイヤーを重ねる（セクション 12 に反映済み）。

---

### Issue 5 【IMPORTANT】: Entity type 収集ロジックのバグ

**問題:**
`main.py` で `new_placeholders` を計算するが未使用。また、全 user メッセージの反復ごとにマッピング全体のエンティティタイプを追加するため、重複が発生する。

```python
new_placeholders = set(masked_text.split()) - set(msg.content.split())  # 未使用
for placeholder in pii_mapping:  # 全マッピングを毎回イテレート → 重複
    entity_type = placeholder.strip("<>").rsplit("_", 1)[0]
    all_entity_types.append(entity_type)
```

**修正:**
マスキングループの後に一度だけ `set` でエンティティタイプを収集する（セクション 9 に反映済み）:

```python
entity_types: set[str] = set()
for placeholder in pii_mapping:
    match = re.match(r"<([A-Z_]+)_\d+>", placeholder)
    if match:
        entity_types.add(match.group(1))
```

---

### Issue 6 【IMPORTANT】: `redact_text_with_mapping` が部分文字列で誤置換する可能性

**問題:**
付録の実装が `str.replace()` で単純置換を行うと、PII 値が別の PII の部分文字列である場合に誤った置換が発生する（例: "田中" が "田中太郎" の中に出現）。

**修正:**
Presidio の `AnalyzerEngine` が返す `start/end` 位置を使い、**降順ソート後に位置ベース**で置換することで、部分文字列の衝突を回避する（付録を参照）:

```python
for result in sorted(results, key=lambda r: r.start, reverse=True):
    original = text[result.start:result.end]
    placeholder = reverse_mapping.get(original) or _new_placeholder(...)
    masked_text = masked_text[:result.start] + placeholder + masked_text[result.end:]
```

---

### Issue 7 【CRITICAL】: コンテキストウィンドウ超過とマスキングコストの線形増大

**問題:**
会話が長くなるにつれて、毎ターン全履歴を再マスクして送信するため：
1. **マスキング処理コスト**が会話の長さに比例して増加
2. **トークン数が LLM のコンテキストウィンドウを超過**する可能性がある

**修正:**
`MAX_HISTORY_MESSAGES`（デフォルト20件）で直近の履歴のみ送信するよう制限する（セクション 9 に反映済み）:

```python
system_messages = [m for m in req.messages if m.role == "system"]
history_messages = [m for m in req.messages if m.role != "system"]
trimmed_history = history_messages[-MAX_HISTORY_MESSAGES:]
messages_to_process = system_messages + trimmed_history
```

> **注意:** トリムにより古い会話コンテキストは LLM に渡らなくなる。PIIマッピング自体は Redis に残るため、古いプレースホルダーが偶然再登場した場合でも正しくアンマスクされる。

---

### Issue 8 【CRITICAL】: ストリーミング方式でのデリミタ衝突

**問題（Issue 11 のストリーミング方式を採用した場合）:**
proxy が `---TEPPEKI_META---` をデリミタとして使用する場合、LLM が応答の中でこの文字列を**自然に生成してしまう**可能性がある（マークダウンの区切り線 `---` など）。これが起きると JSON パースが壊れ、アンマスク不能になる。

**修正:**
人間が自然に書かないユニークなデリミタを使用する:

```python
# 方法1: NULLバイトベース（LLMは生成しない）
TEPPEKI_DELIMITER = "\x00TEPPEKI_META\x00"

# 方法2: リクエスト単位でランダム生成し、レスポンスヘッダーで事前通知
import secrets
delimiter = f"__TEPPEKI_{secrets.token_hex(16)}__"
# Response header: X-Teppeki-Delimiter: {delimiter}
```

---

### Issue 9 【IMPORTANT】: ストリーミング方式でのアンマスク後テキストの Supabase 保存タイミング

**問題（Issue 11 のストリーミング方式を採用した場合）:**
マスク済みストリームをリアルタイムで中継し、クライアント側でアンマスクする場合、Supabase の `messages` テーブルに保存されるタイミングと内容が未定義。

- ストリーム中継中に保存 → マスク済みテキストが保存される
- クライアントアンマスク後に保存 → 追加の API コールが必要

**推奨対応:**
Next.js サーバー側（route.ts）でストリーム完了後にデリミタを検出し、サーバー側でアンマスクしてから Supabase に保存する。ブラウザには最初からアンマスク済みテキストを送信することで、クライアント側に PII マッピングを渡す必要がなくなる。

---

### Issue 10 【IMPORTANT】: LLM 呼び出し失敗後の Redis マッピング不整合

**問題:**
マスキング処理（Redis書き込み）成功後に LLM 呼び出しが失敗した場合、Redis には新しい PII が追加済みだが LLM は応答していない。次のリトライで状態が不整合になる。

**修正:**
Redis への保存を **LLM 呼び出し成功後**に移動する（セクション 9 に反映済み）:

```python
# LLM呼び出し成功後にのみ保存
masked_reply, token_usage = await call_llm(...)   # 失敗 → 例外 → Redis保存されない
await save_pii_mapping(req.conversation_id, pii_mapping)  # ← 成功後に移動
```

---

### Issue 11 【UX 改善案】: マスク済みストリーム + クライアント側アンマスク

**背景:**
フルバッファリング（`stream=False`）では、LLM が全応答を生成し終えるまで（5〜30秒）ユーザーに何も表示されない。これは現在のリアルストリーミング（最初のトークンが 1〜2 秒で表示）からの UX 後退となる。

**代替方式（将来実装候補）:**
proxy から**マスク済みテキストをリアルタイムストリーミング**し、ストリーム完了後にサーバー側（Next.js route.ts）でアンマスクしてから Supabase 保存 + クライアントへの送信を行う。

```
ユーザー送信
  → "秘匿化しています..." アニメーション（~220ms）
  → マスク済み LLM 応答がリアルタイムでストリーミング（Next.jsサーバー受信）
  → ストリーム完了 → デリミタ検出 → Next.jsサーバーでアンマスク → Supabase保存
  → アンマスク済みテキストをクライアントへストリーム送信
  → "復号化中です..." アニメーション → インプレース表示
```

**proxy のレスポンス形式（デリミタ方式）:**

```
<PERSON_1>さんのメールアドレス<EMAIL_ADDRESS_1>に連絡しました。
\x00TEPPEKI_META\x00
{"pii_mapping": {"<PERSON_1>": "山田太郎", ...}, "pii_summary": {...}}
```

> **採用時の注意:** Issue 8（デリミタ衝突）・Issue 9（Supabase 保存タイミング）を必ず合わせて対処すること。現在のデフォルト実装（フルバッファリング + フェイクストリーミング）は追加の複雑さなしに動作するため、まずこちらで動作確認してから必要に応じて移行する。

---

## 付録：`redact_text_with_mapping()` が存在しない場合

> **注意:** 現在の実装では `app/masking.py` が `redactor.redactor` の低レベル関数をラップして `redact_text_with_mapping()` を提供している。presidio の `redactor.py` に同関数がない場合、以下を `app/masking.py` の代替として追加してください（Issue 6 の位置ベース置換対応済み）:

```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import re

_analyzer = None
_anonymizer = None


def _get_engines():
    global _analyzer, _anonymizer
    if _analyzer is None:
        _analyzer = AnalyzerEngine()
        _anonymizer = AnonymizerEngine()
    return _analyzer, _anonymizer


def redact_text_with_mapping(
    text: str,
    existing_mapping: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    mapping = dict(existing_mapping or {})
    analyzer, _ = _get_engines()

    results = analyzer.analyze(text=text, language="ja")

    # エンティティ種別ごとのカウンタ（既存マッピングから復元）
    counters: dict[str, int] = {}
    for placeholder in mapping:
        m = re.match(r"<([A-Z_]+)_(\d+)>", placeholder)
        if m:
            etype, idx = m.group(1), int(m.group(2))
            counters[etype] = max(counters.get(etype, 0), idx)

    # 逆引きマップ（元テキスト → プレースホルダー）で重複を避ける
    reverse_mapping = {v: k for k, v in mapping.items()}

    # 位置ベースで降順ソートして置換（issue 6: 部分文字列衝突を回避）
    masked_text = text
    for result in sorted(results, key=lambda r: r.start, reverse=True):
        original = text[result.start:result.end]
        if original in reverse_mapping:
            placeholder = reverse_mapping[original]
        else:
            etype = result.entity_type
            counters[etype] = counters.get(etype, 0) + 1
            placeholder = f"<{etype}_{counters[etype]}>"
            mapping[placeholder] = original
            reverse_mapping[original] = placeholder
        masked_text = masked_text[:result.start] + placeholder + masked_text[result.end:]

    return masked_text, mapping
```
