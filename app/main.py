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
from app.models import ChatRequest, ChatResponse, PIISummary, TextVariant
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


def _unmask_text(text: str, pii_mapping: dict[str, str]) -> str:
    unmasked_text = text
    for placeholder, original in pii_mapping.items():
        unmasked_text = unmasked_text.replace(placeholder, original)
    return unmasked_text


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
    latest_user_input = TextVariant(masked="", unmasked="")
    for msg in messages_to_process:
        if msg.role in ("user", "assistant"):
            masked_text, pii_mapping = redact_text_with_mapping(
                msg.content,
                existing_mapping=pii_mapping,
            )
            masked_messages.append(msg.model_copy(update={"content": masked_text}))
            if msg.role == "user":
                latest_user_input = TextVariant(
                    masked=masked_text,
                    unmasked=msg.content,
                )
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
    reply = _unmask_text(masked_reply, pii_mapping)
    reply_text = TextVariant(masked=masked_reply, unmasked=reply)

    logger.info(
        f"conv={req.conversation_id} pii={len(pii_mapping)} "
        f"tokens={token_usage.input}+{token_usage.output}"
    )

    return ChatResponse(
        reply=reply,
        input_text=latest_user_input,
        reply_text=reply_text,
        pii_summary=PIISummary(
            pii_count=len(pii_mapping),
            entity_types=sorted(entity_types),
            tokens_used=token_usage,
        ),
    )
