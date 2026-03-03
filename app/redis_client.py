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
