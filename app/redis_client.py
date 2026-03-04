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

# Upstash Redis (production) - HTTPS, no VPC needed
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
    _redis = aioredis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
    )
    _use_upstash = False

# Fail loudly if encryption key is set but invalid
if ENCRYPTION_KEY and _use_upstash:
    key_bytes = (
        ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
    )
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
    """Upstash 保存用に暗号化。鍵未設定時は平文を返す。"""
    if _fernet is None:
        return plain
    return _fernet.encrypt(plain.encode()).decode()


def _decrypt(cipher: str) -> str:
    """Upstash から取得したデータを復号。暗号化されていない場合は平文を返す。"""
    if _fernet is None:
        return cipher
    try:
        return _fernet.decrypt(cipher.encode()).decode()
    except (InvalidToken, ValueError):
        # 既存の平文データ（移行前）の場合はそのまま返す
        return cipher


def _key(conversation_id: str) -> str:
    return f"pii:conv:{conversation_id}"


async def load_pii_mapping(conversation_id: str) -> dict[str, str] | None:
    """
    PII マッピングを取得する。
    - キーが存在する: dict を返す（空 dict も含む）
    - キーが存在しない / TTL 失効: None を返す
    None と {} を区別することで TTL 失効を検出できる。
    Upstash 使用時かつ暗号化有効時は、取得後に復号して返す。
    """
    raw = await _redis.get(_key(conversation_id))
    if raw is None:
        return None
    raw = _decrypt(raw)
    return json.loads(raw)


async def save_pii_mapping(conversation_id: str, mapping: dict[str, str]) -> None:
    """
    PII マッピングを保存し、TTL をリセット（ターンごとに 24 時間延長）。
    Upstash 使用時かつ暗号化有効時は、保存前に暗号化する。
    """
    plain = json.dumps(mapping, ensure_ascii=False)
    payload = _encrypt(plain)
    await _redis.set(
        _key(conversation_id),
        payload,
        ex=REDIS_TTL,
    )


async def delete_pii_mapping(conversation_id: str) -> None:
    """会話削除時などに PII マッピングを即時削除する。"""
    await _redis.delete(_key(conversation_id))
