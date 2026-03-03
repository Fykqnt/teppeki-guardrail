# teppeki-redis-session: Memorystore Session Management

You are a Redis/session management architect for teppeki-guardrail. You ensure PII mapping consistency, handle TTL expiry gracefully, and design for the specific access patterns of a multi-turn chat masking proxy.

## Trigger

Activate when: the user asks about Redis design, PII mapping storage, session management, TTL strategy, data consistency, race conditions, or Cloud Memorystore configuration.

## Data Model

### Key Schema
```
pii:conv:{conversation_id}  →  JSON string
```

- `conversation_id` = Supabase `chat.id` (UUID v4)
- Value = `{"<PERSON_1>": "田中太郎", "<PHONE_NUMBER_1>": "090-1234-5678", ...}`
- TTL = 24 hours (sliding, reset on every turn)

### Value Structure
```json
{
  "<PERSON_1>": "山田太郎",
  "<PERSON_2>": "田中花子",
  "<PHONE_NUMBER_1>": "090-1234-5678",
  "<EMAIL_ADDRESS_1>": "yamada@example.com",
  "<ORGANIZATION_1>": "株式会社テッペキ"
}
```

**Typical size**: 10-100 entries per conversation, ~1-10KB JSON

## Access Patterns

### Read-Modify-Write Cycle (every chat turn)
```
1. LOAD:  GET pii:conv:{id}           → dict | None
2. MASK:  redact_text_with_mapping()  → updated dict (in-memory)
3. LLM:   call_llm()                  → success/failure
4. SAVE:  SET pii:conv:{id} ... EX 86400  (only on LLM success)
```

### Critical: None vs Empty Dict Distinction
```python
raw = await redis_client.get(key)
if raw is None:
    return None   # Key doesn't exist OR TTL expired
return json.loads(raw)  # Could be {} for new conversation
```

| Redis State | Return Value | Meaning | Action |
|-------------|-------------|---------|--------|
| Key missing | `None` | Never created OR TTL expired | Check if conversation has history |
| Key = `"{}"` | `{}` | New conversation, no PII yet | Proceed normally |
| Key = `{...}` | `dict` | Active session with mappings | Proceed normally |

### TTL Expiry Handling
```python
stored = await load_pii_mapping(conversation_id)
has_history = any(m.role == "assistant" for m in messages)

if stored is None and has_history:
    # Mapping expired but conversation has prior turns
    # Placeholder numbers would collide → force reset
    raise HTTPException(status_code=409, detail="session_expired")
```

**Why this matters**: If Redis mapping expires and a new `<PERSON_1>` is created, it may refer to a different person than the `<PERSON_1>` from the expired session. The LLM would conflate the two.

## Consistency Guarantees

### Write-After-Success Pattern
```python
# CORRECT: Save AFTER LLM success
masked_reply, usage = await call_llm(model, masked_messages)  # may throw
await save_pii_mapping(conversation_id, pii_mapping)          # only on success

# WRONG: Save BEFORE LLM call
await save_pii_mapping(conversation_id, pii_mapping)  # saved
masked_reply, usage = await call_llm(model, masked_messages)  # fails → mapping has drifted
```

If save happens before LLM and the LLM fails, the mapping now contains entries for PII that was never sent in a successful response. On retry, placeholder numbers are inconsistent.

### Concurrent Request Safety
- **Current design**: No locking needed. Chat UI blocks further sends until response completes.
- **If concurrent access needed**: Use `WATCH`/`MULTI`/`EXEC` or Lua scripts for optimistic locking:

```python
# Future: optimistic locking pattern
async def save_with_lock(conversation_id, mapping):
    key = _pii_key(conversation_id)
    async with redis_client.pipeline(transaction=True) as pipe:
        await pipe.watch(key)
        pipe.multi()
        pipe.set(key, json.dumps(mapping, ensure_ascii=False), ex=REDIS_TTL)
        await pipe.execute()
```

## Redis Client Configuration

```python
import redis.asyncio as aioredis

redis_client = aioredis.Redis(
    host=REDIS_HOST,        # Memorystore VPC-internal IP
    port=REDIS_PORT,        # 6379
    decode_responses=True,  # Auto UTF-8 decode (Japanese text)
)
```

### Connection Best Practices
- Use `decode_responses=True` — all values are JSON strings with Japanese text
- Use `redis[hiredis]` for C-optimized parser performance
- Connection pooling is handled automatically by `redis.asyncio`
- No password needed for VPC-internal Memorystore (basic tier); use AUTH for standard tier

## Operational Patterns

### Conversation Deletion
```python
async def delete_pii_mapping(conversation_id: str) -> None:
    """Immediate cleanup when user deletes conversation."""
    await redis_client.delete(_pii_key(conversation_id))
```

Use this when:
- User explicitly deletes a conversation in the frontend
- GDPR/privacy compliance requires immediate PII removal
- Session cleanup on user account deletion

### TTL Strategy

| Scenario | TTL Behavior |
|----------|-------------|
| Active conversation | TTL resets to 24h on every turn |
| Idle conversation (< 24h) | TTL counting down; resumes normally |
| Idle conversation (> 24h) | Key expired; HTTP 409 on next turn with history |
| New conversation | Key created on first successful LLM response |

### Memory Estimation
- Average mapping: 50 entries × ~100 bytes = ~5KB per conversation
- 1,000 concurrent conversations: ~5MB
- Memorystore Basic 1GB tier: supports ~200,000 concurrent conversations
- TTL auto-cleanup prevents unbounded growth

## Anti-Patterns

- **Storing masked text in Redis** — Always re-mask from source; redactor config may change
- **Using Redis as a message queue** — Redis here is a session store only
- **Long TTLs (> 48h)** — PII retention should be minimized; 24h sliding is sufficient
- **Storing entire conversation history** — Only store the PII mapping dict, not messages
- **Using Redis SUBSCRIBE for events** — Overkill; this is simple key-value access
- **Skipping TTL on SET** — Always set `ex=REDIS_TTL`; never store PII without expiry

## Memorystore Tier Selection

| Feature | Basic | Standard |
|---------|-------|----------|
| Replication | No | Yes (automatic failover) |
| SLA | None | 99.9% |
| Cost (1GB, asia-northeast1) | ~$35/mo | ~$70/mo |
| Data persistence | In-memory only | In-memory + replica |
| Recommendation | Development/staging | Production |

For production: Use **Standard tier** for automatic failover. PII mapping loss on Redis failure is recoverable (triggers 409 → conversation reset), but Standard tier minimizes disruption.
