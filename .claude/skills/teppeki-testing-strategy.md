# teppeki-testing-strategy: Quality Assurance & Testing

You are a QA architect designing the testing strategy for teppeki-guardrail. You ensure correctness of PII masking, API behavior, integration points, and production readiness.

## Trigger

Activate when: the user asks about testing, test design, test coverage, CI/CD, quality assurance, or evaluation of the PII masking pipeline.

## Test Pyramid

```
            ┌─────────┐
            │  E2E    │  curl / Next.js → proxy → LLM round-trip
            ├─────────┤
            │ Integra-│  /chat endpoint with mocked LLM + real Redis
            │  tion   │
            ├─────────┤
            │  Unit   │  redactor, auth, models, redis_client, llm_client
            └─────────┘
```

## Directory Structure

```
tests/
├── test_redactor.py       # Redactor unit tests (PII detection accuracy)
├── test_chat.py           # /chat endpoint integration tests
├── test_auth.py           # Authentication edge cases
├── test_redis_client.py   # Redis operations (with mock or local Redis)
├── test_llm_client.py     # LLM wrapper (with mocked LiteLLM)
└── conftest.py            # Shared fixtures (test client, mock Redis, etc.)
```

## Unit Tests: Redactor

The redactor is the core of the system. Test it extensively.

### Key Test Cases

```python
# tests/test_redactor.py
from redactor.redactor import redact_text_with_mapping

class TestRedactTextWithMapping:
    def test_masks_japanese_person_name(self):
        text = "田中太郎に連絡してください"
        masked, mapping = redact_text_with_mapping(text)
        assert "田中太郎" not in masked
        assert any("PERSON" in k for k in mapping)

    def test_masks_phone_number(self):
        text = "電話番号は090-1234-5678です"
        masked, mapping = redact_text_with_mapping(text)
        assert "090-1234-5678" not in masked
        assert any("PHONE" in k for k in mapping)

    def test_masks_email(self):
        text = "メールはtanaka@example.comまで"
        masked, mapping = redact_text_with_mapping(text)
        assert "tanaka@example.com" not in masked

    def test_existing_mapping_preserves_placeholders(self):
        """Multi-turn consistency: same PII gets same placeholder."""
        text = "田中太郎です"
        existing = {"<PERSON_1>": "田中太郎"}
        masked, mapping = redact_text_with_mapping(text, existing_mapping=existing)
        assert "<PERSON_1>" in masked
        assert mapping["<PERSON_1>"] == "田中太郎"

    def test_new_pii_gets_next_index(self):
        """New PII in same session gets incremented index."""
        text = "山田花子に連絡"
        existing = {"<PERSON_1>": "田中太郎"}
        masked, mapping = redact_text_with_mapping(text, existing_mapping=existing)
        # New person should be <PERSON_2>, not <PERSON_1>
        assert "<PERSON_1>" in mapping  # preserved
        assert len([k for k in mapping if "PERSON" in k]) == 2

    def test_multiple_pii_types(self):
        text = "田中太郎（090-1234-5678、tanaka@example.com）"
        masked, mapping = redact_text_with_mapping(text)
        assert "田中太郎" not in masked
        assert "090-1234-5678" not in masked
        assert "tanaka@example.com" not in masked

    def test_no_pii_returns_unchanged(self):
        text = "今日は天気がいいですね"
        masked, mapping = redact_text_with_mapping(text)
        assert masked == text
        assert len(mapping) == 0

    def test_empty_string(self):
        masked, mapping = redact_text_with_mapping("")
        assert masked == ""
        assert mapping == {}

    def test_system_prompt_not_masked(self):
        """System prompts should pass through without masking (handled by main.py)."""
        text = "あなたは丁寧なアシスタントです"
        masked, mapping = redact_text_with_mapping(text)
        # System prompt has no PII → should be unchanged
        assert masked == text
```

### Evaluation-Based Testing
The redactor has a built-in evaluation framework (`evaluate.py`). Use it for regression testing:

```bash
# Run evaluation against test corpus
python -m redactor.evaluate

# Output: precision, recall, F1 per entity type
# Check for regressions in FP/FN rates
```

## Integration Tests: /chat Endpoint

```python
# tests/test_chat.py
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    # Set required env vars
    with patch.dict(os.environ, {"TEPPEKI_PROXY_API_KEY": "test-key"}):
        from app.main import app
        yield TestClient(app)

@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-key"}

class TestChatEndpoint:
    @patch("app.main.call_llm")
    @patch("app.main.load_pii_mapping", return_value={})
    @patch("app.main.save_pii_mapping")
    def test_successful_chat(self, mock_save, mock_load, mock_llm, client, auth_headers):
        mock_llm.return_value = ("<PERSON_1>さんこんにちは", TokenUsage(input=10, output=5))
        response = client.post("/chat", json={
            "conversation_id": "test-uuid",
            "messages": [{"role": "user", "content": "田中太郎です"}],
        }, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "reply" in data
        assert "pii_summary" in data

    def test_auth_required(self, client):
        response = client.post("/chat", json={...})
        assert response.status_code == 422  # Missing header

    def test_invalid_token(self, client):
        response = client.post("/chat", json={...},
            headers={"Authorization": "Bearer wrong-key"})
        assert response.status_code == 401

    @patch("app.main.load_pii_mapping", return_value=None)
    def test_session_expired_with_history(self, mock_load, client, auth_headers):
        response = client.post("/chat", json={
            "conversation_id": "test-uuid",
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
                {"role": "user", "content": "bye"},
            ],
        }, headers=auth_headers)
        assert response.status_code == 409
        assert response.json()["detail"] == "session_expired"

    @patch("app.main.load_pii_mapping", return_value=None)
    @patch("app.main.call_llm")
    @patch("app.main.save_pii_mapping")
    def test_new_conversation_no_history(self, mock_save, mock_llm, mock_load, client, auth_headers):
        """None from Redis + no assistant history = new conversation (OK)."""
        mock_llm.return_value = ("response", TokenUsage(input=5, output=3))
        response = client.post("/chat", json={
            "conversation_id": "new-uuid",
            "messages": [{"role": "user", "content": "hello"}],
        }, headers=auth_headers)
        assert response.status_code == 200

    def test_message_too_long(self, client, auth_headers):
        response = client.post("/chat", json={
            "conversation_id": "test",
            "messages": [{"role": "user", "content": "x" * 10001}],
        }, headers=auth_headers)
        assert response.status_code == 422

    @patch("app.main.call_llm", side_effect=Exception("LLM timeout"))
    @patch("app.main.load_pii_mapping", return_value={})
    def test_llm_failure_returns_502(self, mock_load, mock_llm, client, auth_headers):
        response = client.post("/chat", json={
            "conversation_id": "test",
            "messages": [{"role": "user", "content": "hello"}],
        }, headers=auth_headers)
        assert response.status_code == 502

    @patch("app.main.call_llm", side_effect=Exception("fail"))
    @patch("app.main.load_pii_mapping", return_value={})
    @patch("app.main.save_pii_mapping")
    def test_redis_not_saved_on_llm_failure(self, mock_save, mock_load, mock_llm, client, auth_headers):
        """Redis save must NOT happen when LLM fails."""
        client.post("/chat", json={
            "conversation_id": "test",
            "messages": [{"role": "user", "content": "hello"}],
        }, headers=auth_headers)
        mock_save.assert_not_called()
```

## Redis Client Tests

```python
# tests/test_redis_client.py
import pytest
from unittest.mock import AsyncMock, patch

class TestRedisClient:
    @pytest.mark.asyncio
    async def test_load_returns_none_when_missing(self):
        with patch("app.redis_client.redis_client") as mock:
            mock.get = AsyncMock(return_value=None)
            result = await load_pii_mapping("nonexistent")
            assert result is None

    @pytest.mark.asyncio
    async def test_load_returns_empty_dict(self):
        with patch("app.redis_client.redis_client") as mock:
            mock.get = AsyncMock(return_value='{}')
            result = await load_pii_mapping("new-conv")
            assert result == {}

    @pytest.mark.asyncio
    async def test_save_sets_ttl(self):
        with patch("app.redis_client.redis_client") as mock:
            mock.set = AsyncMock()
            await save_pii_mapping("test", {"<PERSON_1>": "田中"})
            mock.set.assert_called_once()
            call_kwargs = mock.set.call_args
            assert call_kwargs.kwargs.get("ex") == 86400  # TTL
```

## E2E Testing

### Local E2E (curl)
```bash
# Prerequisites: Redis running locally, .env configured
docker run -d -p 6379:6379 redis:7-alpine
uvicorn app.main:app --port 8080

# Test request
curl -s -X POST http://localhost:8080/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{
    "conversation_id": "test-e2e-001",
    "messages": [
      {"role": "system", "content": "あなたは丁寧なアシスタントです。"},
      {"role": "user", "content": "田中太郎です。090-1234-5678に電話してください。"}
    ]
  }' | jq .

# Expected: reply contains "田中太郎" (unmasked), pii_summary.pii_count >= 2
```

### Multi-Turn E2E
```bash
# Turn 1: New conversation
CONV_ID="test-multi-001"
REPLY=$(curl -s -X POST http://localhost:8080/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{
    \"conversation_id\": \"$CONV_ID\",
    \"messages\": [{\"role\": \"user\", \"content\": \"田中太郎です。\"}]
  }" | jq -r .reply)

# Turn 2: Continue conversation with history
curl -s -X POST http://localhost:8080/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d "{
    \"conversation_id\": \"$CONV_ID\",
    \"messages\": [
      {\"role\": \"user\", \"content\": \"田中太郎です。\"},
      {\"role\": \"assistant\", \"content\": \"$REPLY\"},
      {\"role\": \"user\", \"content\": \"山田花子にも連絡してください。\"}
    ]
  }" | jq .

# Expected: pii_count >= 2 (both persons tracked)
```

## CI/CD Integration

```yaml
# .github/workflows/test.yml (or Cloud Build equivalent)
steps:
  - name: Install dependencies
    run: pip install -r requirements.txt -r requirements-dev.txt

  - name: Run unit tests
    run: pytest tests/ -v --tb=short

  - name: Run redactor evaluation
    run: python -m redactor.evaluate
    # Fail if F1 drops below threshold

  - name: Build Docker image
    run: docker build -t teppeki-guardrail .

  - name: Run integration tests (with local Redis)
    run: |
      docker run -d -p 6379:6379 redis:7-alpine
      docker run --network=host -e REDIS_HOST=localhost teppeki-guardrail &
      sleep 10  # Wait for GiNZA warmup
      pytest tests/test_integration.py -v
```

## Test Coverage Goals

| Component | Target | Priority |
|-----------|--------|----------|
| `redactor.py` (masking accuracy) | Evaluated via evaluate.py | Critical |
| `main.py` (request pipeline) | 90%+ branch coverage | Critical |
| `auth.py` | 100% | High |
| `redis_client.py` | 90%+ | High |
| `llm_client.py` | 80%+ (mostly mocked) | Medium |
| `models.py` | Implicit via endpoint tests | Low |

## Test Data Principles

- Use realistic Japanese PII patterns in test data
- Include edge cases: single kanji names, long phone numbers, mixed script
- Test data in test files only — never use real PII
- Maintain a test corpus under `redactor/test_md/` with known answers in `redactor/answer/`
