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
