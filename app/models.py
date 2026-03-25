from pydantic import BaseModel, Field


class Message(BaseModel):
    role: str    # "user" | "assistant" | "system"
    content: str


class ChatRequest(BaseModel):
    conversation_id: str = Field(..., description="Supabase chat.id（UUID v4）")
    messages: list[Message] = Field(..., min_length=1)
    model: str = Field(default="gemini-3-flash-preview")


class TokenUsage(BaseModel):
    input: int
    output: int


class PIISummary(BaseModel):
    pii_count: int
    entity_types: list[str]
    tokens_used: TokenUsage


class TextVariant(BaseModel):
    masked: str
    unmasked: str


class ChatResponse(BaseModel):
    reply: str
    input_text: TextVariant
    reply_text: TextVariant
    pii_summary: PIISummary
