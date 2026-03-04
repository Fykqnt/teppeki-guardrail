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
