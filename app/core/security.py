import bcrypt as _bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.core.config import settings

api_key_header = APIKeyHeader(name="X-Internal-API-Key", auto_error=False)


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)).decode()


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta if expires_delta is not None else timedelta(minutes=settings.JWT_ACCESS_EXPIRE_MINUTES))
    import uuid
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": now,
        "iss": settings.JWT_ISSUER,
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_REFRESH_EXPIRE_MINUTES)
    import uuid
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": now,
        "iss": settings.JWT_ISSUER,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[str]:
    try:
        options = {"verify_exp": True, "require": ["exp", "iat", "iss"]}
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options=options,
            issuer=settings.JWT_ISSUER,
        )
        if payload.get("type") not in ("access", None):
            return None
        return payload.get("sub")
    except JWTError:
        return None


def decode_refresh_token(token: str) -> Optional[str]:
    try:
        options = {"verify_exp": True, "require": ["exp", "iat", "iss"]}
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options=options,
            issuer=settings.JWT_ISSUER,
        )
        if payload.get("type") != "refresh":
            return None
        return payload.get("sub")
    except JWTError:
        return None


def verify_internal_api_key(api_key: str = Security(api_key_header)) -> str:
    """Dependency — validates the X-Internal-API-Key header on sensor ingest endpoint."""
    if not api_key or api_key != settings.INTERNAL_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing internal API key.",
        )
    return api_key
