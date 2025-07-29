from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends
from pydantic import BaseModel
from typing import Union, Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import logging
import os
import requests
import uuid

from config import (
    API_KEY, 
    PIPELINES_DIR, 
    WEBUI_SECRET_KEY, 
    ENABLE_FORWARD_JWT_TOKEN
)

SESSION_SECRET = WEBUI_SECRET_KEY  # Use same secret as OpenWebUI
ALGORITHM = "HS256"

##############
# Auth Utils
##############

bearer_security = HTTPBearer(auto_error=False)  # Don't auto-error for optional auth
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return (
        pwd_context.verify(plain_password, hashed_password) if hashed_password else None
    )


def get_password_hash(password):
    return pwd_context.hash(password)


def create_token(data: dict, expires_delta: Union[timedelta, None] = None) -> str:
    payload = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
        payload.update({"exp": expire})
    encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[dict]:
    try:
        decoded = jwt.decode(token, SESSION_SECRET, algorithms=[ALGORITHM])
        return decoded
    except Exception as e:
        logging.debug(f"Failed to decode JWT token: {e}")
        return None


def extract_token_from_auth_header(auth_header: str):
    return auth_header[len("Bearer ") :]


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_security),
) -> Optional[dict]:
    """
    Enhanced authentication that supports:
    1. Traditional API Key authentication
    2. JWT Token authentication (from OpenWebUI)
    """
    
    # If no credentials provided
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    
    token = credentials.credentials
    
    # Check if it's a traditional API key
    if token == API_KEY:
        logging.debug("Valid API key authentication")
        return {"type": "api_key", "id": "api_user"}
    
    # Check if JWT forwarding is enabled and try to decode JWT token
    if ENABLE_FORWARD_JWT_TOKEN:
        jwt_data = decode_token(token)
        if jwt_data and "id" in jwt_data:
            logging.info(f"Valid JWT token authentication for user: {jwt_data['id']}")
            return {
                "type": "jwt", 
                "id": jwt_data["id"],
                "jwt_data": jwt_data,
                "jwt_token": token  # Store original token for forwarding
            }
    
    # If we get here, authentication failed
    logging.warning(f"Authentication failed for token: {token[:10]}...")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key or JWT token",
    )


def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_security),
) -> Optional[dict]:
    """
    Optional authentication for internal endpoints.
    When JWT forwarding is enabled, allows anonymous access for internal API calls.
    """
    
    # If JWT forwarding is enabled, allow anonymous access for internal endpoints
    if ENABLE_FORWARD_JWT_TOKEN and not credentials:
        logging.debug("🔓 JWT forwarding enabled - allowing anonymous access for internal endpoint")
        return {"type": "internal", "id": "internal"}
    
    # If credentials provided, validate them
    if credentials:
        token = credentials.credentials
        
        # Check API key
        if token == API_KEY:
            logging.debug("Valid API key authentication")
            return {"type": "api_key", "id": "api_user"}
        
        # Check JWT token (if forwarding enabled)
        if ENABLE_FORWARD_JWT_TOKEN:
            logging.debug(f"🔍 Attempting JWT token validation...")
            jwt_data = decode_token(token)
            if jwt_data and "id" in jwt_data:
                logging.info(f"✅ Valid JWT token authentication for user: {jwt_data['id']}")
                logging.debug(f"🔑 JWT token data keys: {list(jwt_data.keys())}")
                return {
                    "type": "jwt", 
                    "id": jwt_data["id"],
                    "jwt_data": jwt_data,
                    "jwt_token": token  # Store original token for forwarding
                }
            else:
                logging.debug(f"❌ JWT token validation failed - invalid token or missing user ID")
    
    # If no valid auth and JWT forwarding disabled, require auth
    if not ENABLE_FORWARD_JWT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    
    # Allow anonymous access when JWT forwarding enabled
    return {"type": "anonymous", "id": "anonymous"}


def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_security),
) -> dict:
    """
    Strict authentication - no anonymous access allowed
    Use this for endpoints that require authentication
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    
    token = credentials.credentials
    
    # Check API key
    if token == API_KEY:
        return {"type": "api_key", "id": "api_user"}
    
    # Check JWT token
    if ENABLE_FORWARD_JWT_TOKEN:
        jwt_data = decode_token(token)
        if jwt_data and "id" in jwt_data:
            return {
                "type": "jwt", 
                "id": jwt_data["id"],
                "jwt_data": jwt_data,
                "jwt_token": token  # Store original token for forwarding
            }
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key or JWT token",
    )
