"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class User(BaseModel):
    """
    Users collection schema (collection name: "user")
    Supports registration by email or phone.
    """
    name: str = Field(..., description="Display name")
    email: Optional[EmailStr] = Field(None, description="Email address (unique)")
    phone: Optional[str] = Field(None, description="Phone number in international format (unique)")
    password_hash: str = Field(..., description="Password hash with salt")
    salt: str = Field(..., description="Salt used for hashing")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    is_active: bool = Field(True, description="Whether user is active")
