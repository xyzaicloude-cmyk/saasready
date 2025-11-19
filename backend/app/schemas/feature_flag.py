from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class FeatureFlagBase(BaseModel):
    key: str
    name: str
    description: Optional[str] = None
    default_enabled: bool = False


class FeatureFlagCreate(FeatureFlagBase):
    pass


class FeatureFlagResponse(FeatureFlagBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class OrgFeatureFlagOverride(BaseModel):
    enabled: bool
    rollout_percent: Optional[int] = None


class OrgFeatureFlagResponse(BaseModel):
    key: str
    name: str
    description: Optional[str] = None
    default_enabled: bool
    enabled: bool
    overridden: bool
    rollout_percent: Optional[int] = None

    class Config:
        from_attributes = True