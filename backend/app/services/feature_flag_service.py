from sqlalchemy.orm import Session
from typing import List, Optional
from fastapi import HTTPException, status
from ..models.feature_flag import FeatureFlag, OrgFeatureFlag
from ..schemas.feature_flag import (
    FeatureFlagCreate,
    FeatureFlagResponse,
    OrgFeatureFlagOverride,
    OrgFeatureFlagResponse
)


class FeatureFlagService:
    def __init__(self, db: Session):
        self.db = db

    def is_feature_enabled(self, org_id: str, flag_key: str, session: Session) -> bool:
        """
        Check if a feature flag is enabled for a specific organization.
        Returns the override value if exists, otherwise returns the default value.
        """
        flag = session.query(FeatureFlag).filter(FeatureFlag.key == flag_key).first()
        if not flag:
            return False

        override = session.query(OrgFeatureFlag).filter(
            OrgFeatureFlag.org_id == org_id,
            OrgFeatureFlag.feature_flag_id == flag.id
        ).first()

        if override:
            return override.enabled

        return flag.default_enabled

    def create_global_flag(self, data: FeatureFlagCreate) -> FeatureFlag:
        """
        Create a new global feature flag.
        """
        existing = self.db.query(FeatureFlag).filter(FeatureFlag.key == data.key).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Feature flag with key '{data.key}' already exists"
            )

        flag = FeatureFlag(
            key=data.key,
            name=data.name,
            description=data.description,
            default_enabled=data.default_enabled
        )
        self.db.add(flag)
        self.db.commit()
        self.db.refresh(flag)
        return flag

    def get_all_global_flags(self) -> List[FeatureFlag]:
        """
        Get all global feature flags.
        """
        return self.db.query(FeatureFlag).order_by(FeatureFlag.name).all()

    def get_org_feature_flags(self, org_id: str) -> List[OrgFeatureFlagResponse]:
        """
        Get all feature flags with their effective state for an organization.
        """
        flags = self.db.query(FeatureFlag).order_by(FeatureFlag.name).all()
        result = []

        for flag in flags:
            override = self.db.query(OrgFeatureFlag).filter(
                OrgFeatureFlag.org_id == org_id,
                OrgFeatureFlag.feature_flag_id == flag.id
            ).first()

            if override:
                result.append(OrgFeatureFlagResponse(
                    key=flag.key,
                    name=flag.name,
                    description=flag.description,
                    default_enabled=flag.default_enabled,
                    enabled=override.enabled,
                    overridden=True,
                    rollout_percent=override.rollout_percent
                ))
            else:
                result.append(OrgFeatureFlagResponse(
                    key=flag.key,
                    name=flag.name,
                    description=flag.description,
                    default_enabled=flag.default_enabled,
                    enabled=flag.default_enabled,
                    overridden=False,
                    rollout_percent=None
                ))

        return result

    def set_org_feature_flag(
            self,
            org_id: str,
            flag_key: str,
            data: OrgFeatureFlagOverride
    ) -> OrgFeatureFlagResponse:
        """
        Set or update a feature flag override for an organization.
        """
        flag = self.db.query(FeatureFlag).filter(FeatureFlag.key == flag_key).first()
        if not flag:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Feature flag '{flag_key}' not found"
            )

        override = self.db.query(OrgFeatureFlag).filter(
            OrgFeatureFlag.org_id == org_id,
            OrgFeatureFlag.feature_flag_id == flag.id
        ).first()

        if override:
            override.enabled = data.enabled
            override.rollout_percent = data.rollout_percent
        else:
            override = OrgFeatureFlag(
                org_id=org_id,
                feature_flag_id=flag.id,
                enabled=data.enabled,
                rollout_percent=data.rollout_percent
            )
            self.db.add(override)

        self.db.commit()
        self.db.refresh(override)

        return OrgFeatureFlagResponse(
            key=flag.key,
            name=flag.name,
            description=flag.description,
            default_enabled=flag.default_enabled,
            enabled=override.enabled,
            overridden=True,
            rollout_percent=override.rollout_percent
        )

    def delete_org_feature_flag(
            self,
            org_id: str,
            flag_key: str
    ) -> OrgFeatureFlagResponse:
        """
        Delete a feature flag override for an organization (revert to default).
        """
        flag = self.db.query(FeatureFlag).filter(FeatureFlag.key == flag_key).first()
        if not flag:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Feature flag '{flag_key}' not found"
            )

        override = self.db.query(OrgFeatureFlag).filter(
            OrgFeatureFlag.org_id == org_id,
            OrgFeatureFlag.feature_flag_id == flag.id
        ).first()

        if override:
            self.db.delete(override)
            self.db.commit()

        return OrgFeatureFlagResponse(
            key=flag.key,
            name=flag.name,
            description=flag.description,
            default_enabled=flag.default_enabled,
            enabled=flag.default_enabled,
            overridden=False,
            rollout_percent=None
        )


feature_flag_service = FeatureFlagService