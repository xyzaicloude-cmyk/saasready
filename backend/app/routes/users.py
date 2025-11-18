from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.dependencies import get_current_user
from ..schemas.user import UserResponse
from ..models.user import User

router = APIRouter()


@router.get("/me", response_model=UserResponse)
def get_my_profile(
        current_user: User = Depends(get_current_user)
):
    return current_user