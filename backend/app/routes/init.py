from fastapi import APIRouter
from .auth import router as auth_router
from .organizations import router as org_router
from .users import router as users_router
from .audit import router as audit_router
from .test import router as test_router
from .feature_flags import router as feature_flags_router


api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(org_router, prefix="/orgs", tags=["organizations"])
api_router.include_router(users_router, prefix="/users", tags=["users"])
api_router.include_router(audit_router, prefix="/audit", tags=["audit"])
api_router.include_router(test_router, prefix="/test", tags=["test"])
api_router.include_router(feature_flags_router, prefix="/feature-flags", tags=["feature-flags"])  # Fixed variable name


@api_router.get("/test", tags=["test"])
async def api_test():
    return {"message": "API test endpoint works!"}

@api_router.get("/test-cors", tags=["test"])
async def test_cors():
    return {"message": "CORS test endpoint works!"}
__all__ = ["api_router"]