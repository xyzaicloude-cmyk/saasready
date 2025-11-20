from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from app.routes.auth import router as auth_router
from app.routes.organizations import router as org_router
from app.routes.users import router as users_router
from app.routes.audit import router as audit_router
from app.routes.feature_flags import router as feature_router
from .core.seed import seed_database
from .core.database import SessionLocal

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(org_router, prefix="/orgs", tags=["organizations"])
api_router.include_router(users_router, prefix="/users", tags=["users"])
api_router.include_router(audit_router, prefix="/audit", tags=["audit"])
api_router.include_router(feature_router, prefix="/feature-flags", tags=["feature-flags"])

__all__ = ["api_router"]

app = FastAPI(
    title="SaaSReady API",
    description="Enterprise-Ready SaaS Starter Kit with Multi-Tenancy and RBAC",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://frontend:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    """Seed database on startup"""
    db = SessionLocal()
    try:
        seed_database(db)
        print("✓ Database seeded successfully")
    except Exception as e:
        print(f"✗ Database seeding failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()


# Include routers
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
def root():
    return {
        "message": "SaaSReady API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "saasready-api",
        "version": "1.0.0"
    }


@app.get("/test")
async def test_endpoint():
    return {"message": "Test endpoint works!"}


@app.on_event("shutdown")
async def shutdown_event():
    print("👋 SaaSReady API shutting down...")