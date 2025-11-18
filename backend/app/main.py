from fastapi import FastAPI
from fastapi import APIRouter

from fastapi.middleware.cors import CORSMiddleware
from app.routes.auth import router as auth_router
from app.routes.organizations import router as org_router
from app.routes.users import router as users_router
from app.routes.audit import router as audit_router
from .core.seed import seed_database
from .core.database import engine, SessionLocal


api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(org_router, prefix="/orgs", tags=["organizations"])
api_router.include_router(users_router, prefix="/users", tags=["users"])
api_router.include_router(audit_router, prefix="/audit", tags=["audit"])

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
        "http://localhost:3000",  # Next.js dev server
        "http://127.0.0.1:3000",  # Alternative localhost
        "http://frontend:3000",    # Docker container name
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    db = SessionLocal()
    try:
        seed_database(db)
        print("✓ Database seeded successfully")
    except Exception as e:
        print(f"✗ Database seeding failed: {e}")
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


@app.on_event("startup")
async def startup_event():
    print("🚀 SaaSReady API starting up...")
    print("📚 API Documentation available at /docs")

@app.get("/test")
async def test_endpoint():
    return {"message": "Test endpoint works!"}

@app.on_event("shutdown")
async def shutdown_event():
    print("👋 SaaSReady API shutting down...")