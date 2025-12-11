# backend/app/main.py
"""
Main FastAPI application with production-grade middleware and background tasks
Integrated: rate limiting, security headers, request ID, metrics, JWT revocation
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
import logging

# Import routes
from app.routes.auth import router as auth_router
from app.routes.organizations import router as org_router
from app.routes.users import router as users_router
from app.routes.audit import router as audit_router
from app.routes.feature_flags import router as feature_router

# Import core components
from app.core.seed import seed_database
from app.core.database import SessionLocal, check_database_health
from app.core.config import settings

# Import middleware - CRITICAL: These were missing in production
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.metrics import MetricsMiddleware

# Import rate limiter initialization
from app.core.rate_limiter import init_rate_limiter

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' if settings.LOG_FORMAT == 'text'
    else '{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)s","message":"%(message)s"}'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events
    CRITICAL: Initialize rate limiter, seed database, start background tasks
    """
    # Startup
    logger.info("🚀 Starting SaaSReady API")

    # Initialize rate limiter with Redis
    try:
        init_rate_limiter(settings.redis_url_computed)
        logger.info("✅ Rate limiter initialized")
    except Exception as e:
        logger.warning(f"⚠️ Rate limiter initialization failed: {e}")

    # Check database health
    if check_database_health():
        logger.info("✅ Database connection healthy")
    else:
        logger.error("❌ Database connection failed")

    # Seed database
    db = SessionLocal()
    try:
        seed_database(db)
        logger.info("✅ Database seeded successfully")
    except Exception as e:
        logger.error(f"❌ Database seeding failed: {e}")
    finally:
        db.close()

    # Start background tasks (optional - can be run as separate workers)
    # Uncomment to enable in-process background tasks
    # try:
    #     from app.tasks.background_tasks import start_background_tasks
    #     await start_background_tasks()
    #     logger.info("✅ Background tasks started")
    # except Exception as e:
    #     logger.warning(f"⚠️ Background tasks not started: {e}")

    yield

    # Shutdown
    logger.info("👋 Shutting down SaaSReady API")

    # Stop background tasks
    # try:
    #     from app.tasks.background_tasks import stop_background_tasks
    #     await stop_background_tasks()
    #     logger.info("✅ Background tasks stopped")
    # except Exception as e:
    #     logger.warning(f"⚠️ Background tasks cleanup: {e}")


# Create FastAPI application
app = FastAPI(
    title="SaaSReady API",
    description="Enterprise-Ready SaaS Authentication & Multi-Tenancy Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add production middleware (order matters!)
# 1. GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# 2. Request ID for tracing
app.add_middleware(RequestIDMiddleware)

# 3. Security headers
app.add_middleware(SecurityHeadersMiddleware)

# 4. Metrics collection
app.add_middleware(MetricsMiddleware)

# 5. CORS (must be last middleware added, first to execute)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://frontend:3000",
        settings.FRONTEND_BASE_URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-Response-Time"]
)


# Global exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "message": "Request validation failed",
            "details": exc.errors()
        },
        headers={"X-Request-ID": getattr(request.state, "request_id", "unknown")}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred",
            "request_id": getattr(request.state, "request_id", "unknown")
        },
        headers={"X-Request-ID": getattr(request.state, "request_id", "unknown")}
    )


# Include API routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(org_router, prefix="/api/v1/orgs", tags=["organizations"])
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
app.include_router(audit_router, prefix="/api/v1/audit", tags=["audit"])
app.include_router(feature_router, prefix="/api/v1/feature-flags", tags=["feature-flags"])


@app.get("/")
def root():
    """Root endpoint"""
    return {
        "service": "SaaSReady API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health")
def health_check():
    """Health check endpoint with database status"""
    db_healthy = check_database_health()

    return {
        "status": "healthy" if db_healthy else "degraded",
        "service": "saasready-api",
        "version": "1.0.0",
        "database": "connected" if db_healthy else "disconnected"
    }


@app.get("/metrics")
def metrics():
    """
    Metrics endpoint for monitoring
    TODO: Implement Prometheus metrics collection
    """
    from app.core.database import get_pool_status

    try:
        pool_status = get_pool_status()
        return {
            "service": "saasready-api",
            "database_pool": pool_status
        }
    except Exception as e:
        logger.error(f"Metrics error: {e}")
        return {"error": "Metrics unavailable"}