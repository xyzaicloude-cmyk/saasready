from fastapi import APIRouter

router = APIRouter()

@router.get("/test")
def test_endpoint():
    return {"message": "Test endpoint works!"}

@router.get("/test-cors")
def test_cors():
    return {"message": "CORS is working!"}