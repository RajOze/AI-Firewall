from app.models.request import AnalyzeRequest
from app.models.response import AnalyzeResponse
from app.services.detector import analyze_text
from fastapi import APIRouter

router = APIRouter(
    prefix="/analyze",
    tags=["Analysis"],
)


@router.post("/", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    result = analyze_text(request.text)
    return AnalyzeResponse(**result)
