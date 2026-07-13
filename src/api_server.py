from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from report_gen import ReportGenerator
import os

# Import the logic from main.py
from main import fetch_and_store_nvd, map_internal_assets

app = FastAPI(title="Project Nexus - API API")
generator = ReportGenerator()

class LatexPayload(BaseModel):
    latex_code: str
    filename: str = "Daily_Threat_Intel"

@app.get("/run-pipeline")
async def trigger_pipeline():
    """n8n calls this to trigger NVD fetching and Asset matching."""
    try:
        print("[*] Pipeline triggered via API...")
        fetch_and_store_nvd()
        map_internal_assets()
        return {"status": "success", "message": "NVD data fetched and assets correlated."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/compile-pdf")
async def compile_pdf(payload: LatexPayload):
    """n8n calls this to send LaTeX and receive a PDF file."""
    print(f"[*] Received compilation request for {payload.filename}...")
    
    clean_latex = payload.latex_code.replace("```latex", "").replace("```", "").strip()
    success = generator.generate_pdf(clean_latex, payload.filename)
    
    if success:
        pdf_path = generator.pdf_dir / f"{payload.filename}.pdf"
        if pdf_path.exists():
            print(f"[+] Returning compiled PDF: {pdf_path}")
            return FileResponse(
                path=pdf_path, 
                media_type='application/pdf', 
                filename=f"{payload.filename}.pdf"
            )
    raise HTTPException(status_code=500, detail="Failed to compile XeLaTeX PDF.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)