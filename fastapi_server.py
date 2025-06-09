from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from vuln_agent import main_run
import asyncio
from concurrent.futures import ThreadPoolExecutor

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow your Next.js app
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.get("/analyze")
async def analyze(file: str):
    full_file = f"/System/Applications/{file}/Contents/MacOS/{file.split('.')[0]}"
    
    results, trace = await main_run(full_file)

    return {"result": str(results), "trace_url": str(trace)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
