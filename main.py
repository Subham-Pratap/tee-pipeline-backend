import os
import shutil
import tempfile
import uuid
from git import Repo
from git.exc import GitCommandError
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analyzers import run_all_tests

# Create FastAPI app
app = FastAPI(
    title="TEE Pipeline Checker API",
    description="Static analysis for Intel SGX projects",
    version="1.0.0"
)

# Allow requests from your frontend (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    repo_url: str


@app.get("/")
def root():
    return {"status": "ok", "message": "TEE Pipeline Checker API is running"}


@app.post("/analyze")
def analyze_repo(request: AnalyzeRequest):
    repo_url = request.repo_url.strip()

    if not repo_url.startswith(("https://github.com/", "git@github.com:")):
        raise HTTPException(status_code=400, detail="Only GitHub URLs are supported")

    temp_dir = os.path.join(tempfile.gettempdir(), f"tee-analysis-{uuid.uuid4().hex[:8]}")

    try:
        # Stage 1: Clone Repository
        clone_log = f"$ git clone {repo_url}\n"
        try:
            clone_log += "Cloning into temp directory...\n"
            Repo.clone_from(repo_url, temp_dir, depth=1)
            clone_log += "✓ Repository cloned successfully"
            clone_status = "passed"
        except GitCommandError as e:
            clone_log += f"✗ Failed to clone: {str(e)}"
            raise HTTPException(status_code=400, detail=f"Failed to clone repository: {str(e)}")

        # Stage 2: Detect Project Type
        detect_log = "$ Analyzing project structure...\n"
        files = os.listdir(temp_dir)
        detect_log += f"Found {len(files)} items in root\n"
        key_files = [f for f in files if not f.startswith('.')][:10]
        detect_log += f"Contents: {', '.join(key_files)}\n"
        detect_log += "✓ Project structure analyzed"

        # Stage 3: Run Analysis Tests
        test_results = run_all_tests(temp_dir)

        # Count results
        passed = sum(1 for t in test_results if t["status"] == "passed")
        failed = sum(1 for t in test_results if t["status"] == "failed")
        total = len(test_results)

        # Build response
        stages = [
            {
                "name": "Setup",
                "status": "passed",
                "steps": [
                    {"name": "Clone Repository", "status": clone_status, "duration": "1.2s", "log": clone_log},
                    {"name": "Detect Project Type", "status": "passed", "duration": "0.3s", "log": detect_log},
                ]
            },
            {
                "name": "Analysis",
                "status": "passed" if all(t["status"] == "passed" for t in test_results) else "failed",
                "steps": [
                    {"name": t["name"], "status": t["status"], "duration": "0.8s", "log": t["log"]}
                    for t in test_results
                ]
            },
            {
                "name": "Report",
                "status": "passed",
                "steps": [
                    {
                        "name": "Generate Results",
                        "status": "passed",
                        "duration": "0.2s",
                        "log": f"""╔══════════════════════════════════════╗
║     TEE ANALYSIS COMPLETE            ║
╠══════════════════════════════════════╣
║  Tests Passed: {passed}/{total}                   ║
║  Tests Failed: {failed}/{total}                   ║
║  Status: {"PASSED" if failed == 0 else "FAILED":<27} ║
╚══════════════════════════════════════╝"""
                    }
                ]
            }
        ]

        return {
            "success": failed == 0,
            "stages": stages,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "status": "PASSED" if failed == 0 else "FAILED"
            }
        }

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)