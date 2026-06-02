import os
import signal
import asyncio
import subprocess
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ═══════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════
BINARY_PATH = "./demon"
API_HOST = "0.0.0.0"
API_PORT = 8000


# ═══════════════════════════════════════
# MODELS
# ═══════════════════════════════════════
class ProcessStart(BaseModel):
    ip: str = Field(..., description="Target IP address")
    port: int = Field(..., ge=1, le=65535, description="Target port (1-65535)")
    time: int = Field(..., ge=1, le=7200, description="Duration in seconds (1-7200)")
    size: int = Field(1200, ge=100, le=65500, description="Packet size in bytes (100-65500)")
    threads: int = Field(300, ge=1, le=1000, description="Number of threads (1-1000)")


# ═══════════════════════════════════════
# PROCESS MANAGER
# ═══════════════════════════════════════
class ProcessManager:
    def __init__(self):
        self.process = None
        self.monitor_task = None
        self.start_time = None
        self.target_ip = None
        self.target_port = None
        self.duration = None
        self.packet_size = None
        self.thread_count = None
        self.pid = None

    def start(self, ip: str, port: int, time: int, size: int, threads: int) -> int:
        if self.is_running():
            raise HTTPException(status_code=409, detail="Process already running. Stop it first.")

        cmd = [BINARY_PATH, ip, str(port), str(time), str(size), str(threads)]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"Binary not found: {BINARY_PATH}")
        except PermissionError:
            raise HTTPException(status_code=500, detail=f"Binary not executable. Run: chmod +x {BINARY_PATH}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to start: {str(e)}")

        # Check if process started successfully
        try:
            self.process.wait(timeout=0.5)
            exit_code = self.process.returncode
            self.process = None
            raise HTTPException(
                status_code=400,
                detail=f"Binary exited immediately (code {exit_code}). Check arguments."
            )
        except subprocess.TimeoutExpired:
            pass

        self.start_time = datetime.utcnow()
        self.target_ip = ip
        self.target_port = port
        self.duration = time
        self.packet_size = size
        self.thread_count = threads
        self.pid = self.process.pid

        if time > 0:
            self.monitor_task = asyncio.create_task(self._auto_stop(time))

        return self.pid

    async def _auto_stop(self, duration: int):
        await asyncio.sleep(duration)
        self.stop()

    def stop(self) -> bool:
        if self.monitor_task:
            self.monitor_task.cancel()
            self.monitor_task = None

        if not self.process:
            return False

        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                self.process.wait()
        except ProcessLookupError:
            pass
        except Exception:
            pass

        self.process = None
        self.start_time = None
        self.pid = None
        return True

    def is_running(self) -> bool:
        if self.process:
            if self.process.poll() is None:
                return True
            self.process = None
            self.pid = None
            self.start_time = None
        return False

    def status(self) -> dict:
        running = self.is_running()
        
        if running:
            elapsed = int((datetime.utcnow() - self.start_time).total_seconds())
            remaining = max(0, self.duration - elapsed)
            return {
                "running": True,
                "pid": self.pid,
                "target": self.target_ip,
                "port": self.target_port,
                "time": self.duration,
                "size": self.packet_size,
                "threads": self.thread_count,
                "elapsed": elapsed,
                "remaining": remaining
            }
        else:
            return {
                "running": False,
                "pid": 0,
                "target": "",
                "port": 0,
                "time": 0,
                "size": 0,
                "threads": 0,
                "elapsed": 0,
                "remaining": 0
            }


pm = ProcessManager()


# ═══════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    pm.stop()


app = FastAPI(
    title="Demon Process Manager",
    version="2.0.1",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "Demon Process Manager",
        "version": "2.0.1",
        "binary": BINARY_PATH,
        "usage": "./demon [IP] [PORT] [TIME] [SIZE] [THREADS]"
    }


@app.get("/status")
async def get_status():
    return pm.status()


@app.post("/start")
async def start_process(data: ProcessStart):
    if pm.is_running():
        raise HTTPException(
            status_code=409,
            detail=f"Process already running (PID: {pm.pid}). Use /stop first."
        )

    pid = pm.start(
        ip=data.ip,
        port=data.port,
        time=data.time,
        size=data.size,
        threads=data.threads
    )

    return {
        "success": True,
        "message": f"Process started (PID: {pid})",
        "pid": pid,
        "target": data.ip,
        "port": data.port,
        "time": data.time,
        "size": data.size,
        "threads": data.threads
    }


@app.post("/stop")
async def stop_process():
    if not pm.is_running():
        raise HTTPException(status_code=404, detail="No process running")

    pm.stop()
    return {
        "success": True,
        "message": "Process stopped"
    }


# ═══════════════════════════════════════
# MAIN
# ═══════════════════════════════════════
if __name__ == "__main__":
    print("=" * 50)
    print("Demon Process Manager v2.0.1")
    print(f"Binary: {BINARY_PATH}")
    print(f"API: http://{API_HOST}:{API_PORT}")
    print("=" * 50)
    uvicorn.run(app, host=API_HOST, port=API_PORT)        self.pid = None
        return True

    def is_running(self) -> bool:
        if self.process:
            if self.process.poll() is None:
                return True
            # Process exited but we didn't catch it
            self.process = None
            self.pid = None
            self.start_time = None
        return False

    def status(self) -> dict:
        running = self.is_running()
        elapsed = None
        remaining = None

        if running and self.start_time:
            elapsed = int((datetime.utcnow() - self.start_time).total_seconds())
            remaining = max(0, self.duration - elapsed)

        return {
            "running": running,
            "pid": self.pid,
            "target": self.target_ip,
            "port": self.target_port,
            "time": self.duration,
            "size": self.packet_size,
            "threads": self.thread_count,
            "elapsed": elapsed,
            "remaining": remaining
        }


pm = ProcessManager()


# ═══════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Cleanup on shutdown
    yield
    pm.stop()


app = FastAPI(
    title="Demon Process Manager",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ═══════════════════════════════════════
# STARTUP CHECK
# ═══════════════════════════════════════
@app.on_event("startup")
async def startup_check():
    if not os.path.exists(BINARY_PATH):
        print(f"WARNING: Binary not found at {BINARY_PATH}")
    elif not os.access(BINARY_PATH, os.X_OK):
        print(f"WARNING: Binary not executable. Run: chmod +x {BINARY_PATH}")
    else:
        print(f"Binary ready: {BINARY_PATH}")


# ═══════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "Demon Process Manager",
        "version": "2.0.0",
        "binary": BINARY_PATH,
        "usage": "./demon [IP] [PORT] [TIME] [SIZE] [THREADS]"
    }


@app.get("/status", response_model=StatusResponse)
async def get_status():
    return pm.status()


@app.post("/start", response_model=ProcessResponse)
async def start_process(data: ProcessStart):
    """
    Start the binary with:
    - ip: Target IP address
    - port: Target port
    - time: Duration in seconds
    - size: Packet size in bytes
    - threads: Number of threads
    """
    if pm.is_running():
        raise HTTPException(
            status_code=409,
            detail=f"Process already running (PID: {pm.pid}). Use /stop first."
        )

    pid = pm.start(
        ip=data.ip,
        port=data.port,
        time=data.time,
        size=data.size,
        threads=data.threads
    )

    return {
        "success": True,
        "message": f"Process started with PID {pid}",
        "pid": pid,
        "target": data.ip,
        "port": data.port,
        "time": data.time,
        "size": data.size,
        "threads": data.threads
    }


@app.post("/stop", response_model=ProcessResponse)
async def stop_process():
    if not pm.is_running():
        raise HTTPException(status_code=404, detail="No process running")

    pm.stop()
    return {
        "success": True,
        "message": "Process stopped"
    }


# ═══════════════════════════════════════
# MAIN
# ═══════════════════════════════════════
if __name__ == "__main__":
    print("=" * 50)
    print("Demon Process Manager v2.0")
    print(f"Binary: {BINARY_PATH}")
    print(f"Usage: ./demon [IP] [PORT] [TIME] [SIZE] [THREADS]")
    print(f"API: http://{API_HOST}:{API_PORT}")
    print("=" * 50)
    uvicorn.run(app, host=API_HOST, port=API_PORT)

app = FastAPI(title="Process Manager", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/")
async def root():
    return {"service": "Process Manager API", "version": "1.0"}


@app.get("/status")
async def get_status():
    return pm.status()


@app.post("/start")
async def start_process(data: ProcessStart):
    if pm.is_running():
        raise HTTPException(status_code=409, detail="Process already running. Use /stop first.")
    pid = pm.start(data.target, data.port, data.duration)
    return {"success": True, "message": "Process started", "pid": pid}


@app.post("/stop")
async def stop_process():
    if not pm.is_running():
        raise HTTPException(status_code=404, detail="No process running")
    pm.stop()
    return {"success": True, "message": "Process stopped"}


@app.get("/debug")
async def debug():
    import os
    return {
        "cwd": os.getcwd(),
        "files": os.listdir("."),
        "demon_exists": os.path.exists("./demon"),
        "demon_executable": os.access("./demon", os.X_OK)
    }


@app.get("/test_demon")
async def test_demon():
    import subprocess

    try:
        result = subprocess.run(
            ["./demon"],
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT)
