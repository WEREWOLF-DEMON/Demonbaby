import os
import signal
import asyncio
import subprocess
from datetime import datetime
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


BINARY_PATH = "./demon"
API_HOST = "0.0.0.0"
API_PORT = 8000


class ProcessStart(BaseModel):
    target: str
    port: int
    duration: int


class ProcessManager:
    def __init__(self):
        self.process = None
        self.monitor_task = None
        self.start_time = None
        self.target = None
        self.port = None
        self.duration = None

    def start(self, target: str, port: int, duration: int) -> int:
        if self.is_running():
            raise HTTPException(status_code=409, detail="Process already running")

        cmd = [BINARY_PATH, target, str(port), str(duration)]
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        self.start_time = datetime.utcnow()
        self.target = target
        self.port = port
        self.duration = duration

        if duration > 0:
            self.monitor_task = asyncio.create_task(self._auto_stop(duration))

        return self.process.pid

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
        except:
            pass

        self.process = None
        self.start_time = None
        return True

    def is_running(self) -> bool:
        if self.process and self.process.poll() is None:
            return True
        self.process = None
        return False

    def status(self) -> dict:
        running = self.is_running()
        elapsed = None
        if running and self.start_time:
            elapsed = (datetime.utcnow() - self.start_time).total_seconds()

        return {
            "running": running,
            "pid": self.process.pid if running else None,
            "target": self.target,
            "port": self.port,
            "duration": self.duration,
            "elapsed": int(elapsed) if elapsed else None,
            "remaining": max(0, self.duration - int(elapsed)) if elapsed else None
        }


pm = ProcessManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    pm.stop()


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

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT)
