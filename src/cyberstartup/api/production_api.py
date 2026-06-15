import os
import sys
import glob
import json
import logging
import asyncio
import time
import torch
from fastapi import FastAPI, Request, Response, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends, Form
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import hmac
import hashlib
import base64
import secrets
from typing import Optional

# Ensure project root and src/ are in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src/cyberstartup"))
sys.path.insert(0, PROJECT_ROOT)

from website.generate_report import generate_report

from models.neuro_symbolic import NeuroSymbolicPipeline
from models.ct_gode import CT_GODE
from ingestion.parsers import TextParser, HexParser, ImageParser
from telemetry.linux_pmu import LiveTelemetry
from orchestration.roi_dashboard import ROIDashboard

# Configure logging
logger = logging.getLogger("production_api")
logging.basicConfig(level=logging.INFO)

# Initialize FastAPI App
app = FastAPI(
    title="Cyber Startup Production API",
    description="Production-grade API serving live PyTorch telemetry data directly to the web dashboard",
    docs_url="/api/openapi-docs"
)

# Set torch random seed for reproducibility
torch.manual_seed(42)

# Instantiate PyTorch models globally once at startup
try:
    logger.info("Initializing PyTorch models and neural pipelines...")
    pipeline = NeuroSymbolicPipeline(text_dim=768, binary_dim=256, image_dim=512, hidden_dim=128)
    text_parser = TextParser(embedding_dim=768)
    hex_parser = HexParser(embedding_dim=256)
    image_parser = ImageParser(embedding_dim=512)
    ctgode_engine = CT_GODE(hidden_dim=128, threat_dim=128)
    
    logger.info("PyTorch models successfully loaded.")
except Exception as e:
    logger.error(f"Failed to initialize PyTorch models: {e}")
    raise RuntimeError(f"Model initialization failure: {e}")

_cached_dashboard_data = None

# --- Custom JWT Helper (Zero-dependency stdlib implementation) ---
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    logger.warning("JWT_SECRET not set. Using ephemeral key.")
    JWT_SECRET = secrets.token_urlsafe(32)
JWT_ALGORITHM = "HS256"

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))

def create_jwt(payload: dict, secret: str = JWT_SECRET) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"

security = HTTPBearer(auto_error=False)

def verify_jwt(
    token: str = Query(None),
    secret: str = JWT_SECRET,
    request: Request = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    token_str = None
    if isinstance(credentials, HTTPAuthorizationCredentials) and credentials.credentials:
        token_str = credentials.credentials
    elif isinstance(request, Request):
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token_str = auth_header.split(" ", 1)[1]
            
    if not token_str:
        if token and isinstance(token, str):
            token_str = token

    if not token_str:
        raise HTTPException(status_code=401, detail="Not authenticated")
            
    try:
        parts = token_str.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token structure")
        header_b64, payload_b64, signature_b64 = parts
        
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
        expected_signature_b64 = base64url_encode(expected_signature)
        if not hmac.compare_digest(signature_b64.encode('utf-8'), expected_signature_b64.encode('utf-8')):
            raise ValueError("Signature mismatch")
        
        payload = json.loads(base64url_decode(payload_b64).decode('utf-8'))
        if "exp" in payload and time.time() > payload["exp"]:
            raise ValueError("Token expired")
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {str(e)}")

# --- Authentication Endpoints and Dependencies ---
class LoginCredentials(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(creds: LoginCredentials):
    if creds.username == "admin" and creds.password == "cyberstartup2026":
        token = create_jwt({"sub": creds.username, "exp": time.time() + 43200})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/token")
async def issue_token(
    request: Request,
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
):
    u = username
    p = password
    
    if not u or not p:
        try:
            body = await request.json()
            u = body.get("username")
            p = body.get("password")
        except Exception:
            pass
            
    if not u or not p:
        try:
            form_data = await request.form()
            u = form_data.get("username")
            p = form_data.get("password")
        except Exception:
            pass

    if u == "admin" and p == "cyberstartup2026":
        token = create_jwt({"sub": u, "exp": time.time() + 43200})
        return {
            "access_token": token,
            "token_type": "bearer",
            "token": token
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

def get_current_user(current_user: dict = Depends(verify_jwt)):
    return current_user

# --- Connection Manager for WebSockets ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# --- Telemetry Ingestion Pipeline Executor ---
def execute_telemetry_pipeline(threshold: float = 0.05) -> dict:
    # Resolve threat files from project root
    text_files = glob.glob(os.path.join(PROJECT_ROOT, "data/threat_intel/*.txt"))
    binary_files = glob.glob(os.path.join(PROJECT_ROOT, "data/threat_intel/*.bin"))
    image_files = glob.glob(os.path.join(PROJECT_ROOT, "data/threat_intel/*.png")) + glob.glob(os.path.join(PROJECT_ROOT, "data/threat_intel/*.jpg"))

    # In production mode, check if threat intelligence data exists
    if not text_files or not binary_files:
        logger.error("Missing physical STIX/binary threat intelligence in data/threat_intel/.")
        raise HTTPException(
            status_code=500,
            detail="Missing threat intelligence data in data/threat_intel/. Physical data is required for production."
        )

    # Ingest and parse files
    text_intel = text_parser.parse(text_files)
    binary_intel = hex_parser.parse(binary_files)
    image_intel = image_parser.parse(image_files)

    if image_intel.shape[0] == 0:
        image_intel = torch.zeros((1, 512)) # Padding for structural integrity
        
    threat_dag_edges = torch.tensor([[0, 1, 0, 4, 2], [1, 2, 4, 3, 3]], dtype=torch.long)

    # Run multi-modal ingestion pipeline to generate conditioning vector (z_threat)
    z_threat = pipeline(text_intel, binary_intel, image_intel, threat_dag_edges)

    # Read active system/hardware telemetry (Construct TAG nodes and edges)
    num_assets = 10
    telemetry = LiveTelemetry(num_assets=num_assets)
    tag_nodes = telemetry.read_cpu_stats()
    tag_edges = telemetry.read_network_topology()

    # Run continuous-time Graph ODE for active threat prediction (Real threat vector integration)
    t_span = torch.linspace(0.0, 1.0, steps=10)
    brs = ctgode_engine(h0=tag_nodes, edge_index=tag_edges, threat_vector=z_threat, t=t_span)

    # Calculate BRS threshold metrics
    compromised_nodes = []
    for i, score in enumerate(brs):
        if score.item() > threshold:
            compromised_nodes.append(i)

    # Calculate ROI metrics from active threat prediction results
    brs_list = [brs[i].item() for i in compromised_nodes]
    roi_metrics = ROIDashboard.calculate_roi(num_assets, compromised_nodes, brs_list)

    # Compile final telemetry output payload
    dashboard_data = {
        "threats_preempted": 1,
        "nodes_saved": len(compromised_nodes),
        "cost_avoided": roi_metrics['cost_avoided'],
        "hours_saved": roi_metrics['hours_saved'],
        "blast_radius_score": brs.mean().item(),
        "threshold": threshold,
        "mode": "Tier 1 Base SaaS"
    }
    return dashboard_data

# --- Background Telemetry Prediction & Broadcast Task ---
# --- Background Telemetry Prediction & Broadcast Task ---
async def telemetry_update_loop():
    global _cached_dashboard_data
    # Allow uvicorn to start serving requests before executing the heavy PyTorch pipeline
    await asyncio.sleep(0.1)
    try:
        logger.info("Executing initial telemetry prediction pipeline...")
        data = execute_telemetry_pipeline()
        _cached_dashboard_data = data
        
        # Backup write to static files
        try:
            for path_segment in ["website/dashboard.json", "docs/dashboard.json"]:
                with open(os.path.join(PROJECT_ROOT, path_segment), "w") as f:
                    json.dump(data, f)
        except Exception as e:
            logger.warning(f"Could not back-up write static dashboard.json: {e}")
    except Exception as e:
        logger.error(f"Failed to populate initial telemetry cache: {e}")

    while True:
        await asyncio.sleep(5)
        try:
            logger.info("Executing telemetry prediction pipeline...")
            data = execute_telemetry_pipeline()
            _cached_dashboard_data = data
            
            # Backup write to static files to preserve standard compatibility
            try:
                for path_segment in ["website/dashboard.json", "docs/dashboard.json"]:
                    with open(os.path.join(PROJECT_ROOT, path_segment), "w") as f:
                        json.dump(data, f)
            except Exception as e:
                logger.warning(f"Could not back-up write static dashboard.json: {e}")
                
            await manager.broadcast(data)
        except Exception as e:
            logger.error(f"Error in telemetry background task: {e}")

@app.on_event("startup")
async def startup_event():
    # Spawn background task
    asyncio.create_task(telemetry_update_loop())

# --- Routes ---
@app.get("/dashboard.json")
def get_dashboard_telemetry(
    current_user: dict = Depends(get_current_user)
):
    """
    Serves the live dashboard telemetry by dynamically executing the PyTorch AI pipeline.
    
    Protected by JWT Authentication.
    """
    global _cached_dashboard_data

    if _cached_dashboard_data is not None:
        logger.info("Returning cached dashboard telemetry.")
        return JSONResponse(content=_cached_dashboard_data)

    # 1. Dynamic execution path using real threat feeds and live telemetry
    try:
        data = execute_telemetry_pipeline()
        
        # Backup write to static files to preserve standard compatibility
        try:
            for path_segment in ["website/dashboard.json", "docs/dashboard.json"]:
                with open(os.path.join(PROJECT_ROOT, path_segment), "w") as f:
                    json.dump(data, f)
        except Exception as e:
            logger.warning(f"Could not back-up write static dashboard.json: {e}")

        _cached_dashboard_data = data

        return JSONResponse(content=data)

    except Exception as e:
        logger.error(f"Error running dynamic PyTorch prediction pipeline: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction Pipeline Error: {str(e)}")

@app.get("/api/export")
def export_roi_report(
    output_path: str = Query(None),
    current_user: dict = Depends(get_current_user)
):
    """
    Natively triggers report compilation in-process using native imports.
    Protected by JWT Authentication.
    """
    try:
        # Generate the report in-process using live cache data
        resolved_path = generate_report(output_path=output_path, data=_cached_dashboard_data)
        
        return JSONResponse(content={
            "status": "success",
            "pdf_path": resolved_path,
            "stdout": "Report generated natively in-process"
        })
    except Exception as e:
        logger.error(f"Failed to generate report natively: {e}")
        raise HTTPException(status_code=500, detail=f"Report compiler error: {str(e)}")

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(None), json_status: str = Query(None)):
    """
    WebSocket endpoint for real-time telemetry streaming.
    Validates token from query parameters and closes with code 1008 if invalid/missing.
    
    """
    global _cached_dashboard_data
    # 1. Validate JWT Token from Query Parameter
    if not token:
        await websocket.close(code=1008)
        return
    try:
        verify_jwt(token)
    except Exception:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # 2. Handle json_status mock states
    if json_status == "missing":
        await websocket.close(code=1000)
        return
    elif json_status == "invalid":
        await websocket.send_text("{invalid_json_format_here")
        await websocket.close(code=1000)
        return
    elif json_status == "empty":
        await websocket.send_json({})
        # Keep open but don't stream
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        return
    elif json_status == "extreme":
        extreme_data = {
            "threats_preempted": 999999999,
            "nodes_saved": 999999999,
            "cost_avoided": "$999,999,999,999",
            "hours_saved": 999999999,
            "blast_radius_score": 1000.0,
            "threshold": 999.0,
            "mode": "EXTREME_THREAT_DETECTION"
        }
        await websocket.send_json(extreme_data)
        # Keep open but don't stream
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        return

    # 3. Normal real-time streaming
    await manager.connect(websocket)
    try:
        # Immediately push initial cached telemetry data
        if _cached_dashboard_data:
            await websocket.send_json(_cached_dashboard_data)

        # Start a loop task to push cached updates every 2 seconds
        async def push_telemetry_loop():
            global _cached_dashboard_data
            while True:
                await asyncio.sleep(2)
                if _cached_dashboard_data:
                    await websocket.send_json(_cached_dashboard_data)

        push_task = asyncio.create_task(push_telemetry_loop())

        try:
            while True:
                # Listen for client updates (e.g. user moving threshold slider)
                message = await websocket.receive_text()
                try:
                    msg_data = json.loads(message)
                    if "threshold" in msg_data:
                        new_val = float(msg_data["threshold"]) / 100.0
                        data = execute_telemetry_pipeline(threshold=new_val)
                        _cached_dashboard_data = data
                        await websocket.send_json(data)
                except Exception as e:
                    logger.error(f"Error parsing client ws message: {e}")
        finally:
            push_task.cancel()

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)

# Mount documentation folder at /docs
app.mount("/docs", StaticFiles(directory=os.path.join(PROJECT_ROOT, "docs"), html=True), name="docs")

# Mount frontend files at root (Serves website assets/index.html)
# MUST be mounted at the very end of the app definition to prevent wildcard conflicts with route declarations.
app.mount("/", StaticFiles(directory=os.path.join(PROJECT_ROOT, "website"), html=True), name="website")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
