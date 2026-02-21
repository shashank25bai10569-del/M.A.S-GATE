import os
import shutil
import uuid
import time
import tempfile
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create folders
UPLOAD_DIR = "uploads"
QUARANTINE_DIR = "quarantine"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Optional imports with graceful fallback
try:
    import magic
    MAGIC_AVAILABLE = True
    print("✅ python-magic loaded")
except ImportError:
    MAGIC_AVAILABLE = False
    print("⚠️ python-magic not available")
    magic = None

try:
    import yara
    YARA_IMPORT_AVAILABLE = True
    print("✅ yara module loaded")
except ImportError:
    YARA_IMPORT_AVAILABLE = False
    print("⚠️ yara module not available")
    yara = None

# Load YARA rules
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "yara_rules", "malware_rules.yar")
rules = None
YARA_AVAILABLE = False

if YARA_IMPORT_AVAILABLE:
    try:
        if os.path.exists(YARA_RULES_PATH):
            rules = yara.compile(filepath=YARA_RULES_PATH)
            print("✅ YARA rules loaded successfully!")
            YARA_AVAILABLE = True
        else:
            print(f"⚠️ Rules file not found: {YARA_RULES_PATH}")
    except Exception as e:
        print(f"⚠️ Error loading YARA rules: {e}")

# WebSocket connections
active_connections = []

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def notify_clients(message: str):
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except:
            pass

def calculate_risk_score(file_path, filename, yara_matches=None):
    """Calculate risk score 0-100"""
    score = 0
    risk_factors = []
    
    # File size
    try:
        if os.path.exists(file_path):
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if size_mb > 10:
                score += 30
                risk_factors.append(f"Very large: {size_mb:.1f}MB")
            elif size_mb > 1:
                score += 15
                risk_factors.append(f"Large: {size_mb:.1f}MB")
    except:
        pass
    
    # Suspicious extensions
    suspicious = {
        '.exe': 60, '.bat': 50, '.sh': 45, '.vbs': 55,
        '.ps1': 60, '.dll': 60, '.bin': 50, '.cmd': 50,
        '.jar': 40, '.js': 30, '.php': 35
    }
    ext = os.path.splitext(filename)[1].lower()
    if ext in suspicious:
        score += suspicious[ext]
        risk_factors.append(f"Suspicious extension: {ext}")
    
    # File header
    try:
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                header = f.read(4)
                if header.startswith(b'MZ'):
                    score += 50
                    risk_factors.append("Windows executable detected")
                elif header.startswith(b'\x7fELF'):
                    score += 50
                    risk_factors.append("Linux executable detected")
    except Exception as e:
        pass
    
    # YARA matches
    if yara_matches:
        score += len(yara_matches) * 20
        for match in yara_matches:
            risk_factors.append(f"YARA match: {match}")
    
    return min(score, 100), risk_factors

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1]
    safe_filename = f"{file_id}{file_ext}"
    final_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Step 1: Save to a temporary file first (this avoids Windows locking issues)
    try:
        content = await file.read()
        
        # Create a temporary file in the same directory
        with tempfile.NamedTemporaryFile(dir=UPLOAD_DIR, delete=False, suffix=file_ext) as tmp_file:
            tmp_path = tmp_file.name
            tmp_file.write(content)
            tmp_file.flush()
        
        await notify_clients(f"📁 Received: {file.filename} ({len(content)} bytes)")
        await notify_clients(f"📁 Temp file: {os.path.basename(tmp_path)}")
        
    except Exception as e:
        await notify_clients(f"❌ Save failed: {str(e)}")
        return JSONResponse(content={"status": "error", "message": str(e)})
    
    # Step 2: Wait a moment for Windows
    time.sleep(0.3)
    
    # Step 3: Now work with the temporary file
    mime_type = "unknown"
    yara_matches = []
    
    # MIME check (optional)
    if MAGIC_AVAILABLE:
        try:
            if os.path.exists(tmp_path):
                mime_type = magic.from_file(tmp_path, mime=True)
                await notify_clients(f"🔍 MIME: {mime_type}")
        except Exception as e:
            await notify_clients(f"⚠️ MIME error: {str(e)}")
    
    # YARA scan
    if YARA_AVAILABLE and rules:
        try:
            await notify_clients("🔍 Scanning with YARA...")
            if os.path.exists(tmp_path):
                matches = rules.match(tmp_path)
                if matches:
                    yara_matches = [m.rule for m in matches]
                    await notify_clients(f"🚨 YARA MATCH: {', '.join(yara_matches)}")
                else:
                    await notify_clients("✅ No YARA threats")
            else:
                await notify_clients("⚠️ Temp file missing")
        except Exception as e:
            await notify_clients(f"⚠️ YARA error: {str(e)}")
    else:
        await notify_clients("ℹ️ YARA unavailable")
    
    # Risk score calculation (using temp file)
    risk_score, factors = calculate_risk_score(tmp_path, file.filename, yara_matches)
    for f in factors:
        await notify_clients(f"⚠️ {f}")
    
    await notify_clients(f"📊 Risk score: {risk_score}/100")
    
    # Step 4: Decision - quarantine if risk > 40 OR any YARA matches
    if risk_score > 40 or yara_matches:
        # Move to quarantine
        quarantine_path = os.path.join(QUARANTINE_DIR, safe_filename)
        try:
            if os.path.exists(tmp_path):
                shutil.move(tmp_path, quarantine_path)
                await notify_clients(f"🔒 FILE QUARANTINED: {safe_filename}")
                
                # Verify quarantine
                if os.path.exists(quarantine_path):
                    await notify_clients(f"✅ Quarantine verified")
                else:
                    await notify_clients("⚠️ Quarantine failed")
            else:
                await notify_clients("❌ Cannot quarantine - temp file missing")
        except Exception as e:
            await notify_clients(f"❌ Quarantine error: {str(e)}")
            # Cleanup temp file if quarantine fails
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        
        status = "malicious" if (yara_matches or risk_score > 70) else "suspicious"
        return JSONResponse(content={
            "status": status,
            "risk_score": risk_score,
            "yara_matches": yara_matches,
            "mime_type": mime_type,
            "message": f"File quarantined - {status}"
        })
    else:
        # Clean file - move to final destination
        try:
            if os.path.exists(tmp_path):
                shutil.move(tmp_path, final_path)
                await notify_clients(f"✅ FILE CLEAN - saved: {safe_filename}")
            else:
                await notify_clients("⚠️ Temp file missing for clean file")
        except Exception as e:
            await notify_clients(f"⚠️ Error saving clean file: {str(e)}")
            # Cleanup
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        
        return JSONResponse(content={
            "status": "clean",
            "risk_score": risk_score,
            "yara_matches": yara_matches,
            "mime_type": mime_type,
            "message": "File is safe"
        })

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "magic_available": MAGIC_AVAILABLE,
        "yara_available": YARA_AVAILABLE,
        "rules_loaded": rules is not None,
        "temp_dir": tempfile.gettempdir(),
        "message": "M.A.S GATEWAY running"
    }

if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("🚀 M.A.S GATEWAY Starting...")
    print("=" * 50)
    print(f"📁 Upload directory: {os.path.abspath(UPLOAD_DIR)}")
    print(f"📁 Quarantine directory: {os.path.abspath(QUARANTINE_DIR)}")
    print(f"🔍 Python-magic: {'✅' if MAGIC_AVAILABLE else '❌'}")
    print(f"🔍 YARA module: {'✅' if YARA_IMPORT_AVAILABLE else '❌'}")
    print(f"🔍 YARA rules: {'✅' if YARA_AVAILABLE else '❌'}")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)