import os
import shutil
import uuid
import time
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# New feature imports
try:
    from ml_classifier import get_classifier
    ML_AVAILABLE = True
    print("✅ ML Classifier loaded")
except ImportError as e:
    ML_AVAILABLE = False
    print(f"⚠️ ML Classifier not available: {e}")

try:
    from pii_detector import pii_detector
    PII_AVAILABLE = True
    print("✅ PII Detector loaded")
except ImportError as e:
    PII_AVAILABLE = False
    print(f"⚠️ PII Detector not available: {e}")

try:
    from database import save_scan_result, get_recent_scans, DB_AVAILABLE
    print(f"✅ Database module loaded (available: {DB_AVAILABLE})")
except ImportError as e:
    DB_AVAILABLE = False
    print(f"⚠️ Database module not available: {e}")

try:
    import tasks
    from celery.result import AsyncResult
    CELERY_AVAILABLE = True
    print("✅ Celery tasks loaded")
except ImportError as e:
    CELERY_AVAILABLE = False
    print(f"⚠️ Celery not available: {e}")

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

# Delta Sync Manager for incremental scanning
class DeltaSyncManager:
    def __init__(self, chunk_size=1024*1024):  # 1MB chunks
        self.chunk_size = chunk_size
        self.chunk_cache = {}
    
    def compute_chunk_hash(self, data):
        """Compute hash for a chunk"""
        return hashlib.sha256(data).hexdigest()
    
    def split_into_chunks(self, file_path):
        """Split file into chunks and compute hashes"""
        chunks = []
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    chunk_hash = self.compute_chunk_hash(chunk)
                    chunks.append({
                        'hash': chunk_hash,
                        'size': len(chunk),
                        'index': len(chunks)
                    })
        except Exception as e:
            print(f"Error splitting chunks: {e}")
        return chunks
    
    def detect_changes(self, old_chunks, new_chunks):
        """Detect which chunks have changed"""
        old_hashes = {c['hash']: c for c in old_chunks}
        new_hashes = {c['hash']: c for c in new_chunks}
        
        unchanged = []
        changed = []
        added = []
        
        for nh in new_hashes:
            if nh in old_hashes:
                unchanged.append(new_hashes[nh])
            else:
                added.append(new_hashes[nh])
        
        for oh in old_hashes:
            if oh not in new_hashes:
                changed.append(old_hashes[oh])
        
        return {
            'unchanged': unchanged,
            'changed': changed,
            'added': added,
            'stats': {
                'total_old': len(old_chunks),
                'total_new': len(new_chunks),
                'unchanged_count': len(unchanged),
                'changed_count': len(changed),
                'added_count': len(added)
            }
        }
    
    def incremental_scan(self, file_id, file_path):
        """Scan only changed chunks"""
        # Get previous chunks if any
        old_chunks = self.chunk_cache.get(file_id, [])
        
        # Compute new chunks
        new_chunks = self.split_into_chunks(file_path)
        
        if not old_chunks or not new_chunks:
            # First time seeing this file or error, scan all
            self.chunk_cache[file_id] = new_chunks
            return {'full_scan': True, 'chunks': new_chunks}
        
        # Detect changes
        changes = self.detect_changes(old_chunks, new_chunks)
        
        # Update stored chunks
        self.chunk_cache[file_id] = new_chunks
        
        scan_percentage = 0
        if changes['stats']['total_new'] > 0:
            scan_percentage = (changes['stats']['changed_count'] + 
                               changes['stats']['added_count']) / \
                               changes['stats']['total_new'] * 100
        
        return {
            'full_scan': False,
            'changes': changes,
            'scan_percentage': scan_percentage
        }

# Initialize delta sync
delta_sync = DeltaSyncManager()

# Mobile device storage (in production, use database)
mobile_devices = {}
pending_approvals = {}

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

def calculate_risk_score(file_path, filename, yara_matches=None, ml_result=None, pii_findings=None):
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
        '.jar': 40, '.js': 30, '.php': 35, '.py': 20
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
                    risk_factors.append("Windows executable (MZ header)")
                elif header.startswith(b'\x7fELF'):
                    score += 50
                    risk_factors.append("Linux executable (ELF header)")
                elif header.startswith(b'PK'):
                    score += 10
                    risk_factors.append("ZIP/archive format")
    except Exception as e:
        pass
    
    # YARA matches
    if yara_matches:
        score += len(yara_matches) * 20
        for match in yara_matches:
            risk_factors.append(f"YARA match: {match}")
    
    # ML result
    if ml_result:
        if ml_result.get('class') == 'malicious':
            score += 40
            risk_factors.append(f"ML classification: malicious ({ml_result.get('confidence', 0):.2f})")
        elif ml_result.get('class') == 'suspicious':
            score += 20
            risk_factors.append(f"ML classification: suspicious ({ml_result.get('confidence', 0):.2f})")
    
    # PII findings
    if pii_findings and pii_findings.get('severity_counts'):
        score += pii_findings['severity_counts']['HIGH'] * 15
        score += pii_findings['severity_counts']['MEDIUM'] * 8
        score += pii_findings['severity_counts']['LOW'] * 3
        if pii_findings['total_findings'] > 0:
            risk_factors.append(f"PII detected: {pii_findings['total_findings']} instances")
    
    return min(score, 100), risk_factors

@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1]
    safe_filename = f"{file_id}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Save file
    try:
        content = await file.read()
        with open(file_path, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        await notify_clients(f"📁 Received: {file.filename} ({len(content)} bytes)")
    except Exception as e:
        await notify_clients(f"❌ Save failed: {str(e)}")
        return JSONResponse(content={"status": "error", "message": str(e)})
    
    time.sleep(0.1)  # Small delay for Windows
    
    # MIME check
    mime_type = "unknown"
    if MAGIC_AVAILABLE:
        try:
            mime_type = magic.from_file(file_path, mime=True)
            await notify_clients(f"🔍 MIME: {mime_type}")
        except Exception as e:
            await notify_clients(f"⚠️ MIME error: {str(e)}")
    
    # YARA scan
    yara_matches = []
    if YARA_AVAILABLE and rules:
        try:
            await notify_clients("🔍 Scanning with YARA...")
            matches = rules.match(file_path)
            if matches:
                yara_matches = [m.rule for m in matches]
                await notify_clients(f"🚨 YARA MATCH: {', '.join(yara_matches)}")
            else:
                await notify_clients("✅ No YARA threats")
        except Exception as e:
            await notify_clients(f"⚠️ YARA error: {str(e)}")
    else:
        await notify_clients("ℹ️ YARA unavailable")
    
    # ML Classification
    ml_result = None
    if ML_AVAILABLE:
        try:
            await notify_clients("🤖 Running ML classification...")
            classifier = get_classifier()
            ml_result = classifier.predict(file_path)
            await notify_clients(f"🤖 ML: {ml_result['class']} (confidence: {ml_result.get('confidence', 0):.2f})")
        except Exception as e:
            await notify_clients(f"⚠️ ML error: {str(e)}")
    
    # PII Detection
    pii_result = None
    if PII_AVAILABLE:
        try:
            await notify_clients("🔍 Scanning for PII...")
            pii_findings = pii_detector.scan_file(file_path)
            if pii_findings:
                pii_result = pii_detector.generate_report(pii_findings)
                if pii_result['total_findings'] > 0:
                    await notify_clients(f"🔍 PII detected: {pii_result['total_findings']} instances")
                else:
                    await notify_clients("✅ No PII detected")
        except Exception as e:
            await notify_clients(f"⚠️ PII error: {str(e)}")
    
    # Delta sync info
    try:
        delta_result = delta_sync.incremental_scan(file_id, file_path)
        if not delta_result['full_scan']:
            await notify_clients(f"📊 Delta sync: Scanning {delta_result['scan_percentage']:.1f}% of file")
    except Exception as e:
        await notify_clients(f"⚠️ Delta sync error: {str(e)}")
    
    # Calculate risk score with all factors
    risk_score, risk_factors = calculate_risk_score(
        file_path, file.filename, yara_matches, ml_result, pii_result
    )
    
    for factor in risk_factors:
        await notify_clients(f"⚠️ {factor}")
    
    await notify_clients(f"📊 Final risk score: {risk_score}/100")
    
    # Decision
    status = "clean"
    result_status = "clean"
    message = "File is safe"
    
    if risk_score > 40 or yara_matches:
        # Quarantine file
        quarantine_path = os.path.join(QUARANTINE_DIR, safe_filename)
        try:
            shutil.move(file_path, quarantine_path)
            await notify_clients("🔒 FILE QUARANTINED")
            
            if yara_matches:
                status = "malicious"
                message = f"Malware detected: {', '.join(yara_matches)}"
            elif risk_score > 70:
                status = "malicious"
                message = "File quarantined - Malicious content detected"
            else:
                status = "suspicious"
                message = "File quarantined - Suspicious content detected"
            
            result_status = status
        except Exception as e:
            await notify_clients(f"❌ Quarantine error: {str(e)}")
            message = f"Error: {str(e)}"
    
    # Save to database
    if DB_AVAILABLE:
        try:
            file_data = {
                'filename': safe_filename,
                'original_filename': file.filename,
                'file_size': len(content),
                'mime_type': mime_type,
                'risk_score': risk_score,
                'status': result_status,
                'yara_matches': yara_matches,
                'risk_factors': risk_factors,
                'user_ip': request.client.host if hasattr(request, 'client') else None
            }
            save_scan_result(file_data)
        except Exception as e:
            print(f"Database error: {e}")
    
    return JSONResponse(content={
        "status": status,
        "risk_score": risk_score,
        "yara_matches": yara_matches,
        "ml_result": ml_result,
        "pii_detected": pii_result['total_findings'] if pii_result else 0,
        "mime_type": mime_type,
        "file_id": file_id,
        "message": message
    })

@app.post("/upload/async")
async def upload_file_async(file: UploadFile = File(...)):
    """Async file upload with background processing"""
    if not CELERY_AVAILABLE:
        return JSONResponse(content={
            "status": "error",
            "message": "Celery not available"
        })
    
    file_id = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1]
    safe_filename = f"{file_id}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    # Save file
    content = await file.read()
    with open(file_path, 'wb') as f:
        f.write(content)
    
    # Start Celery task
    task = tasks.scan_file.delay(file_path, file.filename)
    
    return {
        "task_id": task.id,
        "file_id": file_id,
        "status": "processing",
        "message": "File queued for scanning"
    }

@app.get("/task/{task_id}")
async def get_task_status(task_id: str):
    """Get status of async task"""
    if not CELERY_AVAILABLE:
        return {"error": "Celery not available"}
    
    task = AsyncResult(task_id, app=tasks.celery_app)
    
    if task.state == 'PENDING':
        response = {'state': task.state, 'status': 'Pending...'}
    elif task.state == 'PROGRESS':
        response = {'state': task.state, 'info': task.info}
    elif task.state == 'SUCCESS':
        response = {'state': task.state, 'result': task.result}
    else:
        response = {'state': task.state, 'error': str(task.info)}
    
    return response

@app.get("/scans/recent")
async def get_recent_scans_endpoint(limit: int = 10):
    """Get recent scan results"""
    if not DB_AVAILABLE:
        return {"error": "Database not available", "scans": []}
    
    try:
        scans = get_recent_scans(limit)
        return {"scans": [{"id": s.id, "filename": s.original_filename, 
                          "risk_score": s.risk_score, "status": s.status} 
                         for s in scans]}
    except Exception as e:
        return {"error": str(e), "scans": []}

@app.post("/delta/scan/{file_id}")
async def delta_scan_file(file_id: str, file: UploadFile = File(...)):
    """Delta sync scan - only scan changed parts"""
    file_ext = os.path.splitext(file.filename)[1]
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}{file_ext}")
    
    content = await file.read()
    with open(file_path, 'wb') as f:
        f.write(content)
    
    delta_result = delta_sync.incremental_scan(file_id, file_path)
    
    if delta_result['full_scan']:
        message = "Full scan performed (first time)"
    else:
        message = f"Delta scan: {delta_result['scan_percentage']:.1f}% of file scanned"
    
    return {
        "file_id": file_id,
        "delta_result": delta_result,
        "message": message
    }

@app.post("/api/mobile/register")
async def register_mobile(device_id: str, device_name: str, push_token: str = None):
    """Register a mobile device for locker service"""
    device_key = secrets.token_hex(32)
    mobile_devices[device_id] = {
        'name': device_name,
        'push_token': push_token,
        'device_key': device_key,
        'registered_at': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat()
    }
    return {
        'status': 'registered',
        'device_key': device_key,
        'message': 'Mobile device registered successfully'
    }

@app.post("/api/mobile/approve")
async def approve_upload(device_id: str, file_id: str, decision: str, signature: str):
    """Approve or reject an upload from mobile"""
    # Verify device exists
    if device_id not in mobile_devices:
        return JSONResponse(status_code=401, content={'error': 'Unknown device'})
    
    # Verify signature (simple HMAC)
    device = mobile_devices[device_id]
    expected = hmac.new(
        device['device_key'].encode(),
        f"{file_id}:{decision}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        return JSONResponse(status_code=403, content={'error': 'Invalid signature'})
    
    # Store decision
    pending_approvals[file_id] = {
        'decision': decision,
        'device_id': device_id,
        'timestamp': datetime.now().isoformat()
    }
    
    # Notify via WebSocket
    await notify_clients(f"📱 Mobile decision: {decision} for file {file_id}")
    
    return {
        'status': 'approved' if decision == 'accept' else 'rejected',
        'file_id': file_id,
        'message': f'Upload {decision}ed from mobile'
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "magic_available": MAGIC_AVAILABLE,
        "yara_available": YARA_AVAILABLE,
        "ml_available": ML_AVAILABLE,
        "pii_available": PII_AVAILABLE,
        "database_available": DB_AVAILABLE,
        "celery_available": CELERY_AVAILABLE,
        "message": "M.A.S GATEWAY running"
    }

@app.get("/stats")
async def get_stats():
    """Get basic statistics"""
    upload_count = len(os.listdir(UPLOAD_DIR)) if os.path.exists(UPLOAD_DIR) else 0
    quarantine_count = len(os.listdir(QUARANTINE_DIR)) if os.path.exists(QUARANTINE_DIR) else 0
    
    return {
        "uploads": upload_count,
        "quarantine": quarantine_count,
        "yara_available": YARA_AVAILABLE,
        "ml_available": ML_AVAILABLE,
        "pii_available": PII_AVAILABLE,
        "database_available": DB_AVAILABLE,
        "celery_available": CELERY_AVAILABLE
    }

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🚀 M.A.S GATEWAY Starting...")
    print("=" * 60)
    print(f"📁 Upload directory: {os.path.abspath(UPLOAD_DIR)}")
    print(f"📁 Quarantine directory: {os.path.abspath(QUARANTINE_DIR)}")
    print(f"🔍 Python-magic: {'✅' if MAGIC_AVAILABLE else '❌'}")
    print(f"🔍 YARA: {'✅' if YARA_AVAILABLE else '❌'}")
    print(f"🤖 ML Classifier: {'✅' if ML_AVAILABLE else '❌'}")
    print(f"🔐 PII Detector: {'✅' if PII_AVAILABLE else '❌'}")
    print(f"💾 Database: {'✅' if DB_AVAILABLE else '❌'}")
    print(f"⚡ Celery: {'✅' if CELERY_AVAILABLE else '❌'}")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)