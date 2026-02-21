from celery import Celery
import os
import time
import json

# Try to import yara (optional)
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

# Configure Celery
celery_app = Celery(
    'tasks',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
)

@celery_app.task(bind=True, name='tasks.scan_file')
def scan_file(self, file_path, filename):
    """
    Async file scanning task
    """
    total_steps = 4
    current_step = 0
    
    # Step 1: Basic analysis
    current_step += 1
    self.update_state(
        state='PROGRESS',
        meta={'current': current_step, 'total': total_steps,
              'status': 'Analyzing file structure...'}
    )
    time.sleep(0.5)
    
    # Step 2: YARA scan
    current_step += 1
    self.update_state(
        state='PROGRESS',
        meta={'current': current_step, 'total': total_steps,
              'status': 'Scanning with YARA...'}
    )
    
    yara_matches = []
    if YARA_AVAILABLE and os.path.exists('yara_rules/malware_rules.yar'):
        try:
            rules = yara.compile(filepath='yara_rules/malware_rules.yar')
            matches = rules.match(file_path)
            if matches:
                yara_matches = [m.rule for m in matches]
        except Exception as e:
            yara_matches = [f"Error: {str(e)}"]
    
    # Step 3: Risk calculation
    current_step += 1
    self.update_state(
        state='PROGRESS',
        meta={'current': current_step, 'total': total_steps,
              'status': 'Calculating risk score...'}
    )
    
    risk_score = 0
    if os.path.exists(file_path):
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if size_mb > 10:
            risk_score += 30
        elif size_mb > 1:
            risk_score += 15
    
    if yara_matches:
        risk_score += len(yara_matches) * 20
    
    # Step 4: Finalize
    current_step += 1
    self.update_state(
        state='PROGRESS',
        meta={'current': current_step, 'total': total_steps,
              'status': 'Finalizing results...'}
    )
    
    return {
        'filename': filename,
        'yara_matches': yara_matches,
        'risk_score': min(risk_score, 100),
        'status': 'completed',
        'scan_time': time.time()
    }

@celery_app.task(name='tasks.cleanup_old_files')
def cleanup_old_files():
    """Clean up old files from uploads folder"""
    upload_dir = 'uploads'
    if os.path.exists(upload_dir):
        now = time.time()
        count = 0
        for f in os.listdir(upload_dir):
            f_path = os.path.join(upload_dir, f)
            if os.path.isfile(f_path):
                # Remove files older than 1 hour
                if now - os.path.getmtime(f_path) > 3600:
                    os.remove(f_path)
                    count += 1
    return f"Cleaned up {count} files from {upload_dir}"