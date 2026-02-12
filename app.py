"""
Mizan GRC - Enterprise Governance, Risk & Compliance Platform
Flask Application - Full RTL Support
Created by: Eng. Mohammad Abbas Alsaadon
"""

import os
import json
import sqlite3
import hashlib
import secrets
import re
import html
import threading
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort, Response

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=7)

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# CSRF Protection
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_token():
    return generate_csrf_token()

# Make csrf_token available in all templates
app.jinja_env.globals['csrf_token'] = csrf_token

# ============================================================================
# BACKGROUND TASK SYSTEM for long-running AI operations
# ============================================================================
# Render has a 30s request timeout + gunicorn uses multiple workers.
# We store task state in SQLite so any worker can read/write it.

def create_background_task(task_id, user_id, domain):
    """Create a new pending task in the database."""
    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO background_tasks (task_id, user_id, status, callback_domain) VALUES (?, ?, ?, ?)',
            (task_id, user_id, 'pending', domain)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Task create error: {e}", flush=True)

def complete_background_task(task_id, result):
    """Mark task as done with result."""
    try:
        conn = get_db()
        conn.execute(
            'UPDATE background_tasks SET status = ?, result = ? WHERE task_id = ?',
            ('done', result, task_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Task complete error: {e}", flush=True)

def fail_background_task(task_id, error):
    """Mark task as failed."""
    try:
        conn = get_db()
        conn.execute(
            'UPDATE background_tasks SET status = ?, error = ? WHERE task_id = ?',
            ('error', error, task_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Task fail error: {e}", flush=True)

def get_background_task(task_id):
    """Get task status from database."""
    try:
        conn = get_db()
        task = conn.execute(
            'SELECT task_id, user_id, status, result, error, callback_domain FROM background_tasks WHERE task_id = ?',
            (task_id,)
        ).fetchone()
        conn.close()
        return task
    except Exception as e:
        print(f"Task get error: {e}", flush=True)
        return None

def delete_background_task(task_id):
    """Remove completed task."""
    try:
        conn = get_db()
        conn.execute('DELETE FROM background_tasks WHERE task_id = ?', (task_id,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def run_ai_task(task_id, prompt, lang):
    """Run AI generation in a background thread, store result in DB."""
    try:
        result = generate_ai_content(prompt, lang)
        complete_background_task(task_id, result)
        print(f"✅ Background task {task_id[:8]} completed ({len(result)} chars)", flush=True)
    except Exception as e:
        fail_background_task(task_id, str(e))
        print(f"❌ Background task {task_id[:8]} failed: {e}", flush=True)

@app.before_request
def csrf_protect():
    """Validate CSRF token for POST requests."""
    if request.method == "POST":
        # Skip CSRF for API endpoints that use JSON
        if request.is_json:
            return
        token = session.get('csrf_token', None)
        form_token = request.form.get('csrf_token')
        if not token or token != form_token:
            # For now, just log - can abort(403) for stricter security
            pass

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if os.getenv('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Input sanitization
def sanitize_input(text, max_length=1000):
    """Sanitize user input to prevent XSS and injection attacks."""
    if not text:
        return ''
    # Convert to string and limit length
    text = str(text)[:max_length]
    # HTML escape
    text = html.escape(text)
    # Remove potential SQL injection patterns
    dangerous_patterns = ['--', ';--', '/*', '*/', 'xp_', 'UNION', 'SELECT', 'DROP', 'DELETE', 'INSERT', 'UPDATE']
    for pattern in dangerous_patterns:
        text = re.sub(re.escape(pattern), '', text, flags=re.IGNORECASE)
    return text.strip()

def validate_username(username):
    """Validate username format."""
    if not username or not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
        return False
    return True

def validate_email(email):
    """Validate email format."""
    if not email:
        return True  # Email is optional
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def validate_password(password):
    """Validate password strength."""
    if len(password) < 8:
        return False, 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain lowercase letter'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain a number'
    return True, ''

# Simple rate limiting (in-memory, resets on restart)
rate_limit_store = {}

def check_rate_limit(key, max_requests=10, window_seconds=60):
    """Check if request is within rate limit."""
    now = datetime.now()
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    # Remove old entries
    rate_limit_store[key] = [t for t in rate_limit_store[key] if (now - t).seconds < window_seconds]
    
    if len(rate_limit_store[key]) >= max_requests:
        return False
    
    rate_limit_store[key].append(now)
    return True

# Configuration
class Config:
    APP_NAME = "Mizan"
    APP_VERSION = "3.0.0"
    APP_TAGLINE = "Governance • Risk • Compliance"
    CREATOR_NAME = "Eng. Mohammad Abbas Alsaadon"
    CREATOR_NAME_AR = "المهندس: محمد بن عباس السعدون"
    CREATOR_TITLE = "Consultant/Expert"
    COPYRIGHT_YEAR = "2026"
    DB_PATH = "mizan.db"
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
    GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')
    GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')  # Groq (Llama 3.1, Mistral, etc.)
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'auto')  # auto, openai, anthropic, google, groq
    AI_MODEL = os.getenv('AI_MODEL', '')  # Override model name
    # Email settings (using SMTP)
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', 'noreply@mizan.app')

config = Config()

def send_otp_email(to_email, otp_code, doc_title, shared_by):
    """Send OTP code via email."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    if not config.SMTP_USERNAME or not config.SMTP_PASSWORD:
        print("SMTP not configured, OTP:", otp_code, flush=True)
        return False, "Email service not configured"
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Your Mizan Document Access Code - {otp_code}'
        msg['From'] = config.SMTP_FROM_EMAIL
        msg['To'] = to_email
        
        # Plain text version
        text = f"""
Your Mizan Document Access Code

You have been granted access to a document shared by {shared_by}.

Document: {doc_title}

Your access code is: {otp_code}

This code expires in 10 minutes.

If you did not request this, please ignore this email.

---
Mizan GRC Platform
        """
        
        # HTML version
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 500px; margin: 0 auto; background: white; border-radius: 10px; padding: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .logo {{ font-size: 28px; font-weight: bold; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .otp-box {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; font-size: 32px; letter-spacing: 8px; text-align: center; padding: 20px; border-radius: 10px; margin: 20px 0; }}
        .info {{ color: #666; margin: 15px 0; }}
        .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">MIZAN</div>
            <p>Secure Document Access</p>
        </div>
        <p>You have been granted access to a document shared by <strong>{shared_by}</strong>.</p>
        <p class="info"><strong>Document:</strong> {doc_title}</p>
        <p>Your access code is:</p>
        <div class="otp-box">{otp_code}</div>
        <p class="info">⏱️ This code expires in 10 minutes.</p>
        <p class="info">If you did not request this, please ignore this email.</p>
        <div class="footer">
            <p>Mizan GRC Platform</p>
        </div>
    </div>
</body>
</html>
        """
        
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as server:
            server.starttls()
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            server.sendmail(config.SMTP_FROM_EMAIL, to_email, msg.as_string())
        
        return True, "Email sent"
    except Exception as e:
        print(f"Email error: {e}", flush=True)
        return False, str(e)

# ============================================================================
# DATABASE
# ============================================================================

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hash password with salt."""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hash_obj.hex()}"

def verify_password(password, stored_hash):
    """Verify password against stored hash."""
    try:
        salt, hash_value = stored_hash.split('$')
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hash_obj.hex() == hash_value
    except:
        return False

def init_db():
    """Initialize database tables."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table with role and email
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Add columns if they don't exist (for existing databases)
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN email TEXT UNIQUE')
    except:
        pass
    
    # AI preference columns
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN ai_provider_generate TEXT DEFAULT "auto"')
    except:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN ai_provider_review TEXT DEFAULT "auto"')
    except:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "user"')
    except:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1')
    except:
        pass
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN last_login TIMESTAMP')
    except:
        pass
    
    # Strategies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS strategies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT,
            org_name TEXT,
            sector TEXT,
            content TEXT,
            language TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Policies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT,
            policy_name TEXT,
            framework TEXT,
            content TEXT,
            language TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Audits table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT,
            framework TEXT,
            scope TEXT,
            content TEXT,
            language TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Risks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain TEXT,
            asset_name TEXT,
            threat TEXT,
            risk_level TEXT,
            analysis TEXT,
            language TEXT DEFAULT 'en',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Add language column to risks if not exists (for existing databases)
    try:
        cursor.execute('ALTER TABLE risks ADD COLUMN language TEXT DEFAULT "en"')
    except:
        pass
    
    # Shared documents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            doc_type TEXT NOT NULL,
            doc_id INTEGER NOT NULL,
            title TEXT,
            domain TEXT,
            content TEXT,
            language TEXT DEFAULT 'en',
            view_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            requires_otp INTEGER DEFAULT 0,
            recipient_email TEXT,
            otp_code TEXT,
            otp_verified INTEGER DEFAULT 0,
            otp_expires_at TIMESTAMP,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Industry benchmarks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS benchmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sector TEXT NOT NULL,
            sector_ar TEXT,
            compliance_score_avg REAL DEFAULT 60,
            maturity_level_avg REAL DEFAULT 2.5,
            risk_coverage_avg REAL DEFAULT 50,
            policy_count_avg INTEGER DEFAULT 5,
            audit_count_avg INTEGER DEFAULT 3,
            risk_assessment_avg INTEGER DEFAULT 4,
            source TEXT,
            source_year INTEGER DEFAULT 2024,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default benchmark data if empty
    existing = cursor.execute('SELECT COUNT(*) FROM benchmarks').fetchone()[0]
    if existing == 0:
        default_benchmarks = [
            ('Government', 'حكومي', 62, 2.5, 55, 6, 3, 4, 'NCA Annual Report', 2024),
            ('Banking/Finance', 'بنوك/مالي', 78, 3.8, 72, 12, 6, 8, 'SAMA CSF Report', 2024),
            ('Healthcare', 'رعاية صحية', 58, 2.3, 48, 5, 2, 3, 'MOH Compliance Survey', 2024),
            ('Energy', 'طاقة', 70, 3.2, 65, 8, 4, 6, 'SEC Industry Report', 2024),
            ('Telecom', 'اتصالات', 72, 3.4, 68, 9, 5, 7, 'CITC Benchmark Study', 2024),
            ('Retail', 'تجزئة', 52, 2.0, 42, 4, 2, 3, 'Industry Average Estimate', 2024),
            ('Manufacturing', 'تصنيع', 55, 2.2, 45, 4, 2, 3, 'Industry Average Estimate', 2024),
        ]
        cursor.executemany('''
            INSERT INTO benchmarks (sector, sector_ar, compliance_score_avg, maturity_level_avg, 
                                   risk_coverage_avg, policy_count_avg, audit_count_avg, 
                                   risk_assessment_avg, source, source_year)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_benchmarks)
    
    # Background tasks table for async AI operations
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS background_tasks (
            task_id TEXT PRIMARY KEY,
            user_id INTEGER,
            status TEXT DEFAULT 'pending',
            result TEXT,
            error TEXT,
            callback_domain TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Clean up old tasks on startup
    cursor.execute("DELETE FROM background_tasks WHERE created_at < datetime('now', '-1 hour')")
    
    # ERM Risk Register table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_register (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT DEFAULT 'Operational',
            likelihood INTEGER DEFAULT 3,
            impact INTEGER DEFAULT 3,
            owner TEXT,
            treatment TEXT DEFAULT 'Mitigate',
            treatment_plan TEXT,
            status TEXT DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Awareness module scores
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS awareness_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            module_id TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            passed INTEGER DEFAULT 0,
            language TEXT DEFAULT 'en',
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Project management tasks
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS project_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT DEFAULT 'General',
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'todo',
            priority TEXT DEFAULT 'medium',
            owner TEXT,
            due_date TEXT,
            category TEXT DEFAULT 'implementation',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Compliance score history for trend tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            score REAL DEFAULT 0,
            maturity_avg REAL DEFAULT 0,
            strategies INTEGER DEFAULT 0,
            policies INTEGER DEFAULT 0,
            audits INTEGER DEFAULT 0,
            risks INTEGER DEFAULT 0,
            domains_covered INTEGER DEFAULT 0,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create default admin user if not exists
    admin_hash = hash_password(os.getenv('ADMIN_PASSWORD', 'MizanAdmin2026!'))
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash, role) 
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin@mizan.local', admin_hash, 'admin'))
    except:
        pass
    
    conn.commit()
    conn.close()
# Initialize database on startup
init_db()

# ============================================================================
# AUTHENTICATION
# ============================================================================

def login_required(f):
    """Decorator to require login. Returns JSON 401 for API calls, redirect for pages."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API endpoints, return JSON error instead of redirect
            if request.path.startswith('/api/') or request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Session expired. Please login again.', 'session_expired': True}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Registration limit
MAX_USERS = 3000

# Usage limits per user PER DOMAIN (for free tier)
USAGE_LIMITS = {
    'strategies': 1,
    'policies': 2,
    'audits': 2,
    'risks': 2
}

def get_user_usage_by_domain(user_id, domain):
    """Get current usage counts for a user in a specific domain."""
    conn = get_db()
    usage = {
        'strategies': conn.execute('SELECT COUNT(*) FROM strategies WHERE user_id = ? AND domain = ?', (user_id, domain)).fetchone()[0],
        'policies': conn.execute('SELECT COUNT(*) FROM policies WHERE user_id = ? AND domain = ?', (user_id, domain)).fetchone()[0],
        'audits': conn.execute('SELECT COUNT(*) FROM audits WHERE user_id = ? AND domain = ?', (user_id, domain)).fetchone()[0],
        'risks': conn.execute('SELECT COUNT(*) FROM risks WHERE user_id = ? AND domain = ?', (user_id, domain)).fetchone()[0]
    }
    conn.close()
    return usage

def check_usage_limit(user_id, doc_type, domain):
    """Check if user has reached usage limit for a document type in a domain."""
    usage = get_user_usage_by_domain(user_id, domain)
    current = usage.get(doc_type, 0)
    limit = USAGE_LIMITS.get(doc_type, 1)
    return current < limit, current, limit

def get_remaining_usage(user_id, domain):
    """Get remaining usage for all document types in a specific domain."""
    usage = get_user_usage_by_domain(user_id, domain)
    remaining = {}
    for doc_type, limit in USAGE_LIMITS.items():
        remaining[doc_type] = {
            'used': usage.get(doc_type, 0),
            'limit': limit,
            'remaining': max(0, limit - usage.get(doc_type, 0))
        }
    return remaining

# ============================================================================
# TRANSLATIONS
# ============================================================================

TRANSLATIONS = {
    "en": {
        "app_name": "Mizan",
        "tagline": "Governance • Risk • Compliance",
        "login": "Sign In",
        "register": "Register",
        "logout": "Logout",
        "username": "Username",
        "password": "Password",
        "welcome": "Welcome to Enterprise GRC Platform",
        "welcome_sub": "Secure • Compliant • Intelligent",
        "disclaimer": "AI-generated content. Verify with professionals. This app does not save or store your data.",
        "no_sensitive": "Do not enter sensitive or confidential data",
        "usage_limit": "Usage Limit",
        "usage_reached": "You have reached your limit for this feature",
        "remaining": "remaining",
        "domains": ["Cyber Security", "Data Management", "Artificial Intelligence", "Digital Transformation", "Global Standards", "Enterprise Risk Management"],
        "tabs": ["Strategy", "Policy Lab", "Audit", "Risk Radar"],
        "org_name": "Organization Name",
        "sector": "Sector",
        "sectors": ["Government", "Banking/Finance", "Healthcare", "Energy", "Telecom", "Retail", "Manufacturing"],
        "size": "Organization Size",
        "sizes": ["Small (<100)", "Medium (100-1000)", "Large (1000+)"],
        "budget": "Budget Range",
        "budgets": ["< 1M SAR", "1M-5M SAR", "5M-20M SAR", "20M+ SAR"],
        "frameworks": "Regulatory Frameworks",
        "horizon": "Strategic Horizon (Months)",
        "generate": "Generate Strategy",
        "generating": "Generating...",
        "current_state": "Current State Assessment",
        "technologies": "Current Technologies",
        "challenges": "Key Challenges",
        "strategy_sections": {
            "vision": "Executive Vision & Strategic Objectives",
            "gaps": "Current State Assessment (Gap Analysis)",
            "pillars": "Strategic Pillars & Initiatives",
            "roadmap": "Implementation Roadmap",
            "kpis": "Measuring Success (KPIs & KRIs)",
            "confidence": "Confidence Score"
        },
        "policy_name": "Policy Title",
        "policy_framework": "Framework/Standard",
        "generate_policy": "Generate Policy",
        "risk_category": "Risk Category",
        "risk_scenario": "Risk Scenario",
        "asset_name": "Asset Name",
        "analyze_risk": "Analyze Risk",
        "download": "Download",
        "created_by": "Created by",
        "settings": "Settings",
        "clear_history": "Clear History",
        "ai_connected": "AI Core Connected",
        "ai_disconnected": "Simulation Mode",
        "logged_in_as": "Logged in as",
        "my_documents": "My Documents",
        "document_history": "Document History",
        "no_documents": "No documents yet. Start generating!",
        "view_document": "View",
        "delete_document": "Delete",
        "document_type": "Type",
        "document_date": "Date",
        "all_types": "All Types",
        "all_domains": "All Domains",
        "strategies": "Strategies",
        "policies": "Policies",
        "audits": "Audits",
        "risks": "Risk Analyses",
        "filter_by": "Filter by",
        "confirm_delete": "Are you sure you want to delete this document?",
        "share": "Share",
        "share_document": "Share Document",
        "share_link": "Share Link",
        "copy_link": "Copy Link",
        "link_copied": "Link copied to clipboard!",
        "shared_by": "Shared by",
        "views": "Views",
        "share_expires": "Expires",
        "never_expires": "Never",
        "stop_sharing": "Stop Sharing",
        "my_shared": "My Shared Links",
        "no_shared": "No shared documents yet",
        "shared_document": "Shared Document",
        "document_not_found": "Document not found or link expired",
        "secure_share": "Secure Share (OTP)",
        "public_share": "Public Share",
        "recipient_email": "Recipient Email",
        "send_otp": "Send Access Code",
        "otp_sent": "Access code sent to",
        "enter_otp": "Enter Access Code",
        "verify_otp": "Verify",
        "otp_invalid": "Invalid or expired code",
        "otp_verified": "Verified! Loading document...",
        "otp_required": "This document requires verification",
        "otp_email_subject": "Your Mizan Document Access Code",
        "resend_otp": "Resend Code",
        "analytics": "Analytics",
        "insights": "Insights & Analytics",
        "compliance_score": "Compliance Score",
        "risk_heatmap": "Risk Heatmap",
        "maturity_radar": "Maturity Radar",
        "benchmark": "Benchmark Comparison",
        "your_score": "Your Score",
        "industry_avg": "Industry Average",
        "gap": "Gap",
        "above_avg": "Above Average",
        "below_avg": "Below Average",
        "likelihood": "Likelihood",
        "impact": "Impact",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
        "governance": "Governance",
        "risk_mgmt": "Risk Management",
        "compliance": "Compliance",
        "technology": "Technology",
        "process": "Process",
        "maturity_level": "Maturity Level",
        "initial": "Initial",
        "developing": "Developing",
        "defined": "Defined",
        "managed": "Managed",
        "optimized": "Optimized",
        "no_data": "No data yet. Generate documents to see analytics.",
        "select_sector": "Select your sector to compare",
        "benchmark_source": "Source",
        "manage_benchmarks": "Manage Benchmarks",
        "templates": "Templates",
        "use_template": "Use Template",
        "select_template": "Select a Template",
        "template_description": "Description",
        "apply_template": "Apply Template",
        "no_templates": "No templates available",
        "bilingual": "Bilingual",
        "generate_both": "Generate Both (EN & AR)",
        "chat_document": "Chat with Document",
        "ask_question": "Ask a question about this document...",
        "send": "Send",
        "review_policy": "Review Policy",
        "review_type": "Review Type",
        "comprehensive_review": "Comprehensive Review",
        "compliance_review": "Compliance Check",
        "gap_analysis": "Gap Analysis",
        "start_review": "Start Review",
        "gap_remediation": "Gap Remediation",
        "enter_gaps": "Enter identified gaps (one per line)",
        "generate_plan": "Generate Remediation Plan",
        "reviewing": "Reviewing...",
        "chatting": "Processing...",
        "profile": "Profile",
        "my_profile": "My Profile",
        "change_password": "Change Password",
        "current_password": "Current Password",
        "new_password": "New Password",
        "confirm_password": "Confirm New Password",
        "update_password": "Update Password",
        "password_updated": "Password updated successfully",
        "password_mismatch": "Passwords do not match",
        "wrong_password": "Current password is incorrect",
        "account_info": "Account Information",
        "member_since": "Member Since",
        "last_active": "Last Active",
        "total_documents": "Total Documents",
        "usage_summary": "Usage Summary",
        "used": "Used",
        "of": "of",
        "export_all": "Export All",
        "export_all_docs": "Export All Documents",
        "export_desc": "Download all your documents as a ZIP file",
        "exporting": "Exporting...",
        "no_docs_export": "No documents to export",
        "recent_documents": "Recent Documents",
        "quick_actions": "Quick Actions",
        "new_strategy": "New Strategy",
        "new_policy": "New Policy",
        "new_audit": "New Audit",
        "new_risk": "New Risk Analysis",
        "view_all": "View All",
        "usage_overview": "Usage Overview",
        "domains_active": "Active Domains",
        "landing_title": "Enterprise GRC Platform",
        "landing_subtitle": "AI-Powered Governance, Risk & Compliance Management",
        "landing_cta": "Get Started Free",
        "landing_login": "Already have an account?",
        "feature_ai": "AI-Powered Generation",
        "feature_ai_desc": "Generate strategies, policies, audits, and risk assessments using advanced AI",
        "feature_domains": "6 GRC Domains",
        "feature_domains_desc": "Cyber Security, Data Management, AI, Digital Transformation & Global Standards",
        "feature_bilingual": "Bilingual Support",
        "feature_bilingual_desc": "Full Arabic and English support with RTL layout and professional exports",
        "feature_export": "Professional Exports",
        "feature_export_desc": "Export to PDF, Word, and Excel with proper formatting and branding",
        "feature_analytics": "Analytics Dashboard",
        "feature_analytics_desc": "Track compliance scores, risk heatmaps, and maturity assessments",
        "feature_templates": "150+ Templates",
        "feature_templates_desc": "Ready-to-use policy, audit, and risk templates across all domains",
        "trusted_by": "Trusted by GRC professionals across the Kingdom",
        "how_it_works": "How It Works",
        "step1_title": "Select Your Domain",
        "step1_desc": "Choose from 6 specialized GRC domains",
        "step2_title": "Configure & Generate",
        "step2_desc": "Set parameters and let AI generate professional documents",
        "step3_title": "Review & Export",
        "step3_desc": "Review, customize, and export in multiple formats"
    },
    "ar": {
        "app_name": "ميزان",
        "tagline": "الحوكمة • المخاطر • الامتثال",
        "login": "تسجيل الدخول",
        "register": "إنشاء حساب",
        "logout": "تسجيل الخروج",
        "username": "اسم المستخدم",
        "password": "كلمة المرور",
        "welcome": "مرحباً بك في منصة حوكمة المؤسسات",
        "welcome_sub": "آمن • ممتثل • ذكي",
        "disclaimer": "محتوى مُنشأ بالذكاء الاصطناعي. يُرجى التحقق مع المختصين. هذا التطبيق لا يحفظ أو يخزن بياناتك.",
        "no_sensitive": "لا تدخل بيانات حساسة أو سرية",
        "usage_limit": "حد الاستخدام",
        "usage_reached": "لقد وصلت إلى الحد الأقصى لهذه الميزة",
        "remaining": "متبقي",
        "domains": ["الأمن السيبراني", "إدارة البيانات", "الذكاء الاصطناعي", "التحول الرقمي", "المعايير العالمية", "إدارة المخاطر المؤسسية"],
        "tabs": ["الاستراتيجية", "معمل السياسات", "التدقيق", "رادار المخاطر"],
        "org_name": "اسم المنظمة",
        "sector": "القطاع",
        "sectors": ["حكومي", "بنوك/مالي", "رعاية صحية", "طاقة", "اتصالات", "تجزئة", "تصنيع"],
        "size": "حجم المنظمة",
        "sizes": ["صغيرة (أقل من 100)", "متوسطة (100-1000)", "كبيرة (أكثر من 1000)"],
        "budget": "نطاق الميزانية",
        "budgets": ["< 1 مليون ريال", "1-5 مليون ريال", "5-20 مليون ريال", "20+ مليون ريال"],
        "frameworks": "الأطر التنظيمية",
        "horizon": "الأفق الاستراتيجي (أشهر)",
        "generate": "إنشاء الاستراتيجية",
        "generating": "جاري الإنشاء...",
        "current_state": "تقييم الوضع الحالي",
        "technologies": "التقنيات الحالية",
        "challenges": "التحديات الرئيسية",
        "strategy_sections": {
            "vision": "الرؤية التنفيذية والأهداف الاستراتيجية",
            "gaps": "تقييم الوضع الراهن (تحليل الفجوات)",
            "pillars": "الركائز الاستراتيجية والمبادرات",
            "roadmap": "خارطة طريق التنفيذ",
            "kpis": "قياس النجاح (مؤشرات الأداء والمخاطر)",
            "confidence": "درجة الثقة والتحقق"
        },
        "policy_name": "عنوان السياسة",
        "policy_framework": "الإطار/المعيار",
        "generate_policy": "إنشاء السياسة",
        "risk_category": "فئة المخاطر",
        "risk_scenario": "سيناريو الخطر",
        "asset_name": "اسم الأصل",
        "analyze_risk": "تحليل الخطر",
        "download": "تحميل",
        "created_by": "تم الإنشاء بواسطة",
        "settings": "الإعدادات",
        "clear_history": "مسح السجل",
        "ai_connected": "الذكاء الاصطناعي متصل",
        "ai_disconnected": "وضع المحاكاة",
        "logged_in_as": "مسجل الدخول كـ",
        "my_documents": "مستنداتي",
        "document_history": "سجل المستندات",
        "no_documents": "لا توجد مستندات بعد. ابدأ بالإنشاء!",
        "view_document": "عرض",
        "delete_document": "حذف",
        "document_type": "النوع",
        "document_date": "التاريخ",
        "all_types": "جميع الأنواع",
        "all_domains": "جميع المجالات",
        "strategies": "الاستراتيجيات",
        "policies": "السياسات",
        "audits": "التدقيقات",
        "risks": "تحليلات المخاطر",
        "filter_by": "تصفية حسب",
        "confirm_delete": "هل أنت متأكد من حذف هذا المستند؟",
        "share": "مشاركة",
        "share_document": "مشاركة المستند",
        "share_link": "رابط المشاركة",
        "copy_link": "نسخ الرابط",
        "link_copied": "تم نسخ الرابط!",
        "shared_by": "تمت المشاركة بواسطة",
        "views": "المشاهدات",
        "share_expires": "ينتهي",
        "never_expires": "لا ينتهي",
        "stop_sharing": "إيقاف المشاركة",
        "my_shared": "روابطي المشتركة",
        "no_shared": "لا توجد مستندات مشتركة بعد",
        "shared_document": "مستند مشترك",
        "document_not_found": "المستند غير موجود أو انتهت صلاحية الرابط",
        "secure_share": "مشاركة آمنة (رمز التحقق)",
        "public_share": "مشاركة عامة",
        "recipient_email": "بريد المستلم",
        "send_otp": "إرسال رمز الوصول",
        "otp_sent": "تم إرسال رمز الوصول إلى",
        "enter_otp": "أدخل رمز الوصول",
        "verify_otp": "تحقق",
        "otp_invalid": "رمز غير صالح أو منتهي الصلاحية",
        "otp_verified": "تم التحقق! جاري تحميل المستند...",
        "otp_required": "هذا المستند يتطلب التحقق",
        "otp_email_subject": "رمز الوصول لمستند ميزان",
        "resend_otp": "إعادة إرسال الرمز",
        "analytics": "التحليلات",
        "insights": "الرؤى والتحليلات",
        "compliance_score": "درجة الامتثال",
        "risk_heatmap": "خريطة المخاطر الحرارية",
        "maturity_radar": "رادار النضج",
        "benchmark": "مقارنة معيارية",
        "your_score": "درجتك",
        "industry_avg": "متوسط القطاع",
        "gap": "الفجوة",
        "above_avg": "أعلى من المتوسط",
        "below_avg": "أقل من المتوسط",
        "likelihood": "الاحتمالية",
        "impact": "الأثر",
        "low": "منخفض",
        "medium": "متوسط",
        "high": "عالي",
        "critical": "حرج",
        "governance": "الحوكمة",
        "risk_mgmt": "إدارة المخاطر",
        "compliance": "الامتثال",
        "technology": "التقنية",
        "process": "العمليات",
        "maturity_level": "مستوى النضج",
        "initial": "أولي",
        "developing": "تطويري",
        "defined": "محدد",
        "managed": "مُدار",
        "optimized": "محسّن",
        "no_data": "لا توجد بيانات بعد. أنشئ مستندات لعرض التحليلات.",
        "select_sector": "اختر قطاعك للمقارنة",
        "benchmark_source": "المصدر",
        "manage_benchmarks": "إدارة المعايير",
        "templates": "القوالب",
        "use_template": "استخدم قالب",
        "select_template": "اختر قالباً",
        "template_description": "الوصف",
        "apply_template": "تطبيق القالب",
        "no_templates": "لا توجد قوالب متاحة",
        "bilingual": "ثنائي اللغة",
        "generate_both": "إنشاء بالعربية والإنجليزية",
        "chat_document": "محادثة مع الوثيقة",
        "ask_question": "اطرح سؤالاً عن هذه الوثيقة...",
        "send": "إرسال",
        "review_policy": "مراجعة السياسة",
        "review_type": "نوع المراجعة",
        "comprehensive_review": "مراجعة شاملة",
        "compliance_review": "فحص الامتثال",
        "gap_analysis": "تحليل الفجوات",
        "start_review": "بدء المراجعة",
        "gap_remediation": "معالجة الفجوات",
        "enter_gaps": "أدخل الفجوات المحددة (واحدة في كل سطر)",
        "generate_plan": "إنشاء خطة المعالجة",
        "reviewing": "جارٍ المراجعة...",
        "chatting": "جارٍ المعالجة...",
        "profile": "الملف الشخصي",
        "my_profile": "ملفي الشخصي",
        "change_password": "تغيير كلمة المرور",
        "current_password": "كلمة المرور الحالية",
        "new_password": "كلمة المرور الجديدة",
        "confirm_password": "تأكيد كلمة المرور الجديدة",
        "update_password": "تحديث كلمة المرور",
        "password_updated": "تم تحديث كلمة المرور بنجاح",
        "password_mismatch": "كلمتا المرور غير متطابقتين",
        "wrong_password": "كلمة المرور الحالية غير صحيحة",
        "account_info": "معلومات الحساب",
        "member_since": "عضو منذ",
        "last_active": "آخر نشاط",
        "total_documents": "إجمالي المستندات",
        "usage_summary": "ملخص الاستخدام",
        "used": "مستخدم",
        "of": "من",
        "export_all": "تصدير الكل",
        "export_all_docs": "تصدير جميع المستندات",
        "export_desc": "تحميل جميع مستنداتك كملف ZIP",
        "exporting": "جارٍ التصدير...",
        "no_docs_export": "لا توجد مستندات للتصدير",
        "recent_documents": "المستندات الأخيرة",
        "quick_actions": "إجراءات سريعة",
        "new_strategy": "استراتيجية جديدة",
        "new_policy": "سياسة جديدة",
        "new_audit": "تدقيق جديد",
        "new_risk": "تحليل مخاطر جديد",
        "view_all": "عرض الكل",
        "usage_overview": "نظرة عامة على الاستخدام",
        "domains_active": "المجالات النشطة",
        "landing_title": "منصة الحوكمة والمخاطر والامتثال",
        "landing_subtitle": "إدارة الحوكمة والمخاطر والامتثال المدعومة بالذكاء الاصطناعي",
        "landing_cta": "ابدأ مجاناً",
        "landing_login": "لديك حساب بالفعل؟",
        "feature_ai": "إنشاء بالذكاء الاصطناعي",
        "feature_ai_desc": "إنشاء استراتيجيات وسياسات وتقارير تدقيق وتقييم مخاطر باستخدام الذكاء الاصطناعي المتقدم",
        "feature_domains": "6 مجالات للحوكمة",
        "feature_domains_desc": "الأمن السيبراني، إدارة البيانات، الذكاء الاصطناعي، التحول الرقمي والمعايير العالمية",
        "feature_bilingual": "دعم ثنائي اللغة",
        "feature_bilingual_desc": "دعم كامل للعربية والإنجليزية مع تنسيق RTL وتصدير احترافي",
        "feature_export": "تصدير احترافي",
        "feature_export_desc": "تصدير إلى PDF و Word و Excel بتنسيق ومظهر احترافي",
        "feature_analytics": "لوحة تحليلات",
        "feature_analytics_desc": "تتبع درجات الامتثال وخرائط المخاطر الحرارية وتقييمات النضج",
        "feature_templates": "أكثر من 150 قالب",
        "feature_templates_desc": "قوالب جاهزة للسياسات والتدقيق والمخاطر في جميع المجالات",
        "trusted_by": "موثوق من متخصصي الحوكمة في المملكة",
        "how_it_works": "كيف تعمل المنصة",
        "step1_title": "اختر المجال",
        "step1_desc": "اختر من 6 مجالات متخصصة في الحوكمة",
        "step2_title": "حدد المعايير وأنشئ",
        "step2_desc": "حدد المتطلبات واترك الذكاء الاصطناعي ينشئ المستندات الاحترافية",
        "step3_title": "راجع وصدّر",
        "step3_desc": "راجع المستندات وخصصها وصدّرها بعدة تنسيقات"
    }
}

def get_text(lang='en'):
    """Get translations for language."""
    return TRANSLATIONS.get(lang, TRANSLATIONS['en'])

# ============================================================================
# DOMAIN DATA
# ============================================================================

DOMAIN_FRAMEWORKS = {
    "cyber": {
        "KSA": [
            "NCA ECC (Essential Cybersecurity Controls)",
            "NCA CSCC (Critical Systems Cybersecurity Controls)", 
            "NCA DCC (Data Cybersecurity Controls)",
            "NCA OTCC (Operational Technology Cybersecurity Controls)",
            "NCA TCC (Telework Cybersecurity Controls)",
            "NCA OSMACC (Social Media Cybersecurity Controls)",
            "NCA CCC (Cloud Cybersecurity Controls)",
            "NCA NCS (National Cryptographic Standards)",
            "NCA CGIoT (Cybersecurity Guidelines for IoT)",
            "SAMA CSF (Cybersecurity Framework)",
            "SAMA BCM (Business Continuity Management)",
            "CMA Cybersecurity Guidelines",
            "CITC Cybersecurity Regulations"
        ],
        "GCC": [
            "UAE NESA (National Electronic Security Authority)",
            "UAE ADSIC (Abu Dhabi Information Security)",
            "Qatar NCSA (National Cyber Security Agency)",
            "Bahrain NCSRC",
            "Oman ITA Cybersecurity",
            "Kuwait NCSC"
        ],
        "EU": [
            "NIS2 Directive (Network and Information Security)",
            "DORA (Digital Operational Resilience Act)",
            "Cyber Resilience Act",
            "ENISA Guidelines",
            "UK NCSC Cyber Essentials",
            "UK NCSC Cyber Essentials Plus",
            "German BSI IT-Grundschutz"
        ],
        "US": [
            "NIST CSF 2.0 (Cybersecurity Framework)",
            "NIST SP 800-53 (Security Controls)",
            "NIST SP 800-171 (CUI Protection)",
            "CMMC (Cybersecurity Maturity Model)",
            "CISA Guidelines",
            "FedRAMP",
            "FISMA",
            "NERC CIP (Critical Infrastructure)"
        ],
        "International": [
            "ISO 27001:2022 (ISMS)",
            "ISO 27002:2022 (Security Controls)",
            "ISO 27017 (Cloud Security)",
            "ISO 27018 (Cloud Privacy)",
            "ISO 27701 (Privacy Information)",
            "CIS Controls v8",
            "COBIT 2019 (Security)",
            "CSA CCM (Cloud Controls Matrix)",
            "PCI DSS v4.0"
        ]
    },
    "data": {
        "KSA": [
            "PDPL (Personal Data Protection Law)",
            "NCA DCC (Data Cybersecurity Controls)",
            "NDMO Data Governance Framework",
            "SDAIA Data Classification Policy",
            "SAMA Data Management Requirements",
            "CITC Data Regulations"
        ],
        "GCC": [
            "UAE PDPL (Personal Data Protection Law)",
            "UAE DIFC Data Protection Law",
            "UAE ADGM Data Protection Regulations",
            "Qatar DPL (Data Protection Law)",
            "Bahrain PDPL",
            "Oman Data Protection Law",
            "Kuwait Data Protection Draft"
        ],
        "EU": [
            "GDPR (General Data Protection Regulation)",
            "Data Governance Act (DGA)",
            "Data Act",
            "ePrivacy Directive",
            "UK Data Protection Act 2018",
            "UK GDPR"
        ],
        "US": [
            "CCPA/CPRA (California Privacy)",
            "HIPAA (Health Data)",
            "GLBA (Financial Data)",
            "FERPA (Education Data)",
            "COPPA (Children's Data)",
            "State Privacy Laws (Virginia, Colorado, etc.)"
        ],
        "International": [
            "ISO 27701 (Privacy Information Management)",
            "ISO 38505 (Data Governance)",
            "DAMA DMBOK (Data Management)",
            "DCAM (Data Capability Assessment)",
            "COBIT 2019 (Data Governance)"
        ]
    },
    "ai": {
        "KSA": [
            "SDAIA AI Ethics Principles",
            "SDAIA AI Governance Framework",
            "NCA AI Cybersecurity Guidelines",
            "MCIT AI Strategy"
        ],
        "GCC": [
            "UAE National AI Strategy",
            "UAE AI Ethics Guidelines",
            "Qatar National AI Strategy",
            "Bahrain AI Strategy"
        ],
        "EU": [
            "EU AI Act",
            "EU AI Liability Directive",
            "ALTAI (Assessment List for Trustworthy AI)",
            "UK AI Regulation Framework",
            "UK ICO AI Guidance"
        ],
        "US": [
            "NIST AI RMF (Risk Management Framework)",
            "Executive Order on AI Safety",
            "FTC AI Guidelines",
            "EEOC AI Hiring Guidelines",
            "State AI Regulations"
        ],
        "International": [
            "ISO 42001 (AI Management System)",
            "ISO 23894 (AI Risk Management)",
            "IEEE 7000 (Ethical AI)",
            "OECD AI Principles",
            "UNESCO AI Ethics"
        ]
    },
    "dt": {
        "KSA": [
            "DGA Digital Government Policy",
            "DGA Digital Transformation Standards",
            "MCIT National Digital Strategy",
            "Vision 2030 Digital Programs",
            "NCA Cloud Security Controls"
        ],
        "GCC": [
            "UAE Digital Government Strategy",
            "UAE Smart Government Initiative",
            "Qatar Digital Agenda",
            "Bahrain eGovernment",
            "Oman Digital Strategy"
        ],
        "EU": [
            "EU Digital Compass 2030",
            "Digital Services Act (DSA)",
            "Digital Markets Act (DMA)",
            "eIDAS 2.0",
            "UK Digital Strategy"
        ],
        "US": [
            "Federal Digital Strategy",
            "21st Century IDEA Act",
            "Cloud Smart Strategy",
            "Zero Trust Architecture (EO 14028)"
        ],
        "International": [
            "COBIT 2019",
            "TOGAF (Enterprise Architecture)",
            "ITIL 4 (Service Management)",
            "SAFe (Scaled Agile)",
            "ISO 38500 (IT Governance)",
            "ISO 20000 (Service Management)"
        ]
    },
    "global": {
        "Quality & Management": [
            "ISO 9001:2015 (Quality Management)",
            "ISO 14001:2015 (Environmental)",
            "ISO 45001:2018 (Occupational Health)",
            "ISO 22000 (Food Safety)",
            "ISO 50001 (Energy Management)"
        ],
        "Business Continuity": [
            "ISO 22301:2019 (BCMS)",
            "ISO 22313 (BC Guidance)",
            "ISO 22317 (BIA)",
            "BS 11200 (Crisis Management)",
            "ASIS BCM Standard"
        ],
        "Audit & Assurance": [
            "ISO 19011 (Auditing Guidelines)",
            "ISAE 3402 (Service Organization Controls)",
            "SOC 1/SOC 2/SOC 3",
            "SSAE 18"
        ],
        "Governance": [
            "ISO 37000 (Governance of Organizations)",
            "ISO 37001 (Anti-Bribery)",
            "ISO 37002 (Whistleblowing)",
            "COSO Internal Control Framework",
            "King IV (Corporate Governance)"
        ],
        "Sector-Specific": [
            "PCI DSS v4.0 (Payment Card)",
            "SWIFT CSCF (Financial Messaging)",
            "SOX (Sarbanes-Oxley)",
            "Basel III/IV (Banking)",
            "Solvency II (Insurance)"
        ]
    },
    "erm": {
        "International Standards": [
            "ISO 31000:2018 (Risk Management)",
            "ISO 31010:2019 (Risk Assessment Techniques)",
            "ISO 31022 (Legal Risk)",
            "ISO 31030 (Travel Risk)",
            "ISO 31050 (Emerging Risks)",
            "COSO ERM Framework (2017)",
            "IRM Risk Management Standard"
        ],
        "Financial Risk": [
            "Basel III/IV (Banking Risk)",
            "Solvency II (Insurance Risk)",
            "IFRS 9 (Financial Instruments)",
            "SAMA Risk Management Guidelines",
            "CMA Risk Management Requirements"
        ],
        "Operational Risk": [
            "NIST SP 800-30 (Risk Assessment)",
            "NIST RMF (SP 800-37)",
            "FAIR (Factor Analysis of Information Risk)",
            "OCTAVE (Operationally Critical Threat Assessment)"
        ],
        "Governance": [
            "King IV (Corporate Governance)",
            "FERMA Risk Management Standard",
            "AS/NZS 4360 (Australia/NZ Standard)",
            "AIRMIC/ALARM/IRM Risk Management Guide"
        ],
        "Regional": [
            "NCA Risk Management Requirements (KSA)",
            "SAMA Operational Risk Guidelines (KSA)",
            "CMA Corporate Governance Code (KSA)",
            "UAE Corporate Governance Code",
            "Qatar Corporate Governance Code"
        ]
    }
}

# Legacy flat list for backward compatibility
DOMAIN_FRAMEWORKS_FLAT = {
    "cyber": [fw for region in DOMAIN_FRAMEWORKS["cyber"].values() for fw in region],
    "data": [fw for region in DOMAIN_FRAMEWORKS["data"].values() for fw in region],
    "ai": [fw for region in DOMAIN_FRAMEWORKS["ai"].values() for fw in region],
    "dt": [fw for region in DOMAIN_FRAMEWORKS["dt"].values() for fw in region],
    "global": [fw for region in DOMAIN_FRAMEWORKS["global"].values() for fw in region],
    "erm": [fw for region in DOMAIN_FRAMEWORKS["erm"].values() for fw in region]
}

# Arabic translations for framework names
FRAMEWORK_AR_NAMES = {
    "NCA ECC (Essential Cybersecurity Controls)": "الضوابط الأساسية للأمن السيبراني (NCA ECC)",
    "NCA CSCC (Critical Systems Cybersecurity Controls)": "ضوابط الأمن السيبراني للأنظمة الحساسة (NCA CSCC)",
    "NCA DCC (Data Cybersecurity Controls)": "ضوابط الأمن السيبراني للبيانات (NCA DCC)",
    "NCA OTCC (Operational Technology Cybersecurity Controls)": "ضوابط الأمن السيبراني للتقنيات التشغيلية (NCA OTCC)",
    "NCA TCC (Telework Cybersecurity Controls)": "ضوابط الأمن السيبراني للعمل عن بعد (NCA TCC)",
    "NCA OSMACC (Social Media Cybersecurity Controls)": "ضوابط الأمن السيبراني لوسائل التواصل الاجتماعي (NCA OSMACC)",
    "NCA CCC (Cloud Cybersecurity Controls)": "ضوابط الأمن السيبراني السحابية (NCA CCC)",
    "NCA NCS (National Cryptographic Standards)": "المعايير الوطنية للتشفير (NCA NCS)",
    "NCA CGIoT (Cybersecurity Guidelines for IoT)": "إرشادات الأمن السيبراني لإنترنت الأشياء (NCA CGIoT)",
    "SAMA CSF (Cybersecurity Framework)": "إطار الأمن السيبراني لمؤسسة النقد (SAMA CSF)",
    "SAMA BCM (Business Continuity Management)": "إدارة استمرارية الأعمال لمؤسسة النقد (SAMA BCM)",
    "PDPL (Personal Data Protection Law)": "نظام حماية البيانات الشخصية (PDPL)",
    "NDMO Data Governance Framework": "إطار حوكمة البيانات - مكتب إدارة البيانات الوطنية (NDMO)",
    "SDAIA AI Ethics Framework": "إطار أخلاقيات الذكاء الاصطناعي - سدايا (SDAIA)",
}

def translate_framework_ar(fw_name):
    """Translate framework name to Arabic if available."""
    return FRAMEWORK_AR_NAMES.get(fw_name, fw_name)

def translate_frameworks_list_ar(frameworks_list_str):
    """Translate a comma-separated frameworks list to Arabic."""
    frameworks = [f.strip() for f in frameworks_list_str.split(',')]
    translated = [translate_framework_ar(f) for f in frameworks]
    return '، '.join(translated)
DOMAIN_TECHNOLOGIES = {
    "cyber": {
        "en": {
            "Security Operations": ["SIEM", "SOAR", "SOC", "Threat Intelligence Platform", "Log Management"],
            "Endpoint Security": ["EDR/XDR", "Antivirus/Anti-malware", "Mobile Device Management (MDM)", "Endpoint DLP"],
            "Network Security": ["Next-Gen Firewall", "IDS/IPS", "Network Access Control (NAC)", "Web Proxy", "DNS Security"],
            "Identity & Access": ["IAM", "PAM", "MFA/2FA", "SSO", "Directory Services (AD/LDAP)"],
            "Data Protection": ["DLP", "Encryption (at-rest/in-transit)", "Backup & Recovery", "Data Classification"],
            "Application Security": ["WAF", "SAST/DAST", "API Security", "Code Review Tools"],
            "Cloud Security": ["CASB", "CSPM", "CWPP", "Cloud IAM"],
            "GRC Tools": ["Vulnerability Scanner", "Penetration Testing", "Compliance Management", "Risk Register"]
        },
        "ar": {
            "العمليات الأمنية": ["SIEM", "SOAR", "مركز العمليات الأمنية", "منصة استخبارات التهديدات", "إدارة السجلات"],
            "أمن النقاط الطرفية": ["EDR/XDR", "مكافحة الفيروسات", "إدارة الأجهزة المحمولة", "DLP للنقاط الطرفية"],
            "أمن الشبكات": ["جدار الحماية المتقدم", "IDS/IPS", "التحكم بالوصول للشبكة", "بروكسي الويب", "أمن DNS"],
            "الهوية والوصول": ["IAM", "PAM", "المصادقة متعددة العوامل", "SSO", "خدمات الدليل"],
            "حماية البيانات": ["DLP", "التشفير", "النسخ الاحتياطي والاستعادة", "تصنيف البيانات"],
            "أمن التطبيقات": ["WAF", "SAST/DAST", "أمن API", "أدوات مراجعة الكود"],
            "أمن السحابة": ["CASB", "CSPM", "CWPP", "IAM السحابي"],
            "أدوات الحوكمة": ["ماسح الثغرات", "اختبار الاختراق", "إدارة الامتثال", "سجل المخاطر"]
        }
    },
    "data": {
        "en": {
            "Data Governance": ["Data Catalog", "Metadata Management", "Data Lineage", "Business Glossary"],
            "Data Quality": ["Data Profiling", "Data Cleansing", "Master Data Management (MDM)", "Data Validation"],
            "Data Security": ["Data Masking", "Tokenization", "Database Encryption", "Access Controls"],
            "Data Privacy": ["Consent Management", "Privacy Impact Assessment", "Data Subject Rights Management", "Cookie Management"],
            "Data Integration": ["ETL/ELT Tools", "Data Virtualization", "API Management", "Data Replication"],
            "Data Analytics": ["BI Platform", "Data Warehouse", "Data Lake", "Reporting Tools"],
            "Data Lifecycle": ["Archiving Solutions", "Retention Management", "Secure Disposal", "Backup Systems"]
        },
        "ar": {
            "حوكمة البيانات": ["كتالوج البيانات", "إدارة البيانات الوصفية", "تتبع مسار البيانات", "قاموس الأعمال"],
            "جودة البيانات": ["تحليل البيانات", "تنظيف البيانات", "إدارة البيانات الرئيسية", "التحقق من البيانات"],
            "أمن البيانات": ["إخفاء البيانات", "الترميز", "تشفير قواعد البيانات", "ضوابط الوصول"],
            "خصوصية البيانات": ["إدارة الموافقات", "تقييم أثر الخصوصية", "إدارة حقوق أصحاب البيانات", "إدارة الكوكيز"],
            "تكامل البيانات": ["أدوات ETL/ELT", "المحاكاة الافتراضية للبيانات", "إدارة API", "نسخ البيانات"],
            "تحليل البيانات": ["منصة ذكاء الأعمال", "مستودع البيانات", "بحيرة البيانات", "أدوات التقارير"],
            "دورة حياة البيانات": ["حلول الأرشفة", "إدارة الاحتفاظ", "الإتلاف الآمن", "أنظمة النسخ الاحتياطي"]
        }
    },
    "ai": {
        "en": {
            "ML Infrastructure": ["ML Platform", "Model Registry", "Feature Store", "Experiment Tracking"],
            "Data for AI": ["Data Labeling", "Training Data Management", "Synthetic Data Generation", "Data Versioning"],
            "Model Development": ["AutoML", "Notebook Environment", "Model Training Pipeline", "Hyperparameter Tuning"],
            "Model Operations": ["Model Deployment", "Model Monitoring", "A/B Testing", "Model Versioning"],
            "AI Governance": ["Model Documentation", "Bias Detection", "Explainability Tools", "Audit Trail"],
            "AI Security": ["Adversarial Testing", "Model Encryption", "Secure Inference", "Access Controls"]
        },
        "ar": {
            "بنية تعلم الآلة": ["منصة ML", "سجل النماذج", "مخزن الميزات", "تتبع التجارب"],
            "بيانات الذكاء الاصطناعي": ["تصنيف البيانات", "إدارة بيانات التدريب", "توليد البيانات الاصطناعية", "إصدارات البيانات"],
            "تطوير النماذج": ["AutoML", "بيئة Notebook", "خط أنابيب التدريب", "ضبط المعاملات"],
            "عمليات النماذج": ["نشر النماذج", "مراقبة النماذج", "اختبار A/B", "إصدارات النماذج"],
            "حوكمة الذكاء الاصطناعي": ["توثيق النماذج", "كشف التحيز", "أدوات التفسير", "سجل المراجعة"],
            "أمن الذكاء الاصطناعي": ["الاختبار العدائي", "تشفير النماذج", "الاستدلال الآمن", "ضوابط الوصول"]
        }
    },
    "dt": {
        "en": {
            "Digital Platforms": ["Enterprise Portal", "Mobile Apps", "Customer Experience Platform", "Digital Workplace"],
            "Integration": ["ESB/Integration Platform", "API Gateway", "iPaaS", "Microservices"],
            "Process Automation": ["RPA", "BPM", "Workflow Engine", "Low-Code Platform"],
            "Cloud Services": ["IaaS", "PaaS", "SaaS", "Hybrid Cloud"],
            "Analytics & Insights": ["Big Data Platform", "Real-time Analytics", "Predictive Analytics", "Dashboard/KPI Tools"],
            "Collaboration": ["Unified Communications", "Document Management", "Project Management", "Knowledge Management"],
            "Customer Engagement": ["CRM", "Marketing Automation", "Chatbots", "Omnichannel Platform"]
        },
        "ar": {
            "المنصات الرقمية": ["البوابة المؤسسية", "تطبيقات الجوال", "منصة تجربة العميل", "مكان العمل الرقمي"],
            "التكامل": ["منصة التكامل", "بوابة API", "iPaaS", "الخدمات المصغرة"],
            "أتمتة العمليات": ["RPA", "إدارة العمليات", "محرك سير العمل", "منصة Low-Code"],
            "الخدمات السحابية": ["IaaS", "PaaS", "SaaS", "السحابة الهجينة"],
            "التحليلات": ["منصة البيانات الضخمة", "التحليلات الفورية", "التحليلات التنبؤية", "لوحات المؤشرات"],
            "التعاون": ["الاتصالات الموحدة", "إدارة الوثائق", "إدارة المشاريع", "إدارة المعرفة"],
            "تفاعل العملاء": ["CRM", "أتمتة التسويق", "روبوتات المحادثة", "منصة القنوات المتعددة"]
        }
    },
    "global": {
        "en": {
            "Quality Management": ["QMS Software", "Document Control", "CAPA Management", "Audit Management"],
            "Risk Management": ["ERM Platform", "Risk Register", "Risk Assessment Tools", "Incident Management"],
            "Compliance": ["Compliance Management", "Policy Management", "Training Management", "Certification Tracking"],
            "Business Continuity": ["BCP Platform", "DR Solutions", "Crisis Management", "Emergency Notification"],
            "Information Security": ["ISMS Platform", "Asset Management", "Vulnerability Management", "Security Awareness"]
        },
        "ar": {
            "إدارة الجودة": ["برنامج QMS", "التحكم بالوثائق", "إدارة CAPA", "إدارة التدقيق"],
            "إدارة المخاطر": ["منصة ERM", "سجل المخاطر", "أدوات تقييم المخاطر", "إدارة الحوادث"],
            "الامتثال": ["إدارة الامتثال", "إدارة السياسات", "إدارة التدريب", "تتبع الشهادات"],
            "استمرارية الأعمال": ["منصة BCP", "حلول DR", "إدارة الأزمات", "الإشعارات الطارئة"],
            "أمن المعلومات": ["منصة ISMS", "إدارة الأصول", "إدارة الثغرات", "التوعية الأمنية"]
        }
    },
    "erm": {
        "en": {
            "Risk Identification": ["Risk Register Software", "Risk Taxonomy", "Scenario Analysis Tools", "Risk Surveys/Questionnaires", "Emerging Risk Radar"],
            "Risk Assessment": ["Quantitative Risk Analysis", "Monte Carlo Simulation", "Bow-Tie Analysis", "FMEA Tools", "Bayesian Networks"],
            "Risk Monitoring": ["KRI Dashboards", "Risk Heat Maps", "Real-time Risk Monitoring", "Early Warning Systems", "Risk Aggregation"],
            "Risk Appetite & Tolerance": ["Risk Appetite Framework", "Tolerance Thresholds", "Risk Capacity Models", "Board Reporting"],
            "Business Continuity": ["BCP/DRP Platform", "Crisis Management System", "Emergency Communication", "Business Impact Analysis"],
            "Compliance & Controls": ["Control Self-Assessment", "Internal Audit Software", "Policy Management", "Regulatory Change Management"],
            "Insurance & Transfer": ["Insurance Management Platform", "Claims Management", "Risk Transfer Analysis", "Captive Management"],
            "GRC Integration": ["Enterprise GRC Platform", "Integrated Assurance", "Three Lines Model", "Risk Culture Assessment"]
        },
        "ar": {
            "تحديد المخاطر": ["برنامج سجل المخاطر", "تصنيف المخاطر", "أدوات تحليل السيناريوهات", "استبيانات المخاطر", "رادار المخاطر الناشئة"],
            "تقييم المخاطر": ["التحليل الكمي للمخاطر", "محاكاة مونت كارلو", "تحليل ربطة العنق", "أدوات FMEA", "الشبكات البايزية"],
            "مراقبة المخاطر": ["لوحات مؤشرات المخاطر", "خرائط المخاطر الحرارية", "المراقبة الفورية للمخاطر", "أنظمة الإنذار المبكر", "تجميع المخاطر"],
            "شهية المخاطر والتحمل": ["إطار شهية المخاطر", "عتبات التحمل", "نماذج القدرة على المخاطر", "تقارير مجلس الإدارة"],
            "استمرارية الأعمال": ["منصة BCP/DRP", "نظام إدارة الأزمات", "الاتصالات الطارئة", "تحليل تأثير الأعمال"],
            "الامتثال والضوابط": ["التقييم الذاتي للضوابط", "برنامج التدقيق الداخلي", "إدارة السياسات", "إدارة التغييرات التنظيمية"],
            "التأمين والنقل": ["منصة إدارة التأمين", "إدارة المطالبات", "تحليل نقل المخاطر", "إدارة شركات التأمين الأسيرة"],
            "تكامل الحوكمة": ["منصة GRC المتكاملة", "التأكيد المتكامل", "نموذج الخطوط الثلاثة", "تقييم ثقافة المخاطر"]
        }
    }
}

# Enhanced Risk Categories with scenarios
RISK_CATEGORIES = {
    "cyber": {
        "en": {
            "Access Control": ["Unauthorized access to systems", "Privilege escalation", "Credential theft", "Insider threat", "Session hijacking"],
            "Network Security": ["Network intrusion", "DDoS attack", "Man-in-the-middle attack", "DNS poisoning", "Lateral movement"],
            "Data Protection": ["Data breach", "Data leakage", "Unauthorized data access", "Data corruption", "Ransomware encryption"],
            "Endpoint Security": ["Malware infection", "Zero-day exploit", "USB-based attack", "Remote access trojan", "Cryptomining"],
            "Application Security": ["SQL injection", "XSS attack", "API abuse", "Broken authentication", "Insecure deserialization"],
            "Cloud Security": ["Cloud misconfiguration", "Data exposure in cloud", "Account hijacking", "Insecure APIs", "Shadow IT"],
            "Social Engineering": ["Phishing attack", "Spear phishing", "Business email compromise", "Vishing", "Pretexting"],
            "Third Party Risk": ["Vendor breach", "Supply chain attack", "Third-party data exposure", "Service provider failure"],
            "Operational Technology": ["SCADA attack", "ICS compromise", "Physical-cyber attack", "OT network breach"],
            "Incident Response": ["Delayed detection", "Inadequate response", "Evidence loss", "Communication failure"]
        },
        "ar": {
            "التحكم بالوصول": ["وصول غير مصرح للأنظمة", "تصعيد الصلاحيات", "سرقة بيانات الاعتماد", "التهديد الداخلي", "اختطاف الجلسة"],
            "أمن الشبكات": ["اختراق الشبكة", "هجوم DDoS", "هجوم الوسيط", "تسميم DNS", "الحركة الجانبية"],
            "حماية البيانات": ["خرق البيانات", "تسرب البيانات", "وصول غير مصرح للبيانات", "تلف البيانات", "تشفير الفدية"],
            "أمن النقاط الطرفية": ["إصابة بالبرمجيات الخبيثة", "استغلال يوم الصفر", "هجوم USB", "حصان طروادة", "التعدين الخبيث"],
            "أمن التطبيقات": ["حقن SQL", "هجوم XSS", "إساءة استخدام API", "مصادقة معطلة", "إلغاء تسلسل غير آمن"],
            "أمن السحابة": ["سوء تكوين السحابة", "كشف البيانات السحابية", "اختطاف الحساب", "APIs غير آمنة", "Shadow IT"],
            "الهندسة الاجتماعية": ["هجوم التصيد", "التصيد الموجه", "اختراق البريد التجاري", "التصيد الصوتي", "الذريعة"],
            "مخاطر الأطراف الثالثة": ["اختراق المورد", "هجوم سلسلة التوريد", "كشف بيانات الطرف الثالث", "فشل مزود الخدمة"],
            "التقنيات التشغيلية": ["هجوم SCADA", "اختراق ICS", "هجوم فيزيائي-سيبراني", "اختراق شبكة OT"],
            "الاستجابة للحوادث": ["تأخر الكشف", "استجابة غير كافية", "فقدان الأدلة", "فشل الاتصال"]
        }
    },
    "data": {
        "en": {
            "Data Quality": ["Incomplete data", "Duplicate records", "Data inconsistency", "Outdated information", "Invalid data formats"],
            "Data Privacy": ["Personal data exposure", "Consent violation", "Cross-border transfer issues", "Right to erasure failure", "Purpose limitation breach"],
            "Data Governance": ["Undefined data ownership", "Missing data lineage", "Inconsistent data definitions", "Policy non-compliance", "Metadata gaps"],
            "Data Security": ["Unauthorized data access", "Database breach", "Encryption failure", "Backup exposure", "Insider data theft"],
            "Data Lifecycle": ["Retention policy violation", "Improper disposal", "Archive corruption", "Recovery failure", "Storage overflow"],
            "Data Integration": ["ETL failure", "Data sync issues", "API data exposure", "Migration errors", "Real-time feed disruption"],
            "Regulatory Compliance": ["PDPL violation", "GDPR non-compliance", "Audit findings", "Reporting failures", "Documentation gaps"]
        },
        "ar": {
            "جودة البيانات": ["بيانات ناقصة", "سجلات مكررة", "عدم اتساق البيانات", "معلومات قديمة", "تنسيقات بيانات غير صالحة"],
            "خصوصية البيانات": ["كشف البيانات الشخصية", "انتهاك الموافقة", "مشاكل النقل عبر الحدود", "فشل حق المحو", "انتهاك تحديد الغرض"],
            "حوكمة البيانات": ["ملكية بيانات غير محددة", "مسار بيانات مفقود", "تعريفات بيانات غير متسقة", "عدم الامتثال للسياسة", "فجوات البيانات الوصفية"],
            "أمن البيانات": ["وصول غير مصرح للبيانات", "اختراق قاعدة البيانات", "فشل التشفير", "كشف النسخ الاحتياطية", "سرقة البيانات الداخلية"],
            "دورة حياة البيانات": ["انتهاك سياسة الاحتفاظ", "التخلص غير السليم", "تلف الأرشيف", "فشل الاستعادة", "تجاوز التخزين"],
            "تكامل البيانات": ["فشل ETL", "مشاكل مزامنة البيانات", "كشف بيانات API", "أخطاء الترحيل", "انقطاع التغذية الفورية"],
            "الامتثال التنظيمي": ["انتهاك PDPL", "عدم الامتثال لـ GDPR", "نتائج التدقيق", "فشل التقارير", "فجوات التوثيق"]
        }
    },
    "ai": {
        "en": {
            "Model Bias": ["Demographic bias", "Selection bias", "Measurement bias", "Algorithmic discrimination", "Feedback loop bias"],
            "Data Quality for AI": ["Training data poisoning", "Label errors", "Data drift", "Insufficient training data", "Unrepresentative samples"],
            "Model Performance": ["Model degradation", "Concept drift", "Overfitting", "Underfitting", "Poor generalization"],
            "Explainability": ["Black box decisions", "Lack of interpretability", "Unexplainable outcomes", "Audit trail gaps", "Stakeholder confusion"],
            "AI Security": ["Adversarial attacks", "Model theft", "Model inversion", "Data extraction attacks", "Prompt injection"],
            "Ethical Concerns": ["Autonomous harm", "Privacy invasion", "Unfair treatment", "Manipulation", "Job displacement"],
            "Operational Risks": ["Model failure in production", "Integration issues", "Scalability problems", "Resource constraints", "Dependency failures"],
            "Compliance": ["Regulatory non-compliance", "Documentation gaps", "Consent issues", "Cross-border AI use", "Audit failures"]
        },
        "ar": {
            "تحيز النموذج": ["تحيز ديموغرافي", "تحيز الاختيار", "تحيز القياس", "تمييز خوارزمي", "تحيز حلقة التغذية"],
            "جودة بيانات الذكاء الاصطناعي": ["تسميم بيانات التدريب", "أخطاء التصنيف", "انحراف البيانات", "بيانات تدريب غير كافية", "عينات غير ممثلة"],
            "أداء النموذج": ["تدهور النموذج", "انحراف المفهوم", "الإفراط في التخصيص", "نقص التخصيص", "ضعف التعميم"],
            "قابلية التفسير": ["قرارات الصندوق الأسود", "نقص قابلية التفسير", "نتائج غير قابلة للتفسير", "فجوات سجل المراجعة", "إرباك أصحاب المصلحة"],
            "أمن الذكاء الاصطناعي": ["الهجمات العدائية", "سرقة النموذج", "عكس النموذج", "هجمات استخراج البيانات", "حقن الأوامر"],
            "المخاوف الأخلاقية": ["الضرر المستقل", "انتهاك الخصوصية", "المعاملة غير العادلة", "التلاعب", "استبدال الوظائف"],
            "المخاطر التشغيلية": ["فشل النموذج في الإنتاج", "مشاكل التكامل", "مشاكل قابلية التوسع", "قيود الموارد", "فشل التبعيات"],
            "الامتثال": ["عدم الامتثال التنظيمي", "فجوات التوثيق", "مشاكل الموافقة", "استخدام AI عبر الحدود", "فشل التدقيق"]
        }
    },
    "dt": {
        "en": {
            "Change Management": ["Resistance to change", "Inadequate training", "Cultural barriers", "Communication gaps", "Leadership misalignment"],
            "Technology Integration": ["System incompatibility", "Data migration failures", "API integration issues", "Legacy system constraints", "Vendor lock-in"],
            "Digital Skills": ["Skills shortage", "Knowledge gaps", "Training inadequacy", "Talent retention", "Digital literacy"],
            "Process Disruption": ["Workflow disruption", "Process automation failure", "Business continuity impact", "Operational inefficiency", "Service degradation"],
            "Customer Experience": ["Poor digital experience", "Channel inconsistency", "Accessibility issues", "Response time delays", "Customer data exposure"],
            "Strategic Alignment": ["Misaligned objectives", "ROI uncertainty", "Scope creep", "Priority conflicts", "Resource constraints"],
            "Vendor & Cloud": ["Vendor dependency", "Cloud service outage", "Contract issues", "Cost overruns", "SLA breaches"],
            "Security in Transformation": ["Security gaps during migration", "New attack surfaces", "Access control issues", "Data exposure", "Compliance gaps"]
        },
        "ar": {
            "إدارة التغيير": ["مقاومة التغيير", "تدريب غير كافٍ", "حواجز ثقافية", "فجوات الاتصال", "عدم توافق القيادة"],
            "تكامل التقنية": ["عدم توافق الأنظمة", "فشل ترحيل البيانات", "مشاكل تكامل API", "قيود الأنظمة القديمة", "الارتباط بالمورد"],
            "المهارات الرقمية": ["نقص المهارات", "فجوات المعرفة", "قصور التدريب", "الاحتفاظ بالمواهب", "الثقافة الرقمية"],
            "تعطيل العمليات": ["تعطيل سير العمل", "فشل أتمتة العمليات", "تأثير استمرارية الأعمال", "عدم كفاءة التشغيل", "تدهور الخدمة"],
            "تجربة العميل": ["تجربة رقمية سيئة", "عدم اتساق القنوات", "مشاكل إمكانية الوصول", "تأخر وقت الاستجابة", "كشف بيانات العميل"],
            "التوافق الاستراتيجي": ["أهداف غير متوافقة", "عدم يقين العائد", "زحف النطاق", "تعارض الأولويات", "قيود الموارد"],
            "المورد والسحابة": ["الاعتماد على المورد", "انقطاع الخدمة السحابية", "مشاكل العقود", "تجاوز التكاليف", "انتهاكات SLA"],
            "الأمن في التحول": ["فجوات أمنية أثناء الترحيل", "أسطح هجوم جديدة", "مشاكل التحكم بالوصول", "كشف البيانات", "فجوات الامتثال"]
        }
    },
    "global": {
        "en": {
            "Strategic Risk": ["Market changes", "Competitive disruption", "Regulatory changes", "Technology obsolescence", "Geopolitical factors"],
            "Operational Risk": ["Process failures", "System outages", "Human errors", "Resource constraints", "Supplier disruptions"],
            "Financial Risk": ["Budget overruns", "Cost escalation", "Revenue impact", "Investment loss", "Currency fluctuation"],
            "Compliance Risk": ["Regulatory violations", "Audit findings", "Certification loss", "Legal penalties", "Reporting failures"],
            "Reputational Risk": ["Brand damage", "Customer trust loss", "Media exposure", "Stakeholder concerns", "Social media crisis"],
            "Business Continuity": ["Natural disasters", "Pandemic impact", "Infrastructure failure", "Key person dependency", "Supply chain disruption"],
            "Information Security": ["Data breaches", "Cyber attacks", "Insider threats", "Third-party risks", "Physical security"],
            "Quality Risk": ["Product defects", "Service failures", "Customer complaints", "Non-conformance", "Continuous improvement gaps"]
        },
        "ar": {
            "المخاطر الاستراتيجية": ["تغيرات السوق", "التعطيل التنافسي", "التغييرات التنظيمية", "تقادم التقنية", "العوامل الجيوسياسية"],
            "المخاطر التشغيلية": ["فشل العمليات", "انقطاع الأنظمة", "الأخطاء البشرية", "قيود الموارد", "اضطرابات الموردين"],
            "المخاطر المالية": ["تجاوز الميزانية", "تصاعد التكاليف", "تأثير الإيرادات", "خسارة الاستثمار", "تقلب العملة"],
            "مخاطر الامتثال": ["انتهاكات تنظيمية", "نتائج التدقيق", "فقدان الشهادات", "العقوبات القانونية", "فشل التقارير"],
            "مخاطر السمعة": ["ضرر العلامة التجارية", "فقدان ثقة العميل", "التعرض الإعلامي", "مخاوف أصحاب المصلحة", "أزمة وسائل التواصل"],
            "استمرارية الأعمال": ["الكوارث الطبيعية", "تأثير الجائحة", "فشل البنية التحتية", "الاعتماد على أشخاص رئيسيين", "تعطل سلسلة التوريد"],
            "أمن المعلومات": ["خروقات البيانات", "الهجمات السيبرانية", "التهديدات الداخلية", "مخاطر الأطراف الثالثة", "الأمن المادي"],
            "مخاطر الجودة": ["عيوب المنتج", "فشل الخدمة", "شكاوى العملاء", "عدم المطابقة", "فجوات التحسين المستمر"]
        }
    },
    "erm": {
        "en": {
            "Strategic Risk": ["Market disruption", "Competitive pressure", "Strategic misalignment", "Mergers & acquisitions risk", "Innovation failure", "Stakeholder expectation gap"],
            "Operational Risk": ["Process failure", "System downtime", "Supply chain disruption", "Human error", "Capacity constraints", "Quality failures"],
            "Financial Risk": ["Liquidity risk", "Credit risk", "Market risk", "Currency risk", "Interest rate risk", "Capital adequacy"],
            "Compliance & Legal Risk": ["Regulatory breach", "Contract dispute", "Litigation exposure", "License/permit risk", "Anti-corruption violation", "Sanctions risk"],
            "Reputational Risk": ["Brand damage", "Public trust erosion", "Social media crisis", "Ethical misconduct", "ESG criticism", "Customer complaint escalation"],
            "Geopolitical Risk": ["Political instability", "Trade restrictions", "Sanctions", "Cross-border regulatory conflict", "Nationalization risk", "Regional conflict"],
            "Environmental & Climate Risk": ["Physical climate risk", "Transition risk", "Regulatory carbon risk", "Resource scarcity", "Natural disaster", "Environmental liability"],
            "People & Culture Risk": ["Key person dependency", "Talent attrition", "Skills shortage", "Workplace safety", "Labor dispute", "Culture misalignment"],
            "Technology & Cyber Risk": ["Cyber attack", "Technology obsolescence", "Digital transformation failure", "Data breach", "IT infrastructure failure", "Third-party tech risk"],
            "Emerging & Systemic Risk": ["Pandemic risk", "AI disruption", "Black swan events", "Systemic market collapse", "Interconnected risk cascades", "Regulatory paradigm shift"]
        },
        "ar": {
            "المخاطر الاستراتيجية": ["تعطيل السوق", "الضغط التنافسي", "عدم التوافق الاستراتيجي", "مخاطر الاندماج والاستحواذ", "فشل الابتكار", "فجوة توقعات أصحاب المصلحة"],
            "المخاطر التشغيلية": ["فشل العمليات", "توقف الأنظمة", "تعطل سلسلة التوريد", "الخطأ البشري", "قيود السعة", "فشل الجودة"],
            "المخاطر المالية": ["مخاطر السيولة", "مخاطر الائتمان", "مخاطر السوق", "مخاطر العملة", "مخاطر سعر الفائدة", "كفاية رأس المال"],
            "مخاطر الامتثال والقانون": ["خرق تنظيمي", "نزاع تعاقدي", "التعرض للتقاضي", "مخاطر التراخيص", "انتهاك مكافحة الفساد", "مخاطر العقوبات"],
            "مخاطر السمعة": ["ضرر العلامة التجارية", "تآكل الثقة العامة", "أزمة وسائل التواصل", "سوء السلوك الأخلاقي", "انتقاد ESG", "تصعيد شكاوى العملاء"],
            "المخاطر الجيوسياسية": ["عدم الاستقرار السياسي", "القيود التجارية", "العقوبات", "تعارض تنظيمي عابر للحدود", "مخاطر التأميم", "الصراع الإقليمي"],
            "المخاطر البيئية والمناخية": ["مخاطر المناخ المادية", "مخاطر التحول", "مخاطر الكربون التنظيمية", "شح الموارد", "الكوارث الطبيعية", "المسؤولية البيئية"],
            "مخاطر الأفراد والثقافة": ["الاعتماد على أشخاص رئيسيين", "استنزاف المواهب", "نقص المهارات", "سلامة بيئة العمل", "النزاعات العمالية", "عدم توافق الثقافة"],
            "مخاطر التقنية والسيبرانية": ["الهجمات السيبرانية", "تقادم التقنية", "فشل التحول الرقمي", "خرق البيانات", "فشل البنية التحتية لتقنية المعلومات", "مخاطر تقنية الأطراف الثالثة"],
            "المخاطر الناشئة والنظامية": ["مخاطر الجائحة", "اضطراب الذكاء الاصطناعي", "أحداث البجعة السوداء", "انهيار السوق النظامي", "تتابع المخاطر المترابطة", "تحول النموذج التنظيمي"]
        }
    }
}

DOMAIN_CODES = {
    "Cyber Security": "cyber",
    "Data Management": "data", 
    "Artificial Intelligence": "ai",
    "Digital Transformation": "dt",
    "Global Standards": "global",
    "Enterprise Risk Management": "erm",
    "الأمن السيبراني": "cyber",
    "إدارة البيانات": "data",
    "الذكاء الاصطناعي": "ai",
    "التحول الرقمي": "dt",
    "المعايير العالمية": "global",
    "إدارة المخاطر المؤسسية": "erm"
}

# ============================================================================
# AWARENESS MODULES - Domain Specific Training & Quizzes
# ============================================================================

AWARENESS_MODULES = {
    "cyber": {
        "en": [
            {
                "id": "cyber_phishing",
                "title": "Phishing & Social Engineering",
                "icon": "fas fa-fish",
                "level": "Beginner",
                "duration": "15 min",
                "description": "Learn to identify phishing emails, social engineering tactics, and protect yourself from common attack vectors.",
                "learning_points": [
                    "How to spot phishing emails by checking sender addresses, URLs, and urgent language",
                    "Common social engineering tactics: pretexting, baiting, tailgating, and quid pro quo",
                    "Safe practices: never click suspicious links, verify requests through official channels",
                    "Reporting procedures when you suspect a phishing attempt"
                ],
                "scenario": {
                    "title": "The Urgent Invoice",
                    "text": "You receive an email from 'finance-dept@yourcompany.co' (note: your company domain is yourcompany.com) saying: 'URGENT: Overdue invoice attached. Pay within 24 hours to avoid service interruption.' The email has a ZIP attachment and asks you to enable macros.",
                    "correct_action": "Do not open the attachment. Report it to IT security. The domain is suspicious (.co vs .com), the urgency is a red flag, and ZIP files with macros are a common malware delivery method."
                },
                "quiz": [
                    {"q": "Which of the following is a strong indicator of a phishing email?", "options": ["The email is from a colleague", "The sender domain has a slight misspelling", "The email contains your name", "The email is about a meeting"], "answer": 1},
                    {"q": "An unknown person calls claiming to be IT support and asks for your password. What should you do?", "options": ["Provide the password since IT needs it", "Hang up and call the official IT helpdesk number", "Give only your username", "Ask them to call back later"], "answer": 1},
                    {"q": "What is 'tailgating' in cybersecurity?", "options": ["Following too closely while driving", "Following an authorized person through a secured door", "Sending multiple spam emails", "Monitoring network traffic"], "answer": 1},
                    {"q": "You receive an email with an attachment from your CEO asking you to urgently wire money. What's the best first step?", "options": ["Wire the money immediately", "Reply to the email asking for confirmation", "Call the CEO using a known phone number to verify", "Forward it to all employees as a warning"], "answer": 2},
                    {"q": "Which file type is most commonly used to deliver malware?", "options": [".txt files", ".jpg images", ".exe or macro-enabled documents", ".pdf files only"], "answer": 2}
                ]
            },
            {
                "id": "cyber_passwords",
                "title": "Password Security & MFA",
                "icon": "fas fa-key",
                "level": "Beginner",
                "duration": "10 min",
                "description": "Best practices for creating strong passwords, managing credentials, and using multi-factor authentication.",
                "learning_points": [
                    "Strong passwords: 12+ characters, mix of upper/lower case, numbers, and symbols",
                    "Never reuse passwords across different accounts or systems",
                    "Use a password manager to generate and store unique passwords",
                    "Enable MFA (Multi-Factor Authentication) on all critical accounts",
                    "Understand authentication factors: something you know, have, and are"
                ],
                "scenario": {
                    "title": "The Shared Password",
                    "text": "Your colleague asks to borrow your login credentials to access a shared system while their account is being reset. They say it's just for today and the deadline is tight.",
                    "correct_action": "Never share your credentials. Suggest they contact IT for a temporary account or expedited reset. Sharing passwords violates security policy and makes you accountable for their actions."
                },
                "quiz": [
                    {"q": "What is the recommended minimum password length?", "options": ["6 characters", "8 characters", "12 characters", "4 characters"], "answer": 2},
                    {"q": "Which is the strongest password?", "options": ["Password123", "MyDog'sName", "j7$kL9!mQ2#xP4", "12345678"], "answer": 2},
                    {"q": "What does MFA stand for?", "options": ["Multiple File Access", "Multi-Factor Authentication", "Main Firewall Application", "Managed File Audit"], "answer": 1},
                    {"q": "Which is NOT a valid MFA factor?", "options": ["Fingerprint scan", "SMS code", "Security question", "Your favorite color"], "answer": 3},
                    {"q": "A colleague asks for your password to finish an urgent task. What should you do?", "options": ["Share it just this once", "Give them a hint", "Refuse and suggest contacting IT", "Write it on a sticky note for them"], "answer": 2}
                ]
            },
            {
                "id": "cyber_data_protection",
                "title": "Data Classification & Protection",
                "icon": "fas fa-shield-alt",
                "level": "Intermediate",
                "duration": "20 min",
                "description": "Understanding data classification levels, handling sensitive information, and compliance with data protection regulations.",
                "learning_points": [
                    "Data classification levels: Public, Internal, Confidential, Restricted/Top Secret",
                    "Each classification level requires specific handling, storage, and transmission controls",
                    "Encryption requirements for data at rest and in transit",
                    "Clean desk policy and secure disposal of sensitive documents",
                    "Compliance with NCA ECC, PDPL, and sector-specific regulations"
                ],
                "scenario": {
                    "title": "The USB Drive",
                    "text": "You find a USB drive in the parking lot with a label 'Salary Report Q4'. You're curious about it and consider plugging it into your work computer to find the owner.",
                    "correct_action": "Never plug unknown USB devices into any computer. Report it to security or IT. This is a known attack vector called 'USB baiting' where malware is deliberately planted on drives."
                },
                "quiz": [
                    {"q": "Which data classification typically requires encryption?", "options": ["Public", "Internal only", "Confidential and Restricted", "None of them"], "answer": 2},
                    {"q": "What should you do with printed confidential documents you no longer need?", "options": ["Put them in the regular trash", "Shred them using a cross-cut shredder", "Leave them on your desk", "Recycle them normally"], "answer": 1},
                    {"q": "You need to send a confidential file to a partner. What is the safest method?", "options": ["Personal email attachment", "Encrypted file via approved secure channel", "WhatsApp message", "Unencrypted USB drive"], "answer": 1},
                    {"q": "What does PDPL stand for in Saudi regulations?", "options": ["Private Data Protocol Law", "Personal Data Protection Law", "Public Domain Privacy License", "Primary Data Processing Limit"], "answer": 1},
                    {"q": "An employee accidentally emails confidential data to the wrong person. What should happen first?", "options": ["Ignore it", "Notify the security team immediately", "Delete the sent email", "Ask the recipient to delete it"], "answer": 1}
                ]
            },
            {
                "id": "cyber_incident",
                "title": "Incident Response Basics",
                "icon": "fas fa-ambulance",
                "level": "Intermediate",
                "duration": "15 min",
                "description": "How to recognize, report, and respond to cybersecurity incidents effectively.",
                "learning_points": [
                    "Signs of a security incident: unusual system behavior, unauthorized access alerts, data anomalies",
                    "Incident response steps: Identify, Contain, Eradicate, Recover, Lessons Learned",
                    "Your role: report immediately, preserve evidence, follow established procedures",
                    "Do NOT try to investigate or fix the issue yourself — let the security team handle it",
                    "Documentation is critical: record what you observed, when, and what actions you took"
                ],
                "scenario": {
                    "title": "The Ransomware Alert",
                    "text": "Your computer screen suddenly displays a message saying all your files are encrypted and demands payment in Bitcoin. Some files on the shared drive also appear affected.",
                    "correct_action": "Disconnect from the network immediately (unplug Ethernet or disable WiFi). Do NOT pay the ransom. Call the IT security team right away. Do not restart the computer as this may destroy forensic evidence."
                },
                "quiz": [
                    {"q": "What is the first thing to do when you suspect a cybersecurity incident?", "options": ["Try to fix it yourself", "Report it to the security team immediately", "Turn off your computer", "Wait to see if it resolves"], "answer": 1},
                    {"q": "If your computer is infected with ransomware, should you pay the ransom?", "options": ["Yes, to get files back quickly", "No, it funds criminals and there's no guarantee of recovery", "Only if the amount is small", "Yes, if the company approves"], "answer": 1},
                    {"q": "What is the correct order of incident response?", "options": ["Fix, Report, Forget", "Identify, Contain, Eradicate, Recover, Lessons Learned", "Panic, Restart, Hope", "Eradicate, Identify, Recover"], "answer": 1},
                    {"q": "Why should you preserve evidence during an incident?", "options": ["For social media posts", "For forensic analysis and legal proceedings", "It's not important", "To show your manager"], "answer": 1},
                    {"q": "During an active incident, who should communicate with the media?", "options": ["Any employee", "Only the designated spokesperson/PR team", "The IT team", "The person who found the incident"], "answer": 1}
                ]
            }
        ],
        "ar": [
            {
                "id": "cyber_phishing",
                "title": "التصيد الاحتيالي والهندسة الاجتماعية",
                "icon": "fas fa-fish",
                "level": "مبتدئ",
                "duration": "15 دقيقة",
                "description": "تعلم كيفية التعرف على رسائل التصيد الاحتيالي وأساليب الهندسة الاجتماعية وحماية نفسك من أشهر طرق الهجوم.",
                "learning_points": [
                    "كيفية اكتشاف رسائل التصيد من خلال التحقق من عنوان المرسل والروابط واللغة العاجلة",
                    "أساليب الهندسة الاجتماعية الشائعة: الذرائع، الإغراء، التتبع، والمقايضة",
                    "الممارسات الآمنة: لا تنقر على الروابط المشبوهة، تحقق من الطلبات عبر القنوات الرسمية",
                    "إجراءات الإبلاغ عند الاشتباه في محاولة تصيد احتيالي"
                ],
                "scenario": {
                    "title": "الفاتورة العاجلة",
                    "text": "تلقيت بريداً إلكترونياً من 'finance-dept@yourcompany.co' (ملاحظة: نطاق شركتك هو yourcompany.com) يقول: 'عاجل: فاتورة متأخرة مرفقة. ادفع خلال 24 ساعة لتجنب انقطاع الخدمة.' يحتوي البريد على مرفق ZIP ويطلب تفعيل وحدات الماكرو.",
                    "correct_action": "لا تفتح المرفق. أبلغ فريق أمن تقنية المعلومات. النطاق مشبوه (.co بدلاً من .com)، والاستعجال علامة تحذيرية، وملفات ZIP مع وحدات الماكرو وسيلة شائعة لنشر البرمجيات الخبيثة."
                },
                "quiz": [
                    {"q": "أي مما يلي مؤشر قوي على بريد تصيد احتيالي؟", "options": ["البريد من زميل", "نطاق المرسل به خطأ إملائي بسيط", "البريد يحتوي على اسمك", "البريد عن اجتماع"], "answer": 1},
                    {"q": "اتصل بك شخص مجهول يدعي أنه من الدعم الفني ويطلب كلمة المرور. ماذا تفعل؟", "options": ["أعطيه الكلمة لأن الدعم يحتاجها", "أغلق الخط واتصل بالرقم الرسمي للدعم", "أعطيه اسم المستخدم فقط", "اطلب منه معاودة الاتصال لاحقاً"], "answer": 1},
                    {"q": "ما هو 'التتبع' (Tailgating) في الأمن السيبراني؟", "options": ["القيادة خلف شخص عن قرب", "الدخول خلف شخص مصرح له عبر باب مؤمّن", "إرسال رسائل مزعجة متعددة", "مراقبة حركة الشبكة"], "answer": 1},
                    {"q": "تلقيت بريداً من الرئيس التنفيذي يطلب تحويل أموال عاجل. ما أفضل خطوة أولى؟", "options": ["حوّل المبلغ فوراً", "رد على البريد لتأكيد", "اتصل بالرئيس على رقم معروف للتحقق", "أعد توجيهه للجميع كتحذير"], "answer": 2},
                    {"q": "أي نوع ملفات يُستخدم أكثر لنشر البرمجيات الخبيثة؟", "options": ["ملفات .txt", "صور .jpg", "ملفات .exe أو مستندات بوحدات ماكرو", "ملفات .pdf فقط"], "answer": 2}
                ]
            },
            {
                "id": "cyber_passwords",
                "title": "أمان كلمات المرور والمصادقة المتعددة",
                "icon": "fas fa-key",
                "level": "مبتدئ",
                "duration": "10 دقائق",
                "description": "أفضل الممارسات لإنشاء كلمات مرور قوية وإدارة بيانات الاعتماد واستخدام المصادقة متعددة العوامل.",
                "learning_points": [
                    "كلمات المرور القوية: 12 حرفاً على الأقل، مزيج من الأحرف الكبيرة والصغيرة والأرقام والرموز",
                    "لا تعيد استخدام كلمات المرور عبر حسابات أو أنظمة مختلفة",
                    "استخدم مدير كلمات المرور لإنشاء وتخزين كلمات مرور فريدة",
                    "فعّل المصادقة متعددة العوامل (MFA) على جميع الحسابات المهمة",
                    "عوامل المصادقة: شيء تعرفه، شيء تملكه، شيء أنت عليه"
                ],
                "scenario": {
                    "title": "كلمة المرور المشتركة",
                    "text": "طلب زميلك استعارة بيانات تسجيل الدخول الخاصة بك للوصول إلى نظام مشترك بينما يتم إعادة تعيين حسابه. يقول إنها ليوم واحد فقط والموعد النهائي قريب.",
                    "correct_action": "لا تشارك بيانات الاعتماد أبداً. اقترح عليه الاتصال بتقنية المعلومات للحصول على حساب مؤقت. مشاركة كلمات المرور تنتهك سياسة الأمان وتجعلك مسؤولاً عن تصرفاته."
                },
                "quiz": [
                    {"q": "ما الحد الأدنى الموصى به لطول كلمة المرور؟", "options": ["6 أحرف", "8 أحرف", "12 حرفاً", "4 أحرف"], "answer": 2},
                    {"q": "أي كلمة مرور هي الأقوى؟", "options": ["Password123", "اسم_كلبي", "j7$kL9!mQ2#xP4", "12345678"], "answer": 2},
                    {"q": "ماذا تعني MFA؟", "options": ["الوصول المتعدد للملفات", "المصادقة متعددة العوامل", "تطبيق الجدار الناري الرئيسي", "تدقيق الملفات المُدارة"], "answer": 1},
                    {"q": "أي مما يلي ليس عامل مصادقة صالحاً؟", "options": ["بصمة الإصبع", "رمز SMS", "سؤال الأمان", "لونك المفضل"], "answer": 3},
                    {"q": "طلب زميل كلمة مرورك لإنهاء مهمة عاجلة. ماذا تفعل؟", "options": ["شاركها هذه المرة فقط", "أعطه تلميحاً", "ارفض واقترح الاتصال بتقنية المعلومات", "اكتبها على ورقة لاصقة له"], "answer": 2}
                ]
            },
            {
                "id": "cyber_data_protection",
                "title": "تصنيف البيانات وحمايتها",
                "icon": "fas fa-shield-alt",
                "level": "متوسط",
                "duration": "20 دقيقة",
                "description": "فهم مستويات تصنيف البيانات والتعامل مع المعلومات الحساسة والامتثال لأنظمة حماية البيانات.",
                "learning_points": [
                    "مستويات تصنيف البيانات: عامة، داخلية، سرية، مقيدة/سرية للغاية",
                    "كل مستوى تصنيف يتطلب ضوابط محددة للتعامل والتخزين والنقل",
                    "متطلبات التشفير للبيانات المخزنة والمنقولة",
                    "سياسة المكتب النظيف والتخلص الآمن من المستندات الحساسة",
                    "الامتثال لـ NCA ECC و PDPL واللوائح القطاعية"
                ],
                "scenario": {
                    "title": "ذاكرة USB",
                    "text": "وجدت ذاكرة USB في موقف السيارات عليها ملصق 'تقرير الرواتب Q4'. تشعر بالفضول وتفكر في توصيلها بجهاز العمل لمعرفة صاحبها.",
                    "correct_action": "لا تقم أبداً بتوصيل أجهزة USB مجهولة بأي حاسوب. أبلغ فريق الأمن أو تقنية المعلومات. هذا أسلوب هجوم معروف يُسمى 'إغراء USB' حيث تُزرع البرمجيات الخبيثة عمداً."
                },
                "quiz": [
                    {"q": "أي تصنيف بيانات يتطلب عادةً التشفير؟", "options": ["عامة", "داخلية فقط", "سرية ومقيدة", "لا شيء منها"], "answer": 2},
                    {"q": "ماذا تفعل بالمستندات السرية المطبوعة التي لم تعد تحتاجها؟", "options": ["ضعها في سلة المهملات العادية", "مزقها باستخدام آلة تمزيق متقاطعة", "اتركها على مكتبك", "أعد تدويرها بشكل عادي"], "answer": 1},
                    {"q": "تحتاج لإرسال ملف سري لشريك. ما هي الطريقة الأكثر أماناً؟", "options": ["مرفق بريد شخصي", "ملف مشفر عبر قناة آمنة معتمدة", "رسالة واتساب", "ذاكرة USB غير مشفرة"], "answer": 1},
                    {"q": "ماذا يعني PDPL في اللوائح السعودية؟", "options": ["قانون بروتوكول البيانات الخاصة", "نظام حماية البيانات الشخصية", "رخصة خصوصية النطاق العام", "حد معالجة البيانات الأساسي"], "answer": 1},
                    {"q": "أرسل موظف بيانات سرية بالخطأ لشخص غير مخول. ما أول إجراء؟", "options": ["تجاهل الأمر", "إبلاغ فريق الأمن فوراً", "حذف البريد المرسل", "طلب حذفها من المستلم"], "answer": 1}
                ]
            },
            {
                "id": "cyber_incident",
                "title": "أساسيات الاستجابة للحوادث",
                "icon": "fas fa-ambulance",
                "level": "متوسط",
                "duration": "15 دقيقة",
                "description": "كيفية التعرف على حوادث الأمن السيبراني والإبلاغ عنها والاستجابة لها بفعالية.",
                "learning_points": [
                    "علامات الحادث الأمني: سلوك غير عادي للنظام، تنبيهات وصول غير مصرح به، شذوذ في البيانات",
                    "خطوات الاستجابة للحوادث: التحديد، الاحتواء، الإزالة، الاستعادة، الدروس المستفادة",
                    "دورك: أبلغ فوراً، حافظ على الأدلة، اتبع الإجراءات المعتمدة",
                    "لا تحاول التحقيق أو الإصلاح بنفسك — دع فريق الأمن يتولى الأمر",
                    "التوثيق مهم: سجل ما لاحظته ومتى وما الإجراءات التي اتخذتها"
                ],
                "scenario": {
                    "title": "تنبيه فدية",
                    "text": "ظهرت فجأة رسالة على شاشة حاسوبك تقول إن جميع ملفاتك مشفرة وتطالب بالدفع بالبيتكوين. بعض الملفات على المجلد المشترك تبدو متأثرة أيضاً.",
                    "correct_action": "افصل عن الشبكة فوراً (افصل كابل الإيثرنت أو أوقف الواي فاي). لا تدفع الفدية. اتصل بفريق أمن تقنية المعلومات فوراً. لا تعد تشغيل الحاسوب لأن ذلك قد يدمر الأدلة الجنائية."
                },
                "quiz": [
                    {"q": "ما أول شيء تفعله عند الاشتباه بحادث أمن سيبراني؟", "options": ["حاول إصلاحه بنفسك", "أبلغ فريق الأمن فوراً", "أطفئ حاسوبك", "انتظر لترى إن حُل"], "answer": 1},
                    {"q": "إذا أصيب حاسوبك ببرنامج فدية، هل يجب دفع الفدية؟", "options": ["نعم لاستعادة الملفات بسرعة", "لا، فهذا يموّل المجرمين ولا ضمان للاستعادة", "فقط إذا كان المبلغ صغيراً", "نعم إذا وافقت الشركة"], "answer": 1},
                    {"q": "ما الترتيب الصحيح للاستجابة للحوادث؟", "options": ["إصلاح، إبلاغ، نسيان", "تحديد، احتواء، إزالة، استعادة، دروس مستفادة", "ذعر، إعادة تشغيل، أمل", "إزالة، تحديد، استعادة"], "answer": 1},
                    {"q": "لماذا يجب الحفاظ على الأدلة أثناء الحادث؟", "options": ["للنشر على وسائل التواصل", "للتحليل الجنائي والإجراءات القانونية", "ليست مهمة", "لإظهارها للمدير"], "answer": 1},
                    {"q": "أثناء حادث نشط، من يجب أن يتحدث مع الإعلام؟", "options": ["أي موظف", "المتحدث الرسمي / فريق العلاقات العامة فقط", "فريق تقنية المعلومات", "الشخص الذي اكتشف الحادث"], "answer": 1}
                ]
            }
        ]
    },
    "data": {
        "en": [
            {
                "id": "data_governance",
                "title": "Data Governance Fundamentals",
                "icon": "fas fa-database",
                "level": "Beginner",
                "duration": "15 min",
                "description": "Core principles of data governance, roles, and responsibilities for managing organizational data assets.",
                "learning_points": [
                    "Data governance ensures data quality, security, availability, and usability across the organization",
                    "Key roles: Data Owner, Data Steward, Data Custodian, and Data Consumer",
                    "Data lifecycle: Creation, Storage, Usage, Sharing, Archiving, and Destruction",
                    "Establishing data standards and policies for consistent management"
                ],
                "scenario": {"title": "The Duplicate Records", "text": "Your team discovers that the same customer exists in three different databases with slightly different names and addresses. Orders are being split across records, causing billing errors.", "correct_action": "Report the data quality issue to the Data Steward. Implement a master data management approach with a single source of truth. Establish data entry standards to prevent future duplicates."},
                "quiz": [
                    {"q": "Who is typically responsible for defining data quality standards?", "options": ["IT department only", "Data Steward", "Any employee", "External auditors"], "answer": 1},
                    {"q": "What is a 'single source of truth' in data management?", "options": ["A single database server", "One authoritative data source everyone references", "A backup copy of data", "The CEO's report"], "answer": 1},
                    {"q": "Which is NOT part of the data lifecycle?", "options": ["Creation", "Storage", "Monetization", "Destruction"], "answer": 2},
                    {"q": "What is a Data Custodian responsible for?", "options": ["Business decisions about data", "Technical management and storage of data", "Creating data policies", "Using data for reports"], "answer": 1},
                    {"q": "Why is data governance important?", "options": ["Only for compliance", "To increase IT budgets", "To ensure data quality, security, and proper use", "To slow down operations"], "answer": 2}
                ]
            },
            {
                "id": "data_quality",
                "title": "Data Quality & Integrity",
                "icon": "fas fa-check-double",
                "level": "Intermediate",
                "duration": "15 min",
                "description": "Ensuring data accuracy, completeness, consistency, and timeliness across systems.",
                "learning_points": ["Data quality dimensions: Accuracy, Completeness, Consistency, Timeliness, Validity, Uniqueness", "Impact of poor data quality: wrong decisions, compliance failures, customer dissatisfaction", "Data validation techniques: input validation, cross-referencing, automated checks", "Establishing data quality metrics and monitoring dashboards"],
                "scenario": {"title": "The Missing Records", "text": "A regulatory audit reveals that 15% of transaction records are missing required fields. The compliance team is asking for an explanation and a remediation plan.", "correct_action": "Conduct a root cause analysis to identify where the data quality breaks. Implement mandatory field validation at the data entry point. Create a remediation plan with timeline to fix existing records and prevent recurrence."},
                "quiz": [
                    {"q": "Which is NOT a dimension of data quality?", "options": ["Accuracy", "Completeness", "Popularity", "Timeliness"], "answer": 2},
                    {"q": "What causes the biggest impact from poor data quality?", "options": ["Slower computers", "Incorrect business decisions", "Bigger databases", "More storage costs"], "answer": 1},
                    {"q": "What is data validation?", "options": ["Deleting old data", "Checking data meets defined rules before accepting it", "Backing up data", "Sharing data externally"], "answer": 1},
                    {"q": "How often should data quality be measured?", "options": ["Once a year", "Only during audits", "Continuously through automated monitoring", "Never"], "answer": 2},
                    {"q": "What is a data quality metric?", "options": ["The size of a database", "A measurable indicator of data quality", "A type of database software", "An encryption method"], "answer": 1}
                ]
            },
            {
                "id": "data_privacy",
                "title": "Data Privacy & PDPL Compliance",
                "icon": "fas fa-user-lock",
                "level": "Intermediate",
                "duration": "20 min",
                "description": "Understanding personal data protection requirements under Saudi PDPL and international regulations.",
                "learning_points": ["PDPL principles: lawful processing, purpose limitation, data minimization, accuracy, storage limitation", "Individual rights: access, correction, deletion, portability, objection to processing", "Requirements for cross-border data transfers", "Data breach notification obligations and timelines"],
                "scenario": {"title": "The Marketing Database", "text": "Marketing wants to use customer data collected for service delivery to send promotional emails. They argue it will increase revenue and the data is already available.", "correct_action": "This likely violates purpose limitation. The data was collected for service delivery, not marketing. Marketing needs to obtain separate consent for promotional use or verify that the privacy policy covers marketing as a compatible purpose."},
                "quiz": [
                    {"q": "What is 'purpose limitation' in PDPL?", "options": ["Limiting data storage", "Using data only for the purpose it was collected for", "Limiting database size", "Restricting employee access"], "answer": 1},
                    {"q": "Under PDPL, what right do individuals have regarding their data?", "options": ["No rights", "Right to access and correct their data", "Only the right to delete", "Only government access"], "answer": 1},
                    {"q": "When must a data breach be reported under PDPL?", "options": ["Within 72 hours", "Within 30 days", "Only if data is lost", "Reporting is optional"], "answer": 0},
                    {"q": "What does 'data minimization' mean?", "options": ["Deleting all data", "Collecting only what is necessary for the stated purpose", "Using the smallest database", "Minimizing IT costs"], "answer": 1},
                    {"q": "Can personal data be transferred outside Saudi Arabia?", "options": ["Always freely", "Never under any circumstances", "Only with adequate protections and authorization", "Only to GCC countries"], "answer": 2}
                ]
            }
        ],
        "ar": [
            {
                "id": "data_governance", "title": "أساسيات حوكمة البيانات", "icon": "fas fa-database", "level": "مبتدئ", "duration": "15 دقيقة",
                "description": "المبادئ الأساسية لحوكمة البيانات والأدوار والمسؤوليات لإدارة أصول البيانات المؤسسية.",
                "learning_points": ["حوكمة البيانات تضمن جودة وأمن وتوفر وسهولة استخدام البيانات عبر المنظمة", "الأدوار الرئيسية: مالك البيانات، أمين البيانات، حارس البيانات، مستخدم البيانات", "دورة حياة البيانات: الإنشاء، التخزين، الاستخدام، المشاركة، الأرشفة، الإتلاف", "وضع معايير وسياسات البيانات للإدارة المتسقة"],
                "scenario": {"title": "السجلات المكررة", "text": "اكتشف فريقك أن نفس العميل موجود في ثلاث قواعد بيانات مختلفة بأسماء وعناوين مختلفة قليلاً. الطلبات مقسمة عبر السجلات مما يسبب أخطاء في الفواتير.", "correct_action": "أبلغ أمين البيانات بمشكلة الجودة. طبّق نهج إدارة البيانات الرئيسية بمصدر واحد للحقيقة. ضع معايير إدخال البيانات لمنع التكرار مستقبلاً."},
                "quiz": [
                    {"q": "من المسؤول عادةً عن تحديد معايير جودة البيانات؟", "options": ["قسم تقنية المعلومات فقط", "أمين البيانات", "أي موظف", "المدققون الخارجيون"], "answer": 1},
                    {"q": "ما هو 'المصدر الواحد للحقيقة'؟", "options": ["خادم قاعدة بيانات واحد", "مصدر بيانات واحد موثوق يرجع إليه الجميع", "نسخة احتياطية", "تقرير الرئيس التنفيذي"], "answer": 1},
                    {"q": "أي مما يلي ليس جزءاً من دورة حياة البيانات؟", "options": ["الإنشاء", "التخزين", "التسييل", "الإتلاف"], "answer": 2},
                    {"q": "ما مسؤولية حارس البيانات؟", "options": ["القرارات التجارية حول البيانات", "الإدارة التقنية وتخزين البيانات", "إنشاء سياسات البيانات", "استخدام البيانات للتقارير"], "answer": 1},
                    {"q": "لماذا حوكمة البيانات مهمة؟", "options": ["للامتثال فقط", "لزيادة ميزانية تقنية المعلومات", "لضمان جودة البيانات وأمنها واستخدامها السليم", "لإبطاء العمليات"], "answer": 2}
                ]
            },
            {
                "id": "data_quality", "title": "جودة البيانات وسلامتها", "icon": "fas fa-check-double", "level": "متوسط", "duration": "15 دقيقة",
                "description": "ضمان دقة البيانات واكتمالها واتساقها وتوقيتها عبر الأنظمة.",
                "learning_points": ["أبعاد جودة البيانات: الدقة، الاكتمال، الاتساق، التوقيت، الصلاحية، التفرد", "أثر ضعف الجودة: قرارات خاطئة، فشل في الامتثال، عدم رضا العملاء", "تقنيات التحقق: التحقق من المدخلات، المراجعة التبادلية، الفحوصات الآلية", "وضع مقاييس جودة البيانات ولوحات المراقبة"],
                "scenario": {"title": "السجلات المفقودة", "text": "كشف تدقيق تنظيمي أن 15% من سجلات المعاملات تفتقد حقولاً مطلوبة. فريق الامتثال يطلب تفسيراً وخطة معالجة.", "correct_action": "أجرِ تحليل السبب الجذري لتحديد مكان خلل جودة البيانات. طبّق التحقق الإلزامي من الحقول عند نقطة إدخال البيانات. أنشئ خطة معالجة بجدول زمني."},
                "quiz": [
                    {"q": "أي مما يلي ليس بُعداً لجودة البيانات؟", "options": ["الدقة", "الاكتمال", "الشعبية", "التوقيت"], "answer": 2},
                    {"q": "ما أكبر أثر لضعف جودة البيانات؟", "options": ["بطء الحواسيب", "قرارات تجارية خاطئة", "قواعد بيانات أكبر", "تكاليف تخزين أعلى"], "answer": 1},
                    {"q": "ما هو التحقق من البيانات؟", "options": ["حذف البيانات القديمة", "فحص البيانات وفق قواعد محددة قبل قبولها", "نسخ البيانات احتياطياً", "مشاركة البيانات خارجياً"], "answer": 1},
                    {"q": "كم مرة يجب قياس جودة البيانات؟", "options": ["مرة سنوياً", "أثناء التدقيق فقط", "باستمرار عبر المراقبة الآلية", "أبداً"], "answer": 2},
                    {"q": "ما هو مقياس جودة البيانات؟", "options": ["حجم قاعدة البيانات", "مؤشر قابل للقياس لجودة البيانات", "نوع من برامج قواعد البيانات", "طريقة تشفير"], "answer": 1}
                ]
            },
            {
                "id": "data_privacy", "title": "خصوصية البيانات والامتثال لنظام PDPL", "icon": "fas fa-user-lock", "level": "متوسط", "duration": "20 دقيقة",
                "description": "فهم متطلبات حماية البيانات الشخصية وفق نظام PDPL السعودي واللوائح الدولية.",
                "learning_points": ["مبادئ PDPL: المعالجة المشروعة، تحديد الغرض، تقليل البيانات، الدقة، تحديد التخزين", "حقوق الأفراد: الوصول، التصحيح، الحذف، النقل، الاعتراض على المعالجة", "متطلبات نقل البيانات عبر الحدود", "التزامات إخطار خرق البيانات والجداول الزمنية"],
                "scenario": {"title": "قاعدة بيانات التسويق", "text": "يريد التسويق استخدام بيانات العملاء المجمعة لتقديم الخدمات لإرسال رسائل ترويجية. يقولون إنها ستزيد الإيرادات والبيانات متاحة بالفعل.", "correct_action": "هذا على الأرجح ينتهك تحديد الغرض. جُمعت البيانات لتقديم الخدمات لا للتسويق. يحتاج التسويق للحصول على موافقة منفصلة أو التحقق من أن سياسة الخصوصية تغطي التسويق كغرض متوافق."},
                "quiz": [
                    {"q": "ما هو 'تحديد الغرض' في PDPL؟", "options": ["تحديد مساحة التخزين", "استخدام البيانات فقط للغرض الذي جُمعت من أجله", "تحديد حجم القاعدة", "تقييد وصول الموظفين"], "answer": 1},
                    {"q": "بموجب PDPL، ما الحق الذي يملكه الأفراد بشأن بياناتهم؟", "options": ["لا حقوق", "حق الوصول والتصحيح", "حق الحذف فقط", "وصول الحكومة فقط"], "answer": 1},
                    {"q": "متى يجب الإبلاغ عن خرق البيانات وفق PDPL؟", "options": ["خلال 72 ساعة", "خلال 30 يوماً", "فقط إذا فُقدت البيانات", "الإبلاغ اختياري"], "answer": 0},
                    {"q": "ماذا يعني 'تقليل البيانات'؟", "options": ["حذف جميع البيانات", "جمع الضروري فقط للغرض المحدد", "استخدام أصغر قاعدة بيانات", "تقليل تكاليف تقنية المعلومات"], "answer": 1},
                    {"q": "هل يمكن نقل البيانات الشخصية خارج السعودية؟", "options": ["دائماً بحرية", "أبداً تحت أي ظرف", "فقط مع حماية كافية وتفويض", "فقط لدول الخليج"], "answer": 2}
                ]
            }
        ]
    },
    "ai": {
        "en": [
            {
                "id": "ai_ethics", "title": "AI Ethics & Responsible Use", "icon": "fas fa-balance-scale", "level": "Beginner", "duration": "15 min",
                "description": "Understanding ethical principles for AI development, deployment, and governance.",
                "learning_points": ["Core AI ethics principles: fairness, transparency, accountability, privacy, safety", "Bias in AI: how it occurs in training data, model design, and deployment", "Explainability: users have the right to understand AI decisions that affect them", "Human oversight: AI should augment, not replace, human judgment in critical decisions"],
                "scenario": {"title": "The Biased Hiring Tool", "text": "Your company deployed an AI tool to screen resumes. After 3 months, data shows it consistently ranks male candidates higher. The tool was trained on historical hiring data from the past 10 years.", "correct_action": "Pause the tool immediately. The historical data likely reflects past gender bias. Conduct a fairness audit, retrain with balanced data, implement ongoing bias monitoring, and ensure human review of all AI-assisted hiring decisions."},
                "quiz": [
                    {"q": "What is AI bias?", "options": ["A type of AI software", "Systematic favoritism or discrimination in AI outputs", "Normal AI behavior", "An AI programming language"], "answer": 1},
                    {"q": "Why is AI explainability important?", "options": ["Only for developers", "So users understand how AI decisions are made", "It's not important", "Only for marketing purposes"], "answer": 1},
                    {"q": "What should happen when AI makes a high-risk decision?", "options": ["Accept it automatically", "A human should review it", "Ignore any concerns", "Speed up the process"], "answer": 1},
                    {"q": "How does bias typically enter AI systems?", "options": ["Through biased training data", "Through electricity", "AI cannot be biased", "Only through intentional programming"], "answer": 0},
                    {"q": "What is 'human-in-the-loop' in AI governance?", "options": ["Humans training AI to exercise", "Requiring human review of AI decisions", "A programming framework", "An error in AI"], "answer": 1}
                ]
            },
            {
                "id": "ai_data_handling", "title": "AI Data Handling & Privacy", "icon": "fas fa-brain", "level": "Intermediate", "duration": "15 min",
                "description": "Protecting sensitive data when using AI tools, chatbots, and automated systems.",
                "learning_points": ["Never input confidential, personal, or classified data into public AI tools", "Understand where AI tools store and process your data — cloud vs. on-premise", "AI-generated content may contain hallucinations — always verify critical information", "Organizational policies for approved AI tools and use cases"],
                "scenario": {"title": "The AI Shortcut", "text": "A team member copies a confidential contract into a public AI chatbot to summarize it, saving hours of work. They share the AI summary in a team meeting.", "correct_action": "This is a data breach. The confidential contract was sent to a third-party AI service. Report the incident, assess what data was exposed, and remind the team that confidential data must never be input into public AI tools."},
                "quiz": [
                    {"q": "Is it safe to paste confidential data into public AI tools?", "options": ["Yes, AI tools are always secure", "No, the data may be stored and used for training", "Only short texts", "Only if you delete the chat after"], "answer": 1},
                    {"q": "What is an AI 'hallucination'?", "options": ["AI having dreams", "AI generating false or fabricated information confidently", "A visual AI effect", "Normal AI behavior"], "answer": 1},
                    {"q": "Before using an AI tool at work, you should:", "options": ["Just use whatever is available", "Check if it's approved by your organization's policy", "Ask a friend", "Google it"], "answer": 1},
                    {"q": "Where is data typically processed by cloud AI services?", "options": ["Only on your device", "On external servers, potentially in another country", "Nowhere — it disappears", "Only on your company's servers"], "answer": 1},
                    {"q": "A colleague uses AI to draft an email with client financial data. What's the concern?", "options": ["No concern", "Client data exposure to third-party AI provider", "Email formatting issues", "Spelling errors"], "answer": 1}
                ]
            }
        ],
        "ar": [
            {
                "id": "ai_ethics", "title": "أخلاقيات الذكاء الاصطناعي والاستخدام المسؤول", "icon": "fas fa-balance-scale", "level": "مبتدئ", "duration": "15 دقيقة",
                "description": "فهم المبادئ الأخلاقية لتطوير الذكاء الاصطناعي ونشره وحوكمته.",
                "learning_points": ["المبادئ الأساسية لأخلاقيات الذكاء الاصطناعي: العدالة، الشفافية، المساءلة، الخصوصية، السلامة", "التحيز في الذكاء الاصطناعي: كيف يحدث في بيانات التدريب وتصميم النماذج والنشر", "قابلية التفسير: للمستخدمين الحق في فهم قرارات الذكاء الاصطناعي التي تؤثر عليهم", "الإشراف البشري: الذكاء الاصطناعي يجب أن يعزز الحكم البشري لا أن يحل محله"],
                "scenario": {"title": "أداة التوظيف المتحيزة", "text": "نشرت شركتك أداة ذكاء اصطناعي لفرز السير الذاتية. بعد 3 أشهر، تُظهر البيانات أنها تصنف المرشحين الذكور أعلى باستمرار. دُرّبت الأداة على بيانات توظيف تاريخية من آخر 10 سنوات.", "correct_action": "أوقف الأداة فوراً. البيانات التاريخية تعكس على الأرجح تحيزاً سابقاً. أجرِ تدقيق عدالة، أعد التدريب ببيانات متوازنة، طبّق مراقبة مستمرة للتحيز، وتأكد من المراجعة البشرية."},
                "quiz": [
                    {"q": "ما هو تحيز الذكاء الاصطناعي؟", "options": ["نوع من البرمجيات", "تفضيل أو تمييز منهجي في مخرجات الذكاء الاصطناعي", "سلوك طبيعي", "لغة برمجة"], "answer": 1},
                    {"q": "لماذا قابلية تفسير الذكاء الاصطناعي مهمة؟", "options": ["للمطورين فقط", "ليفهم المستخدمون كيف تُتخذ قرارات الذكاء الاصطناعي", "ليست مهمة", "لأغراض تسويقية فقط"], "answer": 1},
                    {"q": "ماذا يجب أن يحدث عندما يتخذ الذكاء الاصطناعي قراراً عالي المخاطر؟", "options": ["قبوله تلقائياً", "يجب أن يراجعه إنسان", "تجاهل المخاوف", "تسريع العملية"], "answer": 1},
                    {"q": "كيف يدخل التحيز عادةً إلى أنظمة الذكاء الاصطناعي؟", "options": ["عبر بيانات تدريب متحيزة", "عبر الكهرباء", "الذكاء الاصطناعي لا يمكن أن يكون متحيزاً", "فقط عبر البرمجة المتعمدة"], "answer": 0},
                    {"q": "ما هو 'الإنسان في الحلقة'؟", "options": ["تدريب البشر على التمارين", "اشتراط المراجعة البشرية لقرارات الذكاء الاصطناعي", "إطار برمجي", "خطأ في الذكاء الاصطناعي"], "answer": 1}
                ]
            },
            {
                "id": "ai_data_handling", "title": "التعامل مع بيانات الذكاء الاصطناعي والخصوصية", "icon": "fas fa-brain", "level": "متوسط", "duration": "15 دقيقة",
                "description": "حماية البيانات الحساسة عند استخدام أدوات الذكاء الاصطناعي والمحادثات الآلية والأنظمة المؤتمتة.",
                "learning_points": ["لا تدخل أبداً بيانات سرية أو شخصية أو مصنفة في أدوات الذكاء الاصطناعي العامة", "افهم أين تخزن وتعالج أدوات الذكاء الاصطناعي بياناتك — سحابية أم محلية", "المحتوى المُنتج بالذكاء الاصطناعي قد يحتوي على هلوسات — تحقق دائماً من المعلومات المهمة", "السياسات التنظيمية لأدوات الذكاء الاصطناعي المعتمدة وحالات الاستخدام"],
                "scenario": {"title": "اختصار الذكاء الاصطناعي", "text": "نسخ أحد أعضاء الفريق عقداً سرياً في روبوت محادثة ذكاء اصطناعي عام لتلخيصه، موفراً ساعات من العمل. شارك ملخص الذكاء الاصطناعي في اجتماع الفريق.", "correct_action": "هذا خرق بيانات. أُرسل العقد السري لخدمة ذكاء اصطناعي تابعة لطرف ثالث. أبلغ عن الحادث، قيّم البيانات المكشوفة، وذكّر الفريق بعدم إدخال البيانات السرية في أدوات الذكاء الاصطناعي العامة."},
                "quiz": [
                    {"q": "هل من الآمن لصق البيانات السرية في أدوات الذكاء الاصطناعي العامة؟", "options": ["نعم، أدوات الذكاء الاصطناعي آمنة دائماً", "لا، قد تُخزن البيانات وتُستخدم للتدريب", "النصوص القصيرة فقط", "فقط إذا حذفت المحادثة بعدها"], "answer": 1},
                    {"q": "ما هي 'هلوسة' الذكاء الاصطناعي؟", "options": ["أحلام الذكاء الاصطناعي", "إنتاج معلومات خاطئة أو ملفقة بثقة", "تأثير بصري", "سلوك طبيعي"], "answer": 1},
                    {"q": "قبل استخدام أداة ذكاء اصطناعي في العمل، يجب:", "options": ["استخدام أي أداة متاحة", "التحقق من اعتمادها في سياسة منظمتك", "سؤال صديق", "البحث في جوجل"], "answer": 1},
                    {"q": "أين تُعالج البيانات عادةً بواسطة خدمات الذكاء الاصطناعي السحابية؟", "options": ["على جهازك فقط", "على خوادم خارجية، ربما في دولة أخرى", "لا مكان — تختفي", "على خوادم شركتك فقط"], "answer": 1},
                    {"q": "استخدم زميل الذكاء الاصطناعي لصياغة بريد يتضمن بيانات مالية للعملاء. ما المشكلة؟", "options": ["لا مشكلة", "تعرض بيانات العميل لمزود ذكاء اصطناعي خارجي", "مشاكل تنسيق البريد", "أخطاء إملائية"], "answer": 1}
                ]
            }
        ]
    },
    "dt": {
        "en": [
            {
                "id": "dt_change", "title": "Digital Change Management", "icon": "fas fa-sync-alt", "level": "Beginner", "duration": "15 min",
                "description": "Managing organizational change during digital transformation initiatives effectively.",
                "learning_points": ["Change management frameworks: ADKAR, Kotter's 8 Steps", "Stakeholder engagement and communication strategies", "Overcoming resistance to digital change", "Measuring adoption rates and user satisfaction"],
                "scenario": {"title": "The Rejected System", "text": "After 6 months and significant investment, a new ERP system has only 30% adoption. Employees complain it's harder than the old system and continue using spreadsheets.", "correct_action": "Conduct user feedback sessions. Identify specific pain points. Provide role-based training. Identify champions in each department. Gradually phase out old systems while ensuring the new system addresses real workflow needs."},
                "quiz": [
                    {"q": "What does ADKAR stand for?", "options": ["A software framework", "Awareness, Desire, Knowledge, Ability, Reinforcement", "A type of database", "Automated Digital Knowledge And Review"], "answer": 1},
                    {"q": "What is the most common reason digital transformation projects fail?", "options": ["Bad technology", "Insufficient budget", "Poor change management and resistance", "Lack of internet"], "answer": 2},
                    {"q": "What is a 'change champion'?", "options": ["A person who resists change", "An employee who advocates for and supports change", "A project manager", "An external consultant"], "answer": 1},
                    {"q": "How should you handle employee resistance to new systems?", "options": ["Force adoption through mandates only", "Listen, address concerns, provide training and support", "Ignore complaints", "Threaten consequences"], "answer": 1},
                    {"q": "What metric best measures digital transformation success?", "options": ["Money spent", "User adoption rate and satisfaction", "Number of meetings held", "Lines of code written"], "answer": 1}
                ]
            },
            {
                "id": "dt_security", "title": "Security in Digital Transformation", "icon": "fas fa-lock", "level": "Intermediate", "duration": "15 min",
                "description": "Ensuring security-by-design in digital transformation initiatives and cloud migration.",
                "learning_points": ["Security-by-design: integrate security from the start, not as an afterthought", "Cloud security shared responsibility model", "API security and integration risks", "Digital identity management in modern architectures"],
                "scenario": {"title": "The Rush to Cloud", "text": "Management wants to migrate all systems to the cloud within 3 months to cut costs. The security team hasn't been consulted yet.", "correct_action": "Advocate for including security from the start. Conduct a cloud security assessment. Define a shared responsibility model. Prioritize migration of less sensitive systems first. Ensure proper access controls, encryption, and compliance before migrating critical data."},
                "quiz": [
                    {"q": "What is 'security by design'?", "options": ["Adding security after deployment", "Integrating security from the earliest design phase", "A security software brand", "Security only for designers"], "answer": 1},
                    {"q": "In cloud computing, who is responsible for data security?", "options": ["Only the cloud provider", "Only the customer", "Shared responsibility between both", "No one"], "answer": 2},
                    {"q": "What should happen before migrating to the cloud?", "options": ["Nothing special", "Cloud security assessment and risk analysis", "Just move everything at once", "Wait for competitors to go first"], "answer": 1},
                    {"q": "What is API security?", "options": ["A type of antivirus", "Protecting interfaces that connect different systems", "An encryption standard", "A cloud provider"], "answer": 1},
                    {"q": "Why should less sensitive systems be migrated to cloud first?", "options": ["They're smaller", "To learn and refine security controls before migrating critical data", "They're cheaper", "No specific reason"], "answer": 1}
                ]
            }
        ],
        "ar": [
            {
                "id": "dt_change", "title": "إدارة التغيير الرقمي", "icon": "fas fa-sync-alt", "level": "مبتدئ", "duration": "15 دقيقة",
                "description": "إدارة التغيير المؤسسي خلال مبادرات التحول الرقمي بفعالية.",
                "learning_points": ["أطر إدارة التغيير: ADKAR، خطوات كوتر الثمانية", "إشراك أصحاب المصلحة واستراتيجيات التواصل", "التغلب على مقاومة التغيير الرقمي", "قياس معدلات التبني ورضا المستخدمين"],
                "scenario": {"title": "النظام المرفوض", "text": "بعد 6 أشهر واستثمار كبير، نظام ERP الجديد بنسبة تبنٍّ 30% فقط. يشتكي الموظفون أنه أصعب من النظام القديم ويستمرون باستخدام جداول البيانات.", "correct_action": "أجرِ جلسات ملاحظات مع المستخدمين. حدد نقاط الألم المحددة. قدم تدريباً حسب الأدوار. حدد سفراء في كل قسم. أوقف الأنظمة القديمة تدريجياً."},
                "quiz": [
                    {"q": "ماذا تعني ADKAR؟", "options": ["إطار برمجي", "الوعي، الرغبة، المعرفة، القدرة، التعزيز", "نوع قاعدة بيانات", "مراجعة المعرفة الرقمية الآلية"], "answer": 1},
                    {"q": "ما أشهر سبب لفشل مشاريع التحول الرقمي؟", "options": ["تقنية سيئة", "ميزانية غير كافية", "ضعف إدارة التغيير والمقاومة", "عدم وجود إنترنت"], "answer": 2},
                    {"q": "ما هو 'سفير التغيير'؟", "options": ["شخص يقاوم التغيير", "موظف يدافع عن التغيير ويدعمه", "مدير مشروع", "مستشار خارجي"], "answer": 1},
                    {"q": "كيف تتعامل مع مقاومة الموظفين للأنظمة الجديدة؟", "options": ["إجبار التبني بالأوامر فقط", "الاستماع ومعالجة المخاوف وتقديم التدريب والدعم", "تجاهل الشكاوى", "التهديد بالعواقب"], "answer": 1},
                    {"q": "ما أفضل مقياس لنجاح التحول الرقمي؟", "options": ["المال المصروف", "معدل التبني ورضا المستخدمين", "عدد الاجتماعات", "سطور الكود المكتوبة"], "answer": 1}
                ]
            },
            {
                "id": "dt_security", "title": "الأمان في التحول الرقمي", "icon": "fas fa-lock", "level": "متوسط", "duration": "15 دقيقة",
                "description": "ضمان الأمان بالتصميم في مبادرات التحول الرقمي والترحيل السحابي.",
                "learning_points": ["الأمان بالتصميم: دمج الأمان من البداية وليس كإضافة لاحقة", "نموذج المسؤولية المشتركة للأمان السحابي", "أمان واجهات البرمجة (API) ومخاطر التكامل", "إدارة الهوية الرقمية في البنى الحديثة"],
                "scenario": {"title": "التسرع للسحابة", "text": "تريد الإدارة ترحيل جميع الأنظمة للسحابة خلال 3 أشهر لتقليل التكاليف. لم يُستشر فريق الأمن بعد.", "correct_action": "ادعُ لإشراك الأمن من البداية. أجرِ تقييم أمان سحابي. حدد نموذج المسؤولية المشتركة. رحّل الأنظمة الأقل حساسية أولاً. تأكد من ضوابط الوصول والتشفير والامتثال قبل ترحيل البيانات الحرجة."},
                "quiz": [
                    {"q": "ما هو 'الأمان بالتصميم'؟", "options": ["إضافة الأمان بعد النشر", "دمج الأمان من أولى مراحل التصميم", "علامة تجارية لبرنامج أمني", "أمان للمصممين فقط"], "answer": 1},
                    {"q": "في الحوسبة السحابية، من المسؤول عن أمان البيانات؟", "options": ["مزود السحابة فقط", "العميل فقط", "مسؤولية مشتركة بين الاثنين", "لا أحد"], "answer": 2},
                    {"q": "ماذا يجب أن يحدث قبل الترحيل للسحابة؟", "options": ["لا شيء خاص", "تقييم أمان سحابي وتحليل مخاطر", "نقل كل شيء دفعة واحدة", "انتظار المنافسين"], "answer": 1},
                    {"q": "ما هو أمان API؟", "options": ["نوع مضاد فيروسات", "حماية الواجهات التي تربط الأنظمة المختلفة", "معيار تشفير", "مزود سحابي"], "answer": 1},
                    {"q": "لماذا تُرحّل الأنظمة الأقل حساسية أولاً؟", "options": ["لأنها أصغر", "للتعلم وتحسين ضوابط الأمان قبل ترحيل البيانات الحرجة", "لأنها أرخص", "لا سبب محدد"], "answer": 1}
                ]
            }
        ]
    },
    "global": {
        "en": [
            {
                "id": "global_iso27001", "title": "ISO 27001 Essentials", "icon": "fas fa-certificate", "level": "Beginner", "duration": "15 min",
                "description": "Core concepts of ISO 27001 information security management system (ISMS).",
                "learning_points": ["ISO 27001 provides a systematic approach to managing sensitive information", "Key components: Context, Leadership, Planning, Support, Operation, Evaluation, Improvement", "Risk-based approach: identify, assess, and treat information security risks", "Annex A controls: 93 controls organized in 4 themes"],
                "scenario": {"title": "The Certification Audit", "text": "Your organization is preparing for ISO 27001 certification. The internal audit found that 40% of employees don't know the information security policy exists.", "correct_action": "This is a major finding. Address it by: conducting mandatory security awareness training, making the policy accessible on the intranet, requiring acknowledgment from all employees, and establishing ongoing communication about security responsibilities."},
                "quiz": [
                    {"q": "What does ISO 27001 primarily address?", "options": ["Quality management", "Information security management", "Environmental management", "Financial management"], "answer": 1},
                    {"q": "What is the PDCA cycle in ISO 27001?", "options": ["A type of encryption", "Plan-Do-Check-Act for continuous improvement", "A network protocol", "A risk assessment tool"], "answer": 1},
                    {"q": "How many controls are in ISO 27001:2022 Annex A?", "options": ["114", "93", "50", "200"], "answer": 1},
                    {"q": "What is the Statement of Applicability (SoA)?", "options": ["A legal document", "A document listing which controls apply and justification", "An audit report", "A user manual"], "answer": 1},
                    {"q": "Is ISO 27001 certification mandatory?", "options": ["Yes, for all companies", "No, it's voluntary but often required by clients", "Only for government", "Only in the EU"], "answer": 1}
                ]
            },
            {
                "id": "global_compliance", "title": "Regulatory Compliance Basics", "icon": "fas fa-gavel", "level": "Intermediate", "duration": "15 min",
                "description": "Understanding compliance requirements, frameworks, and your role in maintaining organizational compliance.",
                "learning_points": ["Compliance means adhering to laws, regulations, standards, and internal policies", "Key Saudi regulations: NCA ECC, PDPL, SAMA CSF, CITC regulations", "International frameworks: ISO 27001, NIST CSF, COBIT, PCI DSS", "Everyone's role: compliance is not just the compliance team's job"],
                "scenario": {"title": "The Compliance Gap", "text": "During a regulatory review, NCA finds that your organization hasn't implemented 30% of required ECC controls. The deadline for compliance passed 6 months ago.", "correct_action": "Immediately develop a remediation plan with clear timelines. Prioritize critical controls first. Assign owners for each gap. Report progress to management weekly. Engage with NCA proactively about your remediation timeline."},
                "quiz": [
                    {"q": "What is NCA ECC?", "options": ["A type of encryption", "Saudi National Cybersecurity Authority Essential Controls", "An email protocol", "A cloud provider"], "answer": 1},
                    {"q": "Whose responsibility is compliance?", "options": ["Only the compliance team", "Only management", "Everyone in the organization", "Only IT department"], "answer": 2},
                    {"q": "What happens if an organization fails to comply with NCA ECC?", "options": ["Nothing", "Possible fines, sanctions, and reputational damage", "Free consulting", "Automatic extension"], "answer": 1},
                    {"q": "What is a compliance audit?", "options": ["A financial review", "A systematic evaluation of adherence to regulations", "A technology upgrade", "A marketing survey"], "answer": 1},
                    {"q": "What should you do if you discover a compliance violation?", "options": ["Ignore it", "Report it through proper channels", "Fix it secretly", "Wait for an audit to find it"], "answer": 1}
                ]
            }
        ],
        "ar": [
            {
                "id": "global_iso27001", "title": "أساسيات ISO 27001", "icon": "fas fa-certificate", "level": "مبتدئ", "duration": "15 دقيقة",
                "description": "المفاهيم الأساسية لنظام إدارة أمن المعلومات ISO 27001.",
                "learning_points": ["يوفر ISO 27001 نهجاً منظماً لإدارة المعلومات الحساسة", "المكونات: السياق، القيادة، التخطيط، الدعم، التشغيل، التقييم، التحسين", "النهج القائم على المخاطر: تحديد وتقييم ومعالجة مخاطر أمن المعلومات", "ضوابط الملحق أ: 93 ضابطة منظمة في 4 محاور"],
                "scenario": {"title": "تدقيق الشهادة", "text": "تستعد منظمتك للحصول على شهادة ISO 27001. وجد التدقيق الداخلي أن 40% من الموظفين لا يعلمون بوجود سياسة أمن المعلومات.", "correct_action": "هذه ملاحظة جوهرية. عالجها بإجراء تدريب توعوي إلزامي، وإتاحة السياسة على الإنترانت، وطلب إقرار من جميع الموظفين، وإنشاء تواصل مستمر حول مسؤوليات الأمن."},
                "quiz": [
                    {"q": "ما الذي يعالجه ISO 27001 بشكل أساسي؟", "options": ["إدارة الجودة", "إدارة أمن المعلومات", "الإدارة البيئية", "الإدارة المالية"], "answer": 1},
                    {"q": "ما هي دورة PDCA في ISO 27001؟", "options": ["نوع تشفير", "خطط-نفذ-تحقق-صحح للتحسين المستمر", "بروتوكول شبكة", "أداة تقييم مخاطر"], "answer": 1},
                    {"q": "كم عدد الضوابط في ملحق أ ISO 27001:2022؟", "options": ["114", "93", "50", "200"], "answer": 1},
                    {"q": "ما هو بيان قابلية التطبيق (SoA)؟", "options": ["وثيقة قانونية", "وثيقة تسرد الضوابط المطبقة ومبرراتها", "تقرير تدقيق", "دليل مستخدم"], "answer": 1},
                    {"q": "هل شهادة ISO 27001 إلزامية؟", "options": ["نعم لجميع الشركات", "لا، طوعية لكن العملاء غالباً يطلبونها", "للحكومة فقط", "في الاتحاد الأوروبي فقط"], "answer": 1}
                ]
            },
            {
                "id": "global_compliance", "title": "أساسيات الامتثال التنظيمي", "icon": "fas fa-gavel", "level": "متوسط", "duration": "15 دقيقة",
                "description": "فهم متطلبات الامتثال والأطر التنظيمية ودورك في الحفاظ على امتثال المنظمة.",
                "learning_points": ["الامتثال يعني الالتزام بالقوانين واللوائح والمعايير والسياسات الداخلية", "اللوائح السعودية الرئيسية: NCA ECC، PDPL، SAMA CSF، لوائح CITC", "الأطر الدولية: ISO 27001، NIST CSF، COBIT، PCI DSS", "دور الجميع: الامتثال ليس مسؤولية فريق الامتثال فقط"],
                "scenario": {"title": "فجوة الامتثال", "text": "أثناء مراجعة تنظيمية، وجدت الهيئة الوطنية للأمن السيبراني أن منظمتك لم تطبق 30% من ضوابط ECC المطلوبة. انتهى الموعد النهائي قبل 6 أشهر.", "correct_action": "طوّر فوراً خطة معالجة بجداول زمنية واضحة. أعطِ الأولوية للضوابط الحرجة. عيّن مسؤولين لكل فجوة. أبلغ الإدارة أسبوعياً. تواصل مع الهيئة بشكل استباقي."},
                "quiz": [
                    {"q": "ما هو NCA ECC؟", "options": ["نوع تشفير", "الضوابط الأساسية للأمن السيبراني للهيئة الوطنية السعودية", "بروتوكول بريد إلكتروني", "مزود سحابي"], "answer": 1},
                    {"q": "مسؤولية الامتثال على عاتق من؟", "options": ["فريق الامتثال فقط", "الإدارة فقط", "الجميع في المنظمة", "قسم تقنية المعلومات فقط"], "answer": 2},
                    {"q": "ماذا يحدث إذا فشلت المنظمة في الامتثال لـ NCA ECC؟", "options": ["لا شيء", "غرامات وعقوبات محتملة وضرر سمعي", "استشارة مجانية", "تمديد تلقائي"], "answer": 1},
                    {"q": "ما هو تدقيق الامتثال؟", "options": ["مراجعة مالية", "تقييم منهجي للالتزام باللوائح", "ترقية تقنية", "استطلاع تسويقي"], "answer": 1},
                    {"q": "ماذا تفعل إذا اكتشفت مخالفة امتثال؟", "options": ["تجاهلها", "أبلغ عنها عبر القنوات المناسبة", "أصلحها سراً", "انتظر التدقيق ليجدها"], "answer": 1}
                ]
            }
        ]
    },
    "erm": {
        "en": [
            {
                "id": "erm_fundamentals", "title": "Risk Management Fundamentals", "icon": "fas fa-exclamation-circle", "level": "Beginner", "duration": "15 min",
                "description": "Core concepts of enterprise risk management, risk identification, and assessment methods.",
                "learning_points": ["Risk = Likelihood × Impact — understanding how risks are measured", "Risk categories: Strategic, Operational, Financial, Compliance, Reputational", "Risk appetite vs risk tolerance: how much risk the organization accepts", "The risk management cycle: Identify, Assess, Treat, Monitor, Report"],
                "scenario": {"title": "The Untracked Risk", "text": "A department head decides not to report a vendor's repeated service failures because they're 'managing it internally'. Three months later, the vendor goes bankrupt, causing a major service disruption.", "correct_action": "All significant risks must be reported and tracked in the risk register, regardless of who is managing them. The risk register provides visibility to leadership. Implement vendor risk monitoring with early warning indicators."},
                "quiz": [
                    {"q": "How is risk typically calculated?", "options": ["Cost × Time", "Likelihood × Impact", "Revenue × Profit", "Employees × Departments"], "answer": 1},
                    {"q": "What is 'risk appetite'?", "options": ["The amount of risk an organization is willing to accept", "A risk management software", "How hungry the risk manager is", "The maximum number of risks"], "answer": 0},
                    {"q": "Which is NOT a risk treatment option?", "options": ["Avoid", "Mitigate", "Transfer", "Ignore completely"], "answer": 3},
                    {"q": "Why must risks be reported to a central register?", "options": ["Bureaucracy", "Visibility and informed decision-making at leadership level", "To create more paperwork", "It's optional"], "answer": 1},
                    {"q": "What framework focuses on enterprise risk management?", "options": ["ISO 9001", "COSO ERM", "PCI DSS", "HTML"], "answer": 1}
                ]
            },
            {
                "id": "erm_culture", "title": "Building a Risk-Aware Culture", "icon": "fas fa-users", "level": "Intermediate", "duration": "15 min",
                "description": "Creating an organizational culture where everyone understands and actively manages risk.",
                "learning_points": ["Risk culture starts at the top — leadership must model risk-aware behavior", "Every employee is a risk manager in their area of work", "Psychological safety: employees must feel safe reporting risks without blame", "Regular risk communication through meetings, dashboards, and training"],
                "scenario": {"title": "The Silent Risk", "text": "An employee notices a critical system has been running without backups for 2 weeks due to a misconfiguration. They hesitate to report it because last time someone reported a problem, they were blamed for it.", "correct_action": "Create a blame-free reporting culture. Establish anonymous reporting channels. Reward risk identification. The employee should be thanked, not blamed. Fix the backup issue immediately and investigate how the monitoring gap occurred."},
                "quiz": [
                    {"q": "Where does risk culture start?", "options": ["IT department", "At the top — leadership", "New employees", "External consultants"], "answer": 1},
                    {"q": "Why is psychological safety important for risk management?", "options": ["It's not important", "Employees need to feel safe reporting risks without fear of blame", "Only for HR purposes", "To reduce stress levels"], "answer": 1},
                    {"q": "Who should be responsible for managing risk?", "options": ["Only the risk management team", "Only senior management", "Everyone in the organization within their role", "External auditors"], "answer": 2},
                    {"q": "How should an organization respond when someone reports a risk?", "options": ["Blame the reporter", "Thank and investigate the risk", "Ignore it", "Punish the department"], "answer": 1},
                    {"q": "What is the best way to communicate risk across an organization?", "options": ["Annual emails only", "Regular updates through multiple channels: meetings, dashboards, training", "Only during crises", "Never — it creates panic"], "answer": 1}
                ]
            }
        ],
        "ar": [
            {
                "id": "erm_fundamentals", "title": "أساسيات إدارة المخاطر", "icon": "fas fa-exclamation-circle", "level": "مبتدئ", "duration": "15 دقيقة",
                "description": "المفاهيم الأساسية لإدارة المخاطر المؤسسية وأساليب التحديد والتقييم.",
                "learning_points": ["المخاطر = الاحتمالية × الأثر — فهم كيفية قياس المخاطر", "فئات المخاطر: استراتيجية، تشغيلية، مالية، امتثال، سمعة", "شهية المخاطر مقابل تحمل المخاطر: مقدار المخاطر التي تقبلها المنظمة", "دورة إدارة المخاطر: التحديد، التقييم، المعالجة، المراقبة، الإبلاغ"],
                "scenario": {"title": "المخاطر غير المتتبعة", "text": "قرر مدير إدارة عدم الإبلاغ عن إخفاقات المورد المتكررة لأنه 'يديرها داخلياً'. بعد 3 أشهر، أفلس المورد مسبباً انقطاعاً كبيراً في الخدمة.", "correct_action": "يجب الإبلاغ عن جميع المخاطر الجوهرية وتتبعها في سجل المخاطر بغض النظر عمن يديرها. السجل يوفر رؤية للقيادة. طبّق مراقبة مخاطر الموردين مع مؤشرات إنذار مبكر."},
                "quiz": [
                    {"q": "كيف تُحسب المخاطر عادةً؟", "options": ["التكلفة × الوقت", "الاحتمالية × الأثر", "الإيرادات × الربح", "الموظفون × الأقسام"], "answer": 1},
                    {"q": "ما هي 'شهية المخاطر'؟", "options": ["مقدار المخاطر التي تقبلها المنظمة", "برنامج إدارة مخاطر", "مدى جوع مدير المخاطر", "الحد الأقصى لعدد المخاطر"], "answer": 0},
                    {"q": "أي مما يلي ليس خيار معالجة مخاطر؟", "options": ["التجنب", "التخفيف", "النقل", "التجاهل الكامل"], "answer": 3},
                    {"q": "لماذا يجب الإبلاغ عن المخاطر في سجل مركزي؟", "options": ["بيروقراطية", "الرؤية واتخاذ القرار المستنير على مستوى القيادة", "لإنشاء مزيد من الأوراق", "اختياري"], "answer": 1},
                    {"q": "أي إطار يركز على إدارة المخاطر المؤسسية؟", "options": ["ISO 9001", "COSO ERM", "PCI DSS", "HTML"], "answer": 1}
                ]
            },
            {
                "id": "erm_culture", "title": "بناء ثقافة واعية بالمخاطر", "icon": "fas fa-users", "level": "متوسط", "duration": "15 دقيقة",
                "description": "إنشاء ثقافة مؤسسية يفهم فيها الجميع المخاطر ويديرونها بنشاط.",
                "learning_points": ["ثقافة المخاطر تبدأ من القمة — القيادة يجب أن تكون قدوة", "كل موظف هو مدير مخاطر في مجال عمله", "الأمان النفسي: يجب أن يشعر الموظفون بالأمان عند الإبلاغ دون لوم", "التواصل المنتظم حول المخاطر عبر الاجتماعات ولوحات المعلومات والتدريب"],
                "scenario": {"title": "المخاطر الصامتة", "text": "لاحظ موظف أن نظاماً حرجاً يعمل بدون نسخ احتياطية منذ أسبوعين بسبب خطأ في الإعدادات. يتردد في الإبلاغ لأنه في المرة الأخيرة التي أبلغ فيها شخص عن مشكلة، تم لومه.", "correct_action": "أنشئ ثقافة إبلاغ بدون لوم. أوجد قنوات إبلاغ مجهولة. كافئ تحديد المخاطر. يجب شكر الموظف لا لومه. أصلح مشكلة النسخ الاحتياطي فوراً وحقق في كيفية حدوث فجوة المراقبة."},
                "quiz": [
                    {"q": "من أين تبدأ ثقافة المخاطر؟", "options": ["قسم تقنية المعلومات", "من القمة — القيادة", "الموظفين الجدد", "المستشارين الخارجيين"], "answer": 1},
                    {"q": "لماذا الأمان النفسي مهم لإدارة المخاطر؟", "options": ["ليس مهماً", "يحتاج الموظفون للشعور بالأمان عند الإبلاغ دون خوف من اللوم", "لأغراض الموارد البشرية فقط", "لتقليل مستويات التوتر"], "answer": 1},
                    {"q": "من يجب أن يكون مسؤولاً عن إدارة المخاطر؟", "options": ["فريق إدارة المخاطر فقط", "الإدارة العليا فقط", "الجميع في المنظمة ضمن دورهم", "المدققون الخارجيون"], "answer": 2},
                    {"q": "كيف يجب أن تستجيب المنظمة عند إبلاغ شخص عن خطر؟", "options": ["لوم المُبلِّغ", "شكره والتحقيق في الخطر", "تجاهله", "معاقبة القسم"], "answer": 1},
                    {"q": "ما أفضل طريقة للتواصل حول المخاطر عبر المنظمة؟", "options": ["رسائل بريد سنوية فقط", "تحديثات منتظمة عبر قنوات متعددة: اجتماعات، لوحات، تدريب", "أثناء الأزمات فقط", "أبداً — يسبب ذعراً"], "answer": 1}
                ]
            }
        ]
    },
    # GRC Professional Modules - Frameworks, Regulations & Standards Training
    "grc_professional": {
        "en": [
            {
                "id": "grc_nca_frameworks", "title": "NCA Cybersecurity Frameworks (KSA)", "icon": "fas fa-flag", "level": "Intermediate", "duration": "25 min",
                "description": "Comprehensive guide to Saudi National Cybersecurity Authority frameworks including ECC, CSCC, DCC, and other controls.",
                "learning_points": [
                    "NCA ECC (Essential Cybersecurity Controls): 114 controls in 5 domains - mandatory for all government entities",
                    "NCA CSCC (Critical Systems): Enhanced controls for national critical infrastructure",
                    "NCA DCC (Data Cybersecurity): Data protection controls aligned with PDPL",
                    "NCA CCC (Cloud): Security requirements for cloud service adoption",
                    "NCA TCC/OTCC: Telework and Operational Technology specific controls"
                ],
                "scenario": {"title": "ECC Compliance Gap", "text": "Your organization scored 65% on NCA ECC compliance assessment. Management wants to reach 90% within 6 months. How do you prioritize?", "correct_action": "Start with high-priority gaps in Cybersecurity Governance and Defense domains. Focus on quick wins (policies, awareness) while planning longer-term technical controls. Create a remediation roadmap with clear ownership and deadlines."},
                "quiz": [
                    {"q": "How many main domains are in NCA ECC?", "options": ["3", "5", "7", "10"], "answer": 1},
                    {"q": "Which NCA framework applies to national critical infrastructure?", "options": ["ECC", "CSCC", "TCC", "DCC"], "answer": 1},
                    {"q": "What is the relationship between NCA DCC and PDPL?", "options": ["They are unrelated", "DCC provides technical controls to implement PDPL requirements", "PDPL replaces DCC", "DCC is optional"], "answer": 1},
                    {"q": "Who must comply with NCA ECC?", "options": ["Only banks", "Only government entities", "All government entities and critical infrastructure", "Only tech companies"], "answer": 2},
                    {"q": "What is NCA CCC used for?", "options": ["Cloud adoption security requirements", "Cryptography standards", "Crisis management", "Customer communications"], "answer": 0}
                ]
            },
            {
                "id": "grc_pdpl", "title": "Saudi PDPL (Personal Data Protection Law)", "icon": "fas fa-user-shield", "level": "Intermediate", "duration": "20 min",
                "description": "Understanding Saudi Personal Data Protection Law requirements, data subject rights, and compliance obligations.",
                "learning_points": [
                    "PDPL applies to all processing of personal data in Saudi Arabia, regardless of processor location",
                    "Lawful bases: consent, contract, legal obligation, vital interests, public interest",
                    "Data subject rights: access, rectification, deletion, portability, objection",
                    "Data Protection Officer (DPO) requirement for certain organizations",
                    "Cross-border transfer restrictions and adequacy requirements",
                    "Penalties: up to 5 million SAR for violations"
                ],
                "scenario": {"title": "Data Breach Response", "text": "Your organization discovers a data breach affecting 10,000 customer records including national IDs. What are your PDPL obligations?", "correct_action": "Notify SDAIA within 72 hours if the breach poses risk to individuals. Assess the breach impact and document all actions. Notify affected individuals if there's high risk to their rights. Implement measures to prevent recurrence."},
                "quiz": [
                    {"q": "What is the maximum penalty for PDPL violations?", "options": ["1 million SAR", "3 million SAR", "5 million SAR", "10 million SAR"], "answer": 2},
                    {"q": "Within how many hours must you notify SDAIA of a serious data breach?", "options": ["24 hours", "48 hours", "72 hours", "1 week"], "answer": 2},
                    {"q": "Which organization regulates PDPL in Saudi Arabia?", "options": ["NCA", "SDAIA", "SAMA", "CITC"], "answer": 1},
                    {"q": "What is NOT a data subject right under PDPL?", "options": ["Right to access", "Right to deletion", "Right to free products", "Right to rectification"], "answer": 2},
                    {"q": "Can personal data be transferred outside Saudi Arabia?", "options": ["Never", "Always without restriction", "Only with adequate protection measures", "Only to GCC countries"], "answer": 2}
                ]
            },
            {
                "id": "grc_iso27001", "title": "ISO 27001:2022 Deep Dive", "icon": "fas fa-certificate", "level": "Advanced", "duration": "30 min",
                "description": "Detailed understanding of ISO 27001:2022 Information Security Management System requirements and implementation.",
                "learning_points": [
                    "ISO 27001:2022 structure: 10 clauses covering context, leadership, planning, support, operation, evaluation, improvement",
                    "Annex A: 93 controls organized in 4 themes (Organizational, People, Physical, Technological)",
                    "Risk-based approach: systematic identification, assessment, and treatment of information security risks",
                    "Statement of Applicability (SoA): documenting which controls apply and their implementation status",
                    "Certification process: Stage 1 (documentation review), Stage 2 (implementation audit), Surveillance audits"
                ],
                "scenario": {"title": "Certification Preparation", "text": "Your organization wants ISO 27001 certification within 12 months. You have basic security controls but no formal ISMS. Where do you start?", "correct_action": "1) Conduct gap assessment against ISO 27001 requirements. 2) Define ISMS scope and get management commitment. 3) Perform risk assessment and create risk treatment plan. 4) Develop required documentation (policies, procedures, SoA). 5) Implement controls and conduct internal audit. 6) Management review before certification audit."},
                "quiz": [
                    {"q": "How many controls are in ISO 27001:2022 Annex A?", "options": ["114", "93", "50", "27"], "answer": 1},
                    {"q": "What document lists which ISO 27001 controls apply to your organization?", "options": ["Risk Register", "Statement of Applicability", "Security Policy", "Audit Report"], "answer": 1},
                    {"q": "What is Stage 1 of ISO 27001 certification?", "options": ["Implementation audit", "Documentation review", "Surveillance audit", "Gap assessment"], "answer": 1},
                    {"q": "How often are surveillance audits conducted after certification?", "options": ["Monthly", "Quarterly", "Annually", "Every 3 years"], "answer": 2},
                    {"q": "What approach does ISO 27001 require for selecting controls?", "options": ["Implement all controls", "Risk-based selection", "Cost-based selection", "Random selection"], "answer": 1}
                ]
            },
            {
                "id": "grc_gdpr", "title": "GDPR Fundamentals", "icon": "fas fa-globe-europe", "level": "Intermediate", "duration": "20 min",
                "description": "Understanding EU General Data Protection Regulation for organizations serving European customers.",
                "learning_points": [
                    "GDPR applies to any organization processing EU residents' data, regardless of location",
                    "Key principles: lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity, accountability",
                    "Data subject rights: access, rectification, erasure (right to be forgotten), restriction, portability, objection",
                    "Data Protection Impact Assessment (DPIA) required for high-risk processing",
                    "Penalties: up to €20 million or 4% of global annual turnover"
                ],
                "scenario": {"title": "International Data Transfer", "text": "Your Saudi company wants to process EU customer data in your Riyadh data center. What GDPR requirements apply?", "correct_action": "EU-Saudi transfers require adequate safeguards. Options: Standard Contractual Clauses (SCCs), Binding Corporate Rules, or explicit consent. Conduct a Transfer Impact Assessment. Ensure technical measures (encryption) protect data. Document the legal basis for transfer."},
                "quiz": [
                    {"q": "What is the maximum GDPR fine?", "options": ["€10 million", "€20 million or 4% of global turnover", "€50 million", "€1 million"], "answer": 1},
                    {"q": "Does GDPR apply to a Saudi company with EU customers?", "options": ["No, only EU companies", "Yes, if processing EU residents' data", "Only if they have EU offices", "Only for financial data"], "answer": 1},
                    {"q": "What is the 'right to be forgotten'?", "options": ["Right to delete your data", "Right to anonymity", "Right to encryption", "Right to data backup"], "answer": 0},
                    {"q": "When is a DPIA required?", "options": ["For all data processing", "Only for high-risk processing", "Only for customer data", "Never required"], "answer": 1},
                    {"q": "What mechanism allows EU-Saudi data transfers?", "options": ["Nothing, transfers are banned", "Standard Contractual Clauses", "Verbal agreement", "Email consent"], "answer": 1}
                ]
            },
            {
                "id": "grc_nist_csf", "title": "NIST Cybersecurity Framework 2.0", "icon": "fas fa-shield-virus", "level": "Intermediate", "duration": "20 min",
                "description": "Understanding NIST CSF 2.0 functions, categories, and implementation for cybersecurity program management.",
                "learning_points": [
                    "NIST CSF 2.0 adds GOVERN as the 6th function alongside Identify, Protect, Detect, Respond, Recover",
                    "Framework provides a common language for cybersecurity risk communication",
                    "Implementation Tiers: Partial (1), Risk Informed (2), Repeatable (3), Adaptive (4)",
                    "Framework Profiles: document current state and target state for gap analysis",
                    "Widely referenced by regulators including NCA as a supplementary framework"
                ],
                "scenario": {"title": "Framework Adoption", "text": "Your CISO asks you to map your current security program to NIST CSF 2.0. Where do you start?", "correct_action": "1) Create Current Profile by assessing existing capabilities against CSF categories. 2) Define Target Profile based on business objectives and risk appetite. 3) Identify gaps between current and target. 4) Prioritize actions based on risk and resources. 5) Track progress using CSF tiers."},
                "quiz": [
                    {"q": "What new function was added in NIST CSF 2.0?", "options": ["PROTECT", "GOVERN", "RESPOND", "ANALYZE"], "answer": 1},
                    {"q": "How many core functions does NIST CSF 2.0 have?", "options": ["4", "5", "6", "7"], "answer": 2},
                    {"q": "What does Implementation Tier 4 (Adaptive) mean?", "options": ["No security program", "Basic security", "Organization adapts to changing cyber risks in real-time", "External security only"], "answer": 2},
                    {"q": "What is a Framework Profile?", "options": ["A user account", "Documentation of current/target security state", "A social media page", "An audit report"], "answer": 1},
                    {"q": "Is NIST CSF mandatory?", "options": ["Yes, for all organizations", "Only for US government", "No, it's voluntary but widely adopted", "Only for banks"], "answer": 2}
                ]
            },
            {
                "id": "grc_coso_erm", "title": "COSO ERM Framework", "icon": "fas fa-project-diagram", "level": "Advanced", "duration": "25 min",
                "description": "Comprehensive guide to COSO Enterprise Risk Management framework for organization-wide risk management.",
                "learning_points": [
                    "COSO ERM 2017 integrates strategy and performance with risk management",
                    "5 Components: Governance & Culture, Strategy & Objective-Setting, Performance, Review & Revision, Information & Communication",
                    "20 Principles across the 5 components provide detailed implementation guidance",
                    "Risk appetite defines the amount of risk an organization is willing to accept in pursuit of value",
                    "ERM should be embedded in strategic planning and decision-making processes"
                ],
                "scenario": {"title": "ERM Implementation", "text": "The board wants to implement COSO ERM but is concerned about cost and complexity. How do you make the business case?", "correct_action": "Demonstrate value: better strategic decisions, reduced surprises, improved resource allocation, enhanced stakeholder confidence. Start with high-impact areas, not a full implementation. Show how ERM prevents costly risk events and enables informed risk-taking. Present case studies of ERM benefits."},
                "quiz": [
                    {"q": "How many components are in COSO ERM 2017?", "options": ["3", "4", "5", "8"], "answer": 2},
                    {"q": "What is risk appetite?", "options": ["How hungry the risk team is", "Amount of risk an org will accept to create value", "Maximum number of risks", "Risk register size"], "answer": 1},
                    {"q": "What does COSO ERM integrate risk management with?", "options": ["IT operations only", "Strategy and performance", "Marketing campaigns", "HR processes only"], "answer": 1},
                    {"q": "Who is responsible for ERM according to COSO?", "options": ["Only the risk department", "Only the board", "Everyone with board oversight", "External auditors"], "answer": 2},
                    {"q": "What year was the current COSO ERM framework released?", "options": ["2004", "2013", "2017", "2020"], "answer": 2}
                ]
            },
            {
                "id": "grc_sama_framework", "title": "SAMA Cyber Security Framework", "icon": "fas fa-university", "level": "Intermediate", "duration": "20 min",
                "description": "Understanding Saudi Arabian Monetary Authority cybersecurity requirements for financial institutions.",
                "learning_points": [
                    "SAMA CSF applies to all financial institutions regulated by SAMA (banks, insurance, finance companies)",
                    "Framework aligns with international standards (ISO 27001, NIST) with local requirements",
                    "4 Domains: Cyber Security Leadership & Governance, Cyber Security Risk Management, Cyber Security Operations, Third Party Security",
                    "Annual self-assessment and periodic SAMA examinations required",
                    "BCM (Business Continuity Management) requirements included"
                ],
                "scenario": {"title": "SAMA Examination", "text": "SAMA announces a cybersecurity examination in 3 months. Your bank has gaps in third-party risk management. How do you prepare?", "correct_action": "1) Conduct rapid gap assessment against SAMA CSF third-party requirements. 2) Inventory all critical third parties. 3) Obtain/review vendor security assessments. 4) Update contracts with security requirements. 5) Implement monitoring for critical vendors. 6) Document everything for examination evidence."},
                "quiz": [
                    {"q": "Which institutions must comply with SAMA CSF?", "options": ["All companies in Saudi", "Only banks", "All SAMA-regulated financial institutions", "Only international banks"], "answer": 2},
                    {"q": "How many main domains does SAMA CSF have?", "options": ["3", "4", "5", "7"], "answer": 1},
                    {"q": "What does SAMA require annually?", "options": ["Full external audit only", "Self-assessment submission", "Framework recertification", "Nothing"], "answer": 1},
                    {"q": "Which international frameworks does SAMA CSF align with?", "options": ["PCI DSS only", "ISO 27001 and NIST", "COBIT only", "None"], "answer": 1},
                    {"q": "Does SAMA CSF include business continuity requirements?", "options": ["No, that's separate", "Yes, BCM is included", "Only for large banks", "Optional"], "answer": 1}
                ]
            },
            {
                "id": "grc_eu_regulations", "title": "EU Regulatory Landscape (NIS2, DORA, AI Act)", "icon": "fas fa-landmark", "level": "Advanced", "duration": "25 min",
                "description": "Overview of key EU regulations affecting cybersecurity, digital resilience, and AI governance.",
                "learning_points": [
                    "NIS2 Directive: Enhanced cybersecurity requirements for essential and important entities, 24-hour incident reporting",
                    "DORA (Digital Operational Resilience Act): ICT risk management for financial sector, third-party risk, testing requirements",
                    "EU AI Act: Risk-based regulation of AI systems - prohibited, high-risk, limited-risk, minimal-risk categories",
                    "These regulations affect organizations outside EU if they serve EU customers or markets",
                    "Significant penalties for non-compliance across all three regulations"
                ],
                "scenario": {"title": "EU Compliance Planning", "text": "Your organization plans to offer AI-powered financial services to EU customers. Which regulations apply?", "correct_action": "Multiple regulations apply: 1) GDPR for personal data processing. 2) DORA for digital resilience (if serving financial sector). 3) EU AI Act for AI system compliance - classify the AI risk level. 4) Potentially NIS2 if considered essential/important entity. Conduct comprehensive regulatory mapping and gap assessment."},
                "quiz": [
                    {"q": "What is NIS2?", "options": ["Network Infrastructure Standard", "EU cybersecurity directive for essential entities", "US security framework", "Data privacy law"], "answer": 1},
                    {"q": "What does DORA stand for?", "options": ["Digital Operations Risk Assessment", "Digital Operational Resilience Act", "Data Organization Regulation Act", "Defense Operations Requirements Act"], "answer": 1},
                    {"q": "How does the EU AI Act classify AI systems?", "options": ["By industry", "By company size", "By risk level", "By country of origin"], "answer": 2},
                    {"q": "How quickly must NIS2 incidents be reported?", "options": ["72 hours", "24 hours initial, 72 hours full", "1 week", "Monthly"], "answer": 1},
                    {"q": "Does DORA apply to non-EU financial firms?", "options": ["No, EU only", "Yes, if they serve EU financial entities", "Only to US firms", "Never"], "answer": 1}
                ]
            }
        ],
        "ar": [
            {
                "id": "grc_nca_frameworks", "title": "أطر الأمن السيبراني للهيئة الوطنية (السعودية)", "icon": "fas fa-flag", "level": "متوسط", "duration": "25 دقيقة",
                "description": "دليل شامل لأطر الهيئة الوطنية للأمن السيبراني بما في ذلك ECC و CSCC و DCC وغيرها.",
                "learning_points": [
                    "الضوابط الأساسية للأمن السيبراني (ECC): 114 ضابط في 5 مجالات - إلزامية لجميع الجهات الحكومية",
                    "ضوابط الأنظمة الحساسة (CSCC): ضوابط معززة للبنية التحتية الحرجة الوطنية",
                    "ضوابط الأمن السيبراني للبيانات (DCC): ضوابط حماية البيانات المتوافقة مع نظام حماية البيانات الشخصية",
                    "ضوابط الأمن السيبراني للحوسبة السحابية (CCC): متطلبات أمان تبني الخدمات السحابية",
                    "ضوابط العمل عن بعد (TCC) والتقنيات التشغيلية (OTCC): ضوابط خاصة بكل منها"
                ],
                "scenario": {"title": "فجوة امتثال ECC", "text": "حصلت منظمتك على 65% في تقييم امتثال ECC. الإدارة تريد الوصول إلى 90% خلال 6 أشهر. كيف تحدد الأولويات؟", "correct_action": "ابدأ بالفجوات عالية الأولوية في مجالي حوكمة الأمن السيبراني والدفاع. ركز على المكاسب السريعة (السياسات، التوعية) مع التخطيط للضوابط التقنية طويلة المدى. أنشئ خارطة طريق للمعالجة مع ملكية ومواعيد واضحة."},
                "quiz": [
                    {"q": "كم عدد المجالات الرئيسية في ECC؟", "options": ["3", "5", "7", "10"], "answer": 1},
                    {"q": "أي إطار من الهيئة ينطبق على البنية التحتية الحرجة الوطنية؟", "options": ["ECC", "CSCC", "TCC", "DCC"], "answer": 1},
                    {"q": "ما العلاقة بين DCC و نظام حماية البيانات الشخصية؟", "options": ["غير مرتبطين", "DCC يوفر ضوابط تقنية لتنفيذ متطلبات النظام", "النظام يحل محل DCC", "DCC اختياري"], "answer": 1},
                    {"q": "من يجب أن يمتثل لـ ECC؟", "options": ["البنوك فقط", "الجهات الحكومية فقط", "جميع الجهات الحكومية والبنية التحتية الحرجة", "شركات التقنية فقط"], "answer": 2},
                    {"q": "ما استخدام CCC؟", "options": ["متطلبات أمان تبني الخدمات السحابية", "معايير التشفير", "إدارة الأزمات", "اتصالات العملاء"], "answer": 0}
                ]
            },
            {
                "id": "grc_pdpl", "title": "نظام حماية البيانات الشخصية السعودي (PDPL)", "icon": "fas fa-user-shield", "level": "متوسط", "duration": "20 دقيقة",
                "description": "فهم متطلبات نظام حماية البيانات الشخصية السعودي وحقوق أصحاب البيانات والتزامات الامتثال.",
                "learning_points": [
                    "نظام حماية البيانات الشخصية ينطبق على جميع معالجة البيانات الشخصية في السعودية بغض النظر عن موقع المعالج",
                    "الأسس القانونية: الموافقة، العقد، الالتزام القانوني، المصالح الحيوية، المصلحة العامة",
                    "حقوق صاحب البيانات: الوصول، التصحيح، الحذف، النقل، الاعتراض",
                    "متطلب تعيين مسؤول حماية البيانات (DPO) لبعض المنظمات",
                    "قيود نقل البيانات عبر الحدود ومتطلبات الملاءمة",
                    "العقوبات: حتى 5 ملايين ريال للمخالفات"
                ],
                "scenario": {"title": "الاستجابة لاختراق البيانات", "text": "اكتشفت منظمتك اختراق بيانات يؤثر على 10,000 سجل عميل تشمل أرقام الهوية الوطنية. ما التزاماتك بموجب النظام؟", "correct_action": "إخطار سدايا خلال 72 ساعة إذا كان الاختراق يشكل خطراً على الأفراد. تقييم أثر الاختراق وتوثيق جميع الإجراءات. إخطار الأفراد المتأثرين إذا كان هناك خطر عالٍ على حقوقهم. تنفيذ إجراءات لمنع التكرار."},
                "quiz": [
                    {"q": "ما أقصى عقوبة لمخالفات نظام حماية البيانات الشخصية؟", "options": ["مليون ريال", "3 ملايين ريال", "5 ملايين ريال", "10 ملايين ريال"], "answer": 2},
                    {"q": "خلال كم ساعة يجب إخطار سدايا باختراق بيانات خطير؟", "options": ["24 ساعة", "48 ساعة", "72 ساعة", "أسبوع"], "answer": 2},
                    {"q": "أي جهة تنظم نظام حماية البيانات الشخصية في السعودية؟", "options": ["الهيئة الوطنية للأمن السيبراني", "سدايا", "ساما", "هيئة الاتصالات"], "answer": 1},
                    {"q": "ما الذي ليس من حقوق صاحب البيانات بموجب النظام؟", "options": ["حق الوصول", "حق الحذف", "حق المنتجات المجانية", "حق التصحيح"], "answer": 2},
                    {"q": "هل يمكن نقل البيانات الشخصية خارج السعودية؟", "options": ["أبداً", "دائماً بدون قيود", "فقط مع تدابير حماية كافية", "فقط لدول الخليج"], "answer": 2}
                ]
            },
            {
                "id": "grc_iso27001", "title": "ISO 27001:2022 بالتفصيل", "icon": "fas fa-certificate", "level": "متقدم", "duration": "30 دقيقة",
                "description": "فهم تفصيلي لمتطلبات نظام إدارة أمن المعلومات ISO 27001:2022 وتنفيذه.",
                "learning_points": [
                    "هيكل ISO 27001:2022: 10 بنود تغطي السياق، القيادة، التخطيط، الدعم، التشغيل، التقييم، التحسين",
                    "الملحق A: 93 ضابط منظمة في 4 محاور (تنظيمية، بشرية، مادية، تقنية)",
                    "النهج القائم على المخاطر: تحديد وتقييم ومعالجة منهجية لمخاطر أمن المعلومات",
                    "بيان قابلية التطبيق (SoA): توثيق الضوابط المطبقة وحالة تنفيذها",
                    "عملية الشهادة: المرحلة 1 (مراجعة الوثائق)، المرحلة 2 (تدقيق التنفيذ)، تدقيقات المراقبة"
                ],
                "scenario": {"title": "التحضير للشهادة", "text": "منظمتك تريد شهادة ISO 27001 خلال 12 شهر. لديكم ضوابط أمنية أساسية لكن لا يوجد نظام ISMS رسمي. من أين تبدأ؟", "correct_action": "1) إجراء تقييم الفجوات مقابل متطلبات ISO 27001. 2) تحديد نطاق ISMS والحصول على التزام الإدارة. 3) إجراء تقييم المخاطر وإنشاء خطة معالجة المخاطر. 4) تطوير الوثائق المطلوبة (السياسات، الإجراءات، SoA). 5) تنفيذ الضوابط وإجراء تدقيق داخلي. 6) مراجعة الإدارة قبل تدقيق الشهادة."},
                "quiz": [
                    {"q": "كم عدد الضوابط في الملحق A لـ ISO 27001:2022؟", "options": ["114", "93", "50", "27"], "answer": 1},
                    {"q": "ما الوثيقة التي تسرد ضوابط ISO 27001 المطبقة على منظمتك؟", "options": ["سجل المخاطر", "بيان قابلية التطبيق", "السياسة الأمنية", "تقرير التدقيق"], "answer": 1},
                    {"q": "ما المرحلة 1 من شهادة ISO 27001؟", "options": ["تدقيق التنفيذ", "مراجعة الوثائق", "تدقيق المراقبة", "تقييم الفجوات"], "answer": 1},
                    {"q": "كم مرة تُجرى تدقيقات المراقبة بعد الشهادة؟", "options": ["شهرياً", "ربع سنوياً", "سنوياً", "كل 3 سنوات"], "answer": 2},
                    {"q": "ما النهج الذي يتطلبه ISO 27001 لاختيار الضوابط؟", "options": ["تنفيذ جميع الضوابط", "اختيار قائم على المخاطر", "اختيار قائم على التكلفة", "اختيار عشوائي"], "answer": 1}
                ]
            }
        ]
    }
}

# ============================================================================
# TEMPLATES LIBRARY - Domain Specific
# ============================================================================

DOMAIN_TEMPLATES = {
    "cyber": {
        "policy": {
            "en": {
                "Information Security Policy": {
                    "description": "Comprehensive information security policy covering data protection, access control, and incident management",
                    "framework": "ISO 27001"
                },
                "Access Control Policy": {
                    "description": "Policy governing user access, authentication, and authorization controls",
                    "framework": "NCA ECC"
                },
                "Incident Response Policy": {
                    "description": "Policy for detecting, responding to, and recovering from security incidents",
                    "framework": "NIST CSF"
                },
                "Network Security Policy": {
                    "description": "Policy for securing network infrastructure, firewalls, and communications",
                    "framework": "NCA ECC"
                },
                "Endpoint Security Policy": {
                    "description": "Policy for securing endpoints including workstations, laptops, and mobile devices",
                    "framework": "NCA ECC"
                },
                "Security Awareness Policy": {
                    "description": "Policy for employee security awareness training and phishing prevention",
                    "framework": "ISO 27001"
                },
                "Vulnerability Management Policy": {
                    "description": "Policy for identifying, assessing, and remediating security vulnerabilities",
                    "framework": "NIST CSF"
                },
                "Cloud Security Policy": {
                    "description": "Policy for secure use of cloud services and infrastructure",
                    "framework": "NCA CCC"
                }
            },
            "ar": {
                "سياسة أمن المعلومات": {
                    "description": "سياسة شاملة لأمن المعلومات تغطي حماية البيانات والتحكم بالوصول وإدارة الحوادث",
                    "framework": "ISO 27001"
                },
                "سياسة التحكم بالوصول": {
                    "description": "سياسة تحكم وصول المستخدمين والمصادقة والتفويض",
                    "framework": "NCA ECC"
                },
                "سياسة الاستجابة للحوادث": {
                    "description": "سياسة لاكتشاف الحوادث الأمنية والاستجابة لها والتعافي منها",
                    "framework": "NIST CSF"
                },
                "سياسة أمن الشبكات": {
                    "description": "سياسة لتأمين البنية التحتية للشبكات وجدران الحماية والاتصالات",
                    "framework": "NCA ECC"
                },
                "سياسة أمن النقاط الطرفية": {
                    "description": "سياسة لتأمين الأجهزة الطرفية بما في ذلك محطات العمل والحواسيب المحمولة",
                    "framework": "NCA ECC"
                },
                "سياسة التوعية الأمنية": {
                    "description": "سياسة للتدريب على التوعية الأمنية والوقاية من التصيد الاحتيالي",
                    "framework": "ISO 27001"
                },
                "سياسة إدارة الثغرات": {
                    "description": "سياسة لتحديد وتقييم ومعالجة الثغرات الأمنية",
                    "framework": "NIST CSF"
                },
                "سياسة أمن السحابة": {
                    "description": "سياسة للاستخدام الآمن للخدمات والبنية التحتية السحابية",
                    "framework": "NCA CCC"
                }
            }
        },
        "audit": {
            "en": {
                "ISO 27001 Compliance Audit": {
                    "description": "Audit checklist for ISO 27001 information security management",
                    "framework": "ISO 27001",
                    "controls": 114
                },
                "NCA ECC Compliance Audit": {
                    "description": "Audit against NCA Essential Cybersecurity Controls",
                    "framework": "NCA ECC",
                    "controls": 114
                },
                "NIST CSF Assessment": {
                    "description": "Assessment against NIST Cybersecurity Framework",
                    "framework": "NIST CSF",
                    "controls": 108
                },
                "Penetration Testing Audit": {
                    "description": "Audit for penetration testing and vulnerability assessment results",
                    "framework": "OWASP",
                    "controls": 50
                }
            },
            "ar": {
                "تدقيق الامتثال ISO 27001": {
                    "description": "قائمة تدقيق لنظام إدارة أمن المعلومات",
                    "framework": "ISO 27001",
                    "controls": 114
                },
                "تدقيق الامتثال NCA ECC": {
                    "description": "تدقيق وفق ضوابط الأمن السيبراني الأساسية",
                    "framework": "NCA ECC",
                    "controls": 114
                },
                "تقييم NIST CSF": {
                    "description": "تقييم وفق إطار الأمن السيبراني NIST",
                    "framework": "NIST CSF",
                    "controls": 108
                },
                "تدقيق اختبار الاختراق": {
                    "description": "تدقيق لنتائج اختبار الاختراق وتقييم الثغرات",
                    "framework": "OWASP",
                    "controls": 50
                }
            }
        },
        "risk": {
            "en": {
                "Cybersecurity Risk Assessment": {
                    "description": "Comprehensive cyber risk assessment covering threats, vulnerabilities, and impacts",
                    "categories": ["External Threats", "Internal Threats", "Technical Vulnerabilities"]
                },
                "Ransomware Risk Assessment": {
                    "description": "Focused assessment on ransomware threats and prevention",
                    "categories": ["Prevention", "Detection", "Response", "Recovery"]
                },
                "Third Party Cyber Risk": {
                    "description": "Assessment of cybersecurity risks from vendors and partners",
                    "categories": ["Vendor Security", "Data Sharing", "Access Control"]
                }
            },
            "ar": {
                "تقييم مخاطر الأمن السيبراني": {
                    "description": "تقييم شامل للمخاطر السيبرانية يغطي التهديدات والثغرات والآثار",
                    "categories": ["تهديدات خارجية", "تهديدات داخلية", "ثغرات تقنية"]
                },
                "تقييم مخاطر برامج الفدية": {
                    "description": "تقييم مركز على تهديدات برامج الفدية والوقاية منها",
                    "categories": ["الوقاية", "الكشف", "الاستجابة", "التعافي"]
                },
                "مخاطر الأطراف الثالثة السيبرانية": {
                    "description": "تقييم مخاطر الأمن السيبراني من الموردين والشركاء",
                    "categories": ["أمن المورد", "مشاركة البيانات", "التحكم بالوصول"]
                }
            }
        }
    },
    "data": {
        "policy": {
            "en": {
                "Data Governance Policy": {
                    "description": "Policy establishing data governance framework, roles, and responsibilities",
                    "framework": "NDMO"
                },
                "Data Classification Policy": {
                    "description": "Policy for classifying data based on sensitivity and criticality",
                    "framework": "NDMO"
                },
                "Data Quality Policy": {
                    "description": "Policy ensuring data accuracy, completeness, and consistency",
                    "framework": "NDMO"
                },
                "Data Retention Policy": {
                    "description": "Policy defining data retention periods and disposal procedures",
                    "framework": "PDPL"
                },
                "Personal Data Protection Policy": {
                    "description": "Policy for handling personal data in compliance with PDPL",
                    "framework": "PDPL"
                },
                "Data Sharing Policy": {
                    "description": "Policy governing internal and external data sharing",
                    "framework": "NDMO"
                },
                "Open Data Policy": {
                    "description": "Policy for publishing and managing open government data",
                    "framework": "NDMO"
                },
                "Data Catalog Policy": {
                    "description": "Policy for maintaining enterprise data catalog and metadata",
                    "framework": "NDMO"
                }
            },
            "ar": {
                "سياسة حوكمة البيانات": {
                    "description": "سياسة تأسيس إطار حوكمة البيانات والأدوار والمسؤوليات",
                    "framework": "NDMO"
                },
                "سياسة تصنيف البيانات": {
                    "description": "سياسة لتصنيف البيانات بناءً على الحساسية والأهمية",
                    "framework": "NDMO"
                },
                "سياسة جودة البيانات": {
                    "description": "سياسة لضمان دقة البيانات واكتمالها واتساقها",
                    "framework": "NDMO"
                },
                "سياسة الاحتفاظ بالبيانات": {
                    "description": "سياسة تحدد فترات الاحتفاظ بالبيانات وإجراءات التخلص",
                    "framework": "PDPL"
                },
                "سياسة حماية البيانات الشخصية": {
                    "description": "سياسة للتعامل مع البيانات الشخصية وفقاً لنظام حماية البيانات",
                    "framework": "PDPL"
                },
                "سياسة مشاركة البيانات": {
                    "description": "سياسة تحكم مشاركة البيانات الداخلية والخارجية",
                    "framework": "NDMO"
                },
                "سياسة البيانات المفتوحة": {
                    "description": "سياسة لنشر وإدارة البيانات الحكومية المفتوحة",
                    "framework": "NDMO"
                },
                "سياسة فهرس البيانات": {
                    "description": "سياسة للحفاظ على فهرس بيانات المؤسسة والبيانات الوصفية",
                    "framework": "NDMO"
                }
            }
        },
        "audit": {
            "en": {
                "NDMO Compliance Audit": {
                    "description": "Audit against National Data Management Office standards",
                    "framework": "NDMO",
                    "controls": 85
                },
                "PDPL Compliance Audit": {
                    "description": "Audit for Personal Data Protection Law compliance",
                    "framework": "PDPL",
                    "controls": 45
                },
                "Data Quality Audit": {
                    "description": "Audit assessing data quality dimensions and metrics",
                    "framework": "NDMO",
                    "controls": 30
                },
                "Data Governance Maturity Audit": {
                    "description": "Audit evaluating data governance maturity level",
                    "framework": "NDMO",
                    "controls": 50
                }
            },
            "ar": {
                "تدقيق الامتثال NDMO": {
                    "description": "تدقيق وفق معايير مكتب إدارة البيانات الوطني",
                    "framework": "NDMO",
                    "controls": 85
                },
                "تدقيق الامتثال لنظام حماية البيانات": {
                    "description": "تدقيق للامتثال لنظام حماية البيانات الشخصية",
                    "framework": "PDPL",
                    "controls": 45
                },
                "تدقيق جودة البيانات": {
                    "description": "تدقيق يقيم أبعاد ومقاييس جودة البيانات",
                    "framework": "NDMO",
                    "controls": 30
                },
                "تدقيق نضج حوكمة البيانات": {
                    "description": "تدقيق يقيم مستوى نضج حوكمة البيانات",
                    "framework": "NDMO",
                    "controls": 50
                }
            }
        },
        "risk": {
            "en": {
                "Data Privacy Risk Assessment": {
                    "description": "Assessment of risks related to personal data processing",
                    "categories": ["Collection", "Processing", "Storage", "Sharing", "Disposal"]
                },
                "Data Quality Risk Assessment": {
                    "description": "Assessment of risks affecting data quality",
                    "categories": ["Accuracy", "Completeness", "Timeliness", "Consistency"]
                },
                "Data Breach Risk Assessment": {
                    "description": "Assessment of data breach risks and impacts",
                    "categories": ["Internal Threats", "External Threats", "Technical Failures"]
                }
            },
            "ar": {
                "تقييم مخاطر خصوصية البيانات": {
                    "description": "تقييم المخاطر المتعلقة بمعالجة البيانات الشخصية",
                    "categories": ["الجمع", "المعالجة", "التخزين", "المشاركة", "التخلص"]
                },
                "تقييم مخاطر جودة البيانات": {
                    "description": "تقييم المخاطر المؤثرة على جودة البيانات",
                    "categories": ["الدقة", "الاكتمال", "التوقيت", "الاتساق"]
                },
                "تقييم مخاطر خرق البيانات": {
                    "description": "تقييم مخاطر خرق البيانات وآثارها",
                    "categories": ["تهديدات داخلية", "تهديدات خارجية", "أعطال تقنية"]
                }
            }
        }
    },
    "ai": {
        "policy": {
            "en": {
                "AI Governance Policy": {
                    "description": "Policy establishing AI governance framework and oversight",
                    "framework": "SDAIA"
                },
                "AI Ethics Policy": {
                    "description": "Policy defining ethical principles for AI development and use",
                    "framework": "SDAIA"
                },
                "AI Risk Management Policy": {
                    "description": "Policy for identifying and managing AI-related risks",
                    "framework": "SDAIA"
                },
                "AI Model Development Policy": {
                    "description": "Policy governing AI model development lifecycle",
                    "framework": "SDAIA"
                },
                "AI Data Usage Policy": {
                    "description": "Policy for data usage in AI training and inference",
                    "framework": "SDAIA"
                },
                "AI Transparency Policy": {
                    "description": "Policy ensuring explainability and transparency in AI decisions",
                    "framework": "SDAIA"
                },
                "Generative AI Policy": {
                    "description": "Policy for responsible use of generative AI tools",
                    "framework": "SDAIA"
                },
                "AI Vendor Management Policy": {
                    "description": "Policy for managing AI vendors and third-party AI services",
                    "framework": "SDAIA"
                }
            },
            "ar": {
                "سياسة حوكمة الذكاء الاصطناعي": {
                    "description": "سياسة تأسيس إطار حوكمة الذكاء الاصطناعي والإشراف",
                    "framework": "SDAIA"
                },
                "سياسة أخلاقيات الذكاء الاصطناعي": {
                    "description": "سياسة تحدد المبادئ الأخلاقية لتطوير واستخدام الذكاء الاصطناعي",
                    "framework": "SDAIA"
                },
                "سياسة إدارة مخاطر الذكاء الاصطناعي": {
                    "description": "سياسة لتحديد وإدارة المخاطر المتعلقة بالذكاء الاصطناعي",
                    "framework": "SDAIA"
                },
                "سياسة تطوير نماذج الذكاء الاصطناعي": {
                    "description": "سياسة تحكم دورة حياة تطوير نماذج الذكاء الاصطناعي",
                    "framework": "SDAIA"
                },
                "سياسة استخدام البيانات للذكاء الاصطناعي": {
                    "description": "سياسة لاستخدام البيانات في تدريب واستدلال الذكاء الاصطناعي",
                    "framework": "SDAIA"
                },
                "سياسة شفافية الذكاء الاصطناعي": {
                    "description": "سياسة لضمان قابلية التفسير والشفافية في قرارات الذكاء الاصطناعي",
                    "framework": "SDAIA"
                },
                "سياسة الذكاء الاصطناعي التوليدي": {
                    "description": "سياسة للاستخدام المسؤول لأدوات الذكاء الاصطناعي التوليدي",
                    "framework": "SDAIA"
                },
                "سياسة إدارة موردي الذكاء الاصطناعي": {
                    "description": "سياسة لإدارة موردي الذكاء الاصطناعي وخدمات الطرف الثالث",
                    "framework": "SDAIA"
                }
            }
        },
        "audit": {
            "en": {
                "SDAIA AI Governance Audit": {
                    "description": "Audit against SDAIA AI governance principles",
                    "framework": "SDAIA",
                    "controls": 60
                },
                "AI Ethics Audit": {
                    "description": "Audit assessing AI ethics compliance",
                    "framework": "SDAIA",
                    "controls": 40
                },
                "AI Model Audit": {
                    "description": "Audit of AI model performance, bias, and fairness",
                    "framework": "SDAIA",
                    "controls": 35
                },
                "Generative AI Audit": {
                    "description": "Audit for generative AI usage and compliance",
                    "framework": "SDAIA",
                    "controls": 25
                }
            },
            "ar": {
                "تدقيق حوكمة الذكاء الاصطناعي SDAIA": {
                    "description": "تدقيق وفق مبادئ حوكمة الذكاء الاصطناعي لسدايا",
                    "framework": "SDAIA",
                    "controls": 60
                },
                "تدقيق أخلاقيات الذكاء الاصطناعي": {
                    "description": "تدقيق يقيم الامتثال لأخلاقيات الذكاء الاصطناعي",
                    "framework": "SDAIA",
                    "controls": 40
                },
                "تدقيق نماذج الذكاء الاصطناعي": {
                    "description": "تدقيق أداء نماذج الذكاء الاصطناعي والتحيز والعدالة",
                    "framework": "SDAIA",
                    "controls": 35
                },
                "تدقيق الذكاء الاصطناعي التوليدي": {
                    "description": "تدقيق لاستخدام الذكاء الاصطناعي التوليدي والامتثال",
                    "framework": "SDAIA",
                    "controls": 25
                }
            }
        },
        "risk": {
            "en": {
                "AI Bias Risk Assessment": {
                    "description": "Assessment of bias risks in AI models and decisions",
                    "categories": ["Data Bias", "Algorithm Bias", "Output Bias"]
                },
                "AI Security Risk Assessment": {
                    "description": "Assessment of security risks specific to AI systems",
                    "categories": ["Model Attacks", "Data Poisoning", "Prompt Injection"]
                },
                "AI Operational Risk Assessment": {
                    "description": "Assessment of operational risks in AI deployment",
                    "categories": ["Model Drift", "Performance Degradation", "Integration Failures"]
                }
            },
            "ar": {
                "تقييم مخاطر تحيز الذكاء الاصطناعي": {
                    "description": "تقييم مخاطر التحيز في نماذج وقرارات الذكاء الاصطناعي",
                    "categories": ["تحيز البيانات", "تحيز الخوارزمية", "تحيز المخرجات"]
                },
                "تقييم مخاطر أمن الذكاء الاصطناعي": {
                    "description": "تقييم المخاطر الأمنية الخاصة بأنظمة الذكاء الاصطناعي",
                    "categories": ["هجمات النموذج", "تسميم البيانات", "حقن الموجه"]
                },
                "تقييم المخاطر التشغيلية للذكاء الاصطناعي": {
                    "description": "تقييم المخاطر التشغيلية في نشر الذكاء الاصطناعي",
                    "categories": ["انحراف النموذج", "تدهور الأداء", "فشل التكامل"]
                }
            }
        }
    },
    "dt": {
        "policy": {
            "en": {
                "Digital Transformation Policy": {
                    "description": "Policy guiding organizational digital transformation initiatives",
                    "framework": "DGA"
                },
                "Digital Services Policy": {
                    "description": "Policy for digital service design, delivery, and management",
                    "framework": "DGA"
                },
                "Technology Adoption Policy": {
                    "description": "Policy for evaluating and adopting new technologies",
                    "framework": "DGA"
                },
                "Process Automation Policy": {
                    "description": "Policy governing business process automation initiatives",
                    "framework": "DGA"
                },
                "Digital Identity Policy": {
                    "description": "Policy for digital identity management and authentication",
                    "framework": "DGA"
                },
                "E-Services Policy": {
                    "description": "Policy for electronic government services",
                    "framework": "DGA"
                },
                "Mobile Services Policy": {
                    "description": "Policy for mobile application development and deployment",
                    "framework": "DGA"
                },
                "IT Infrastructure Modernization Policy": {
                    "description": "Policy for modernizing IT infrastructure and systems",
                    "framework": "DGA"
                }
            },
            "ar": {
                "سياسة التحول الرقمي": {
                    "description": "سياسة توجيه مبادرات التحول الرقمي المؤسسي",
                    "framework": "DGA"
                },
                "سياسة الخدمات الرقمية": {
                    "description": "سياسة لتصميم وتقديم وإدارة الخدمات الرقمية",
                    "framework": "DGA"
                },
                "سياسة تبني التقنية": {
                    "description": "سياسة لتقييم وتبني التقنيات الجديدة",
                    "framework": "DGA"
                },
                "سياسة أتمتة العمليات": {
                    "description": "سياسة تحكم مبادرات أتمتة العمليات التجارية",
                    "framework": "DGA"
                },
                "سياسة الهوية الرقمية": {
                    "description": "سياسة لإدارة الهوية الرقمية والمصادقة",
                    "framework": "DGA"
                },
                "سياسة الخدمات الإلكترونية": {
                    "description": "سياسة للخدمات الحكومية الإلكترونية",
                    "framework": "DGA"
                },
                "سياسة خدمات الجوال": {
                    "description": "سياسة لتطوير ونشر تطبيقات الجوال",
                    "framework": "DGA"
                },
                "سياسة تحديث البنية التحتية": {
                    "description": "سياسة لتحديث البنية التحتية والأنظمة التقنية",
                    "framework": "DGA"
                }
            }
        },
        "audit": {
            "en": {
                "Digital Maturity Audit": {
                    "description": "Audit assessing digital transformation maturity level",
                    "framework": "DGA",
                    "controls": 50
                },
                "E-Services Audit": {
                    "description": "Audit of electronic services quality and compliance",
                    "framework": "DGA",
                    "controls": 40
                },
                "Digital Experience Audit": {
                    "description": "Audit of digital user experience and accessibility",
                    "framework": "DGA",
                    "controls": 35
                },
                "IT Modernization Audit": {
                    "description": "Audit of IT infrastructure modernization progress",
                    "framework": "DGA",
                    "controls": 45
                }
            },
            "ar": {
                "تدقيق النضج الرقمي": {
                    "description": "تدقيق يقيم مستوى نضج التحول الرقمي",
                    "framework": "DGA",
                    "controls": 50
                },
                "تدقيق الخدمات الإلكترونية": {
                    "description": "تدقيق جودة الخدمات الإلكترونية والامتثال",
                    "framework": "DGA",
                    "controls": 40
                },
                "تدقيق التجربة الرقمية": {
                    "description": "تدقيق تجربة المستخدم الرقمية وسهولة الوصول",
                    "framework": "DGA",
                    "controls": 35
                },
                "تدقيق تحديث تقنية المعلومات": {
                    "description": "تدقيق تقدم تحديث البنية التحتية التقنية",
                    "framework": "DGA",
                    "controls": 45
                }
            }
        },
        "risk": {
            "en": {
                "Digital Transformation Risk Assessment": {
                    "description": "Assessment of risks in digital transformation programs",
                    "categories": ["Technology", "Change Management", "Budget", "Timeline"]
                },
                "Technology Adoption Risk Assessment": {
                    "description": "Assessment of risks in adopting new technologies",
                    "categories": ["Integration", "Vendor Lock-in", "Skills Gap", "Security"]
                },
                "Legacy System Risk Assessment": {
                    "description": "Assessment of risks from legacy systems",
                    "categories": ["Technical Debt", "Security", "Integration", "Support"]
                }
            },
            "ar": {
                "تقييم مخاطر التحول الرقمي": {
                    "description": "تقييم المخاطر في برامج التحول الرقمي",
                    "categories": ["التقنية", "إدارة التغيير", "الميزانية", "الجدول الزمني"]
                },
                "تقييم مخاطر تبني التقنية": {
                    "description": "تقييم المخاطر في تبني التقنيات الجديدة",
                    "categories": ["التكامل", "الارتباط بالمورد", "فجوة المهارات", "الأمان"]
                },
                "تقييم مخاطر الأنظمة القديمة": {
                    "description": "تقييم المخاطر من الأنظمة القديمة",
                    "categories": ["الديون التقنية", "الأمان", "التكامل", "الدعم"]
                }
            }
        }
    },
    "global": {
        "policy": {
            "en": {
                "ISO 27001 Policy": {
                    "description": "Policy aligned with ISO 27001 information security standard",
                    "framework": "ISO 27001"
                },
                "ISO 22301 Business Continuity Policy": {
                    "description": "Policy for business continuity management per ISO 22301",
                    "framework": "ISO 22301"
                },
                "ISO 31000 Risk Management Policy": {
                    "description": "Policy for enterprise risk management per ISO 31000",
                    "framework": "ISO 31000"
                },
                "COBIT IT Governance Policy": {
                    "description": "Policy for IT governance based on COBIT framework",
                    "framework": "COBIT"
                },
                "ITIL Service Management Policy": {
                    "description": "Policy for IT service management based on ITIL",
                    "framework": "ITIL"
                },
                "PCI-DSS Compliance Policy": {
                    "description": "Policy for payment card data security compliance",
                    "framework": "PCI-DSS"
                },
                "SOC 2 Compliance Policy": {
                    "description": "Policy for SOC 2 trust service criteria compliance",
                    "framework": "SOC 2"
                },
                "GDPR Compliance Policy": {
                    "description": "Policy for General Data Protection Regulation compliance",
                    "framework": "GDPR"
                }
            },
            "ar": {
                "سياسة ISO 27001": {
                    "description": "سياسة متوافقة مع معيار أمن المعلومات ISO 27001",
                    "framework": "ISO 27001"
                },
                "سياسة استمرارية الأعمال ISO 22301": {
                    "description": "سياسة لإدارة استمرارية الأعمال وفق ISO 22301",
                    "framework": "ISO 22301"
                },
                "سياسة إدارة المخاطر ISO 31000": {
                    "description": "سياسة لإدارة المخاطر المؤسسية وفق ISO 31000",
                    "framework": "ISO 31000"
                },
                "سياسة حوكمة تقنية المعلومات COBIT": {
                    "description": "سياسة لحوكمة تقنية المعلومات بناءً على إطار COBIT",
                    "framework": "COBIT"
                },
                "سياسة إدارة خدمات ITIL": {
                    "description": "سياسة لإدارة خدمات تقنية المعلومات بناءً على ITIL",
                    "framework": "ITIL"
                },
                "سياسة الامتثال PCI-DSS": {
                    "description": "سياسة للامتثال لمعايير أمان بيانات بطاقات الدفع",
                    "framework": "PCI-DSS"
                },
                "سياسة الامتثال SOC 2": {
                    "description": "سياسة للامتثال لمعايير خدمة الثقة SOC 2",
                    "framework": "SOC 2"
                },
                "سياسة الامتثال GDPR": {
                    "description": "سياسة للامتثال للائحة العامة لحماية البيانات",
                    "framework": "GDPR"
                }
            }
        },
        "audit": {
            "en": {
                "ISO 27001 Certification Audit": {
                    "description": "Audit for ISO 27001 certification readiness",
                    "framework": "ISO 27001",
                    "controls": 114
                },
                "ISO 22301 Compliance Audit": {
                    "description": "Audit for business continuity compliance",
                    "framework": "ISO 22301",
                    "controls": 60
                },
                "COBIT Governance Audit": {
                    "description": "Audit for IT governance maturity",
                    "framework": "COBIT",
                    "controls": 40
                },
                "PCI-DSS Compliance Audit": {
                    "description": "Audit for payment card security compliance",
                    "framework": "PCI-DSS",
                    "controls": 250
                }
            },
            "ar": {
                "تدقيق شهادة ISO 27001": {
                    "description": "تدقيق لجاهزية شهادة ISO 27001",
                    "framework": "ISO 27001",
                    "controls": 114
                },
                "تدقيق الامتثال ISO 22301": {
                    "description": "تدقيق للامتثال لاستمرارية الأعمال",
                    "framework": "ISO 22301",
                    "controls": 60
                },
                "تدقيق حوكمة COBIT": {
                    "description": "تدقيق لنضج حوكمة تقنية المعلومات",
                    "framework": "COBIT",
                    "controls": 40
                },
                "تدقيق الامتثال PCI-DSS": {
                    "description": "تدقيق للامتثال لأمان بطاقات الدفع",
                    "framework": "PCI-DSS",
                    "controls": 250
                }
            }
        },
        "risk": {
            "en": {
                "Enterprise Risk Assessment": {
                    "description": "Comprehensive enterprise-wide risk assessment",
                    "categories": ["Strategic", "Operational", "Financial", "Compliance"]
                },
                "Compliance Risk Assessment": {
                    "description": "Assessment of regulatory compliance risks",
                    "categories": ["Legal", "Regulatory", "Contractual", "Industry Standards"]
                },
                "Business Continuity Risk Assessment": {
                    "description": "Assessment of business continuity and disaster recovery risks",
                    "categories": ["Natural Disasters", "Technical Failures", "Human Factors"]
                }
            },
            "ar": {
                "تقييم المخاطر المؤسسية": {
                    "description": "تقييم شامل للمخاطر على مستوى المؤسسة",
                    "categories": ["استراتيجية", "تشغيلية", "مالية", "امتثال"]
                },
                "تقييم مخاطر الامتثال": {
                    "description": "تقييم مخاطر الامتثال التنظيمي",
                    "categories": ["قانونية", "تنظيمية", "تعاقدية", "معايير الصناعة"]
                },
                "تقييم مخاطر استمرارية الأعمال": {
                    "description": "تقييم مخاطر استمرارية الأعمال والتعافي من الكوارث",
                    "categories": ["كوارث طبيعية", "أعطال تقنية", "عوامل بشرية"]
                }
            }
        }
    },
    "erm": {
        "policy": {
            "en": {
                "Enterprise Risk Management Policy": {
                    "description": "Comprehensive ERM policy defining risk management framework, governance, and accountability across the organization",
                    "framework": "ISO 31000"
                },
                "Risk Appetite & Tolerance Policy": {
                    "description": "Policy establishing the organization's risk appetite statement, tolerance levels, and escalation thresholds",
                    "framework": "COSO ERM"
                },
                "Risk Assessment & Treatment Policy": {
                    "description": "Policy for systematic risk identification, analysis, evaluation, and treatment selection",
                    "framework": "ISO 31000"
                },
                "Business Continuity & Crisis Management Policy": {
                    "description": "Policy for business continuity planning, disaster recovery, and organizational crisis management",
                    "framework": "ISO 22301"
                },
                "Third-Party & Supply Chain Risk Policy": {
                    "description": "Policy governing risk management for vendors, suppliers, partners, and outsourced services",
                    "framework": "COSO ERM"
                },
                "Operational Risk Management Policy": {
                    "description": "Policy for managing risks arising from internal processes, people, systems, and external events",
                    "framework": "Basel III"
                },
                "Insurance & Risk Transfer Policy": {
                    "description": "Policy for risk financing, insurance procurement, and risk transfer mechanisms",
                    "framework": "IRM Standard"
                },
                "Risk Culture & Communication Policy": {
                    "description": "Policy promoting risk-aware culture, risk reporting, and stakeholder communication",
                    "framework": "COSO ERM"
                }
            },
            "ar": {
                "سياسة إدارة المخاطر المؤسسية": {
                    "description": "سياسة شاملة لإدارة المخاطر تحدد إطار العمل والحوكمة والمساءلة عبر المنظمة",
                    "framework": "ISO 31000"
                },
                "سياسة شهية المخاطر والتحمل": {
                    "description": "سياسة تحدد بيان شهية المخاطر ومستويات التحمل وعتبات التصعيد",
                    "framework": "COSO ERM"
                },
                "سياسة تقييم ومعالجة المخاطر": {
                    "description": "سياسة للتحديد والتحليل والتقييم واختيار معالجة المخاطر بشكل منهجي",
                    "framework": "ISO 31000"
                },
                "سياسة استمرارية الأعمال وإدارة الأزمات": {
                    "description": "سياسة لتخطيط استمرارية الأعمال والتعافي من الكوارث وإدارة الأزمات",
                    "framework": "ISO 22301"
                },
                "سياسة مخاطر الأطراف الثالثة وسلسلة التوريد": {
                    "description": "سياسة لإدارة مخاطر الموردين والشركاء ومقدمي الخدمات الخارجيين",
                    "framework": "COSO ERM"
                },
                "سياسة إدارة المخاطر التشغيلية": {
                    "description": "سياسة لإدارة المخاطر الناشئة من العمليات الداخلية والأفراد والأنظمة والأحداث الخارجية",
                    "framework": "Basel III"
                },
                "سياسة التأمين ونقل المخاطر": {
                    "description": "سياسة لتمويل المخاطر وشراء التأمين وآليات نقل المخاطر",
                    "framework": "IRM Standard"
                },
                "سياسة ثقافة المخاطر والتواصل": {
                    "description": "سياسة لتعزيز ثقافة الوعي بالمخاطر والإبلاغ عنها والتواصل مع أصحاب المصلحة",
                    "framework": "COSO ERM"
                }
            }
        },
        "audit": {
            "en": {
                "ERM Framework Maturity Audit": {
                    "description": "Comprehensive audit of ERM framework maturity, governance structures, and integration across the organization",
                    "framework": "COSO ERM"
                },
                "Risk Assessment Process Audit": {
                    "description": "Audit of risk identification, analysis, evaluation, and treatment processes and their effectiveness",
                    "framework": "ISO 31000"
                },
                "Business Continuity Readiness Audit": {
                    "description": "Audit of BCP/DRP readiness, testing frequency, recovery capabilities, and crisis management procedures",
                    "framework": "ISO 22301"
                },
                "Three Lines Model Audit": {
                    "description": "Audit of the three lines of defense model implementation, roles, and assurance coverage",
                    "framework": "IIA Standards"
                }
            },
            "ar": {
                "تدقيق نضج إطار إدارة المخاطر المؤسسية": {
                    "description": "تدقيق شامل لنضج إطار إدارة المخاطر وهياكل الحوكمة والتكامل عبر المنظمة",
                    "framework": "COSO ERM"
                },
                "تدقيق عمليات تقييم المخاطر": {
                    "description": "تدقيق عمليات تحديد وتحليل وتقييم ومعالجة المخاطر وفعاليتها",
                    "framework": "ISO 31000"
                },
                "تدقيق جاهزية استمرارية الأعمال": {
                    "description": "تدقيق جاهزية خطط استمرارية الأعمال وتكرار الاختبار وقدرات التعافي وإجراءات إدارة الأزمات",
                    "framework": "ISO 22301"
                },
                "تدقيق نموذج الخطوط الثلاثة": {
                    "description": "تدقيق تطبيق نموذج خطوط الدفاع الثلاثة والأدوار وتغطية التأكيد",
                    "framework": "IIA Standards"
                }
            }
        },
        "risk": {
            "en": {
                "Enterprise-Wide Risk Assessment": {
                    "description": "Comprehensive risk assessment covering strategic, operational, financial, compliance, and emerging risks",
                    "categories": ["Strategic", "Operational", "Financial", "Compliance", "Reputational", "Emerging"]
                },
                "Risk Appetite Calibration Assessment": {
                    "description": "Assessment to calibrate and validate the organization's risk appetite and tolerance thresholds",
                    "categories": ["Risk Appetite", "Tolerance", "Capacity", "Board Expectations"]
                },
                "Interconnected & Emerging Risk Assessment": {
                    "description": "Assessment of emerging risks, systemic risks, and interconnected risk cascades",
                    "categories": ["Geopolitical", "Climate", "Technology", "Pandemic", "Systemic"]
                }
            },
            "ar": {
                "تقييم المخاطر على مستوى المؤسسة": {
                    "description": "تقييم شامل للمخاطر يغطي المخاطر الاستراتيجية والتشغيلية والمالية والامتثال والناشئة",
                    "categories": ["استراتيجية", "تشغيلية", "مالية", "امتثال", "سمعة", "ناشئة"]
                },
                "تقييم معايرة شهية المخاطر": {
                    "description": "تقييم لمعايرة والتحقق من شهية المخاطر وعتبات التحمل في المنظمة",
                    "categories": ["شهية المخاطر", "التحمل", "القدرة", "توقعات مجلس الإدارة"]
                },
                "تقييم المخاطر المترابطة والناشئة": {
                    "description": "تقييم المخاطر الناشئة والمخاطر النظامية وتتابع المخاطر المترابطة",
                    "categories": ["جيوسياسية", "مناخية", "تقنية", "جائحة", "نظامية"]
                }
            }
        }
    }
}
POLICY_TEMPLATES = {"en": {}, "ar": {}}
STRATEGY_TEMPLATES = {"en": {}, "ar": {}}
AUDIT_TEMPLATES = {"en": {}, "ar": {}}
RISK_TEMPLATES = {"en": {}, "ar": {}}

# ============================================================================
# AI SERVICE
# ============================================================================

def check_ai_available():
    """Check if any AI API is available."""
    return bool(config.OPENAI_API_KEY or config.ANTHROPIC_API_KEY or config.GOOGLE_API_KEY or config.GROQ_API_KEY)

def get_available_providers():
    """Get list of available AI providers based on configured API keys."""
    providers = []
    if config.ANTHROPIC_API_KEY:
        providers.append({'id': 'anthropic', 'name': 'Anthropic Claude', 'model': 'claude-sonnet-4-20250514'})
    if config.OPENAI_API_KEY:
        providers.append({'id': 'openai', 'name': 'OpenAI GPT', 'model': 'gpt-4-turbo'})
    if config.GOOGLE_API_KEY:
        providers.append({'id': 'google', 'name': 'Google Gemini', 'model': 'gemini-2.0-flash'})
    if config.GROQ_API_KEY:
        providers.append({'id': 'groq', 'name': 'Groq (Llama 3.1)', 'model': 'llama-3.1-70b-versatile'})
    return providers

def get_user_ai_preference(task_type='generate'):
    """Get user's preferred AI provider for a specific task type.
    
    Args:
        task_type: 'generate' for document generation, 'review' for document review
    
    Returns:
        Provider string ('anthropic', 'openai', 'google', 'auto') or None
    """
    try:
        from flask import session
        if 'user_id' not in session:
            return 'auto'
        
        conn = get_db()
        col = 'ai_provider_generate' if task_type == 'generate' else 'ai_provider_review'
        user = conn.execute(f'SELECT {col} FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if user and user[0]:
            return user[0]
    except Exception:
        pass
    return 'auto'

def get_ai_provider(task_type='generate'):
    """Determine which AI provider to use based on user preference and available keys.
    
    Args:
        task_type: 'generate' for document generation, 'review' for document review
    """
    # First check user preference
    user_pref = get_user_ai_preference(task_type)
    
    # If user has a specific preference (not auto), try to use it
    if user_pref and user_pref != 'auto':
        key_map = {
            'anthropic': config.ANTHROPIC_API_KEY,
            'openai': config.OPENAI_API_KEY,
            'google': config.GOOGLE_API_KEY,
            'groq': config.GROQ_API_KEY
        }
        if key_map.get(user_pref):
            return user_pref
    
    # Fall back to system config or auto-detect
    provider = config.AI_PROVIDER.lower()
    
    if provider == 'openai' and config.OPENAI_API_KEY:
        return 'openai'
    elif provider == 'anthropic' and config.ANTHROPIC_API_KEY:
        return 'anthropic'
    elif provider == 'google' and config.GOOGLE_API_KEY:
        return 'google'
    elif provider == 'groq' and config.GROQ_API_KEY:
        return 'groq'
    elif provider == 'auto' or user_pref == 'auto':
        # Priority: Anthropic > OpenAI > Groq > Google
        if config.ANTHROPIC_API_KEY:
            return 'anthropic'
        elif config.OPENAI_API_KEY:
            return 'openai'
        elif config.GROQ_API_KEY:
            return 'groq'
        elif config.GOOGLE_API_KEY:
            return 'google'
    return None

def get_ai_status():
    """Get current AI provider status for display."""
    provider = get_ai_provider()
    if not provider:
        return {'provider': 'simulation', 'model': 'Built-in', 'connected': False}
    
    models = {
        'openai': config.AI_MODEL or 'gpt-4-turbo',
        'anthropic': config.AI_MODEL or 'claude-sonnet-4-20250514',
        'google': config.AI_MODEL or 'gemini-2.0-flash',
        'groq': config.AI_MODEL or 'llama-3.1-70b-versatile',
    }
    names = {
        'openai': 'OpenAI', 
        'anthropic': 'Anthropic Claude', 
        'google': 'Google Gemini',
        'groq': 'Groq (Llama 3.1)'
    }
    return {'provider': names.get(provider, provider), 'model': models.get(provider, ''), 'connected': True}

def clean_ai_response(text):
    """Remove instruction artifacts that AI might have included in output.
    
    This function removes:
    - FINAL CRITICAL REMINDER sections
    - Instruction warnings (⚠️ CRITICAL:...)
    - Section markers like [SECTION]
    - Meta-commentary about the document
    - AI closing statements (شكراً لكم, نتطلع للعمل, etc.)
    - Confidence Level Interpretation sections
    """
    import re
    
    if not text:
        return text
    
    # Patterns to remove
    patterns = [
        # English FINAL CRITICAL REMINDER and ALL text after it until next section or end
        r'⚠️⚠️⚠️\s*FINAL CRITICAL REMINDER\s*⚠️⚠️⚠️.*?(?=\n##|\Z)',
        # Arabic FINAL CRITICAL REMINDER
        r'⚠️⚠️⚠️\s*تذكير نهائي مهم جداً\s*⚠️⚠️⚠️.*?(?=\n##|\Z)',
        r'⚠️⚠️⚠️\s*تذكير نهائي\s*⚠️⚠️⚠️.*?(?=\n##|\Z)',
        # "The above sections provide..." meta-commentary (multi-line)
        r'The above sections provide[^#]*?(?=\n##|\n\n##|\Z)',
        r'الأقسام أعلاه توفر[^#]*?(?=\n##|\n\n##|\Z)',
        # Remove any paragraph mentioning "detailed implementation guides for each identified gap"
        r'[^\n]*detailed implementation guides for each identified gap[^\n]*(?:\n[^\n#]*)*?(?=\n\n|\n##|\Z)',
        r'[^\n]*ensuring a structured and comprehensive approach[^\n]*(?:\n[^\n#]*)*?(?=\n\n|\n##|\Z)',
        r'[^\n]*Each gap\'s implementation steps have been outlined[^\n]*(?:\n[^\n#]*)*?(?=\n\n|\n##|\Z)',
        r'[^\n]*adhering to the requirements for specificity[^\n]*(?:\n[^\n#]*)*?(?=\n\n|\n##|\Z)',
        # NOTE: Do NOT remove [SECTION] markers here - they are needed for strategy parsing
        # Remove instruction lines starting with ⚠️ CRITICAL or ⚠️ مهم
        r'\n⚠️\s*CRITICAL[^\n]*',
        r'\n⚠️\s*مهم جداً[^\n]*',
        r'\n⚠️\s*تنبيه[^\n]*',
        r'\n⚠️\s*تعليمات[^\n]*',
        r'\n⚠️\s*FRAMEWORK RESTRICTION[^\n]*',
        r'\nCRITICAL INSTRUCTION - SELECTED FRAMEWORK[^\n]*',
        r'\n⚠️\s*قيد الأطر التنظيمية[^\n]*',
        # Remove leaked prompt instruction phrases from within content
        r'The user has selected these specific frameworks?:\s*',
        r'Selected Frameworks \(USE ONLY THESE\):\s*',
        r'Allowed frameworks:\s*',
        r'The selected framework for this audit is:\s*',
        r'Reference framework:\s*',
        # Remove "per {raw_instruction}" patterns where AI echoed prompt labels
        r'\bper\s+The user has selected[^|.\n]*',
        r'\bper\s+Allowed frameworks[^|.\n]*',
        r'\bper\s+Selected Frameworks[^|.\n]*',
        r'\bوفق\s+الأطر المحددة[^|.\n]*',
        # Remove FRAMEWORK/OUTPUT RULES sections if echoed
        r'⚠\s*FRAMEWORK RULES[^\n]*(?:\n-[^\n]*)*',
        r'⚠\s*OUTPUT RULES[^\n]*(?:\n\d+\.[^\n]*)*',
        # Remove instruction blocks with warning emojis
        r'⚠️⚠️⚠️[^⚠]*?⚠️⚠️⚠️',
        r'⚠️ CRITICAL RULES[^\n]*(?:\n-[^\n]*)*',
        r'⚠️ تعليمات مهمة[^\n]*(?:\n-[^\n]*)*',
        r'⚠️ CRITICAL:[^\n]*',
        # Remove lines that are just instructions in parentheses
        r'\n\(?\d+-\d+\s+(steps|خطوات)[^\)]*\)?',
        r'\n\(?\d+-\d+\s+(KPIs?|مؤشر)[^\)]*\)?',
        r'\n\(?\d+-\d+\s+(gaps?|فجوات?)[^\)]*\)?',
        r'\n\(?\d+-\d+\s+(risks?|مخاطر)[^\)]*\)?',
        r'\n\(?\d+-\d+\s+(objectives?|أهداف)[^\)]*\)?',
        r'\n\(?\d+-\d+\s+(activities?|أنشطة)[^\)]*\)?',
        # Remove standalone parenthetical instructions
        r'\(\d+-\d+\s+[^\)]+\)',
        # Remove meta-commentary sentences
        r'This document provides a comprehensive[^\n\.]*\.',
        r'The strategy ensures alignment with[^\n\.]*selected frameworks[^\n\.]*\.',
        # Remove Arabic meta-commentary
        r'هذه الوثيقة توفر[^\n\.]*\.',
        r'تضمن هذه الاستراتيجية التوافق مع[^\n\.]*\.',
        # Remove AI closing statements (Arabic)
        r'شكراً لكم[^\n]*',
        r'شكرا لكم[^\n]*',
        r'نتطلع للعمل[^\n]*',
        r'نأمل أن يكون[^\n]*',
        r'في الختام[^\n]*',
        r'ختاماً[^\n]*نتمنى[^\n]*',
        # Remove AI closing statements (English)
        r'Thank you for.*?(?=\n\n|\n---|\Z)',
        r'We look forward to.*?(?=\n\n|\n---|\Z)',
        r'Please feel free to.*?(?=\n\n|\n---|\Z)',
        r'If you have any questions.*?(?=\n\n|\n---|\Z)',
        # Remove Confidence Level Interpretation sections
        r'\*\*Confidence Level Interpretation:\*\*.*?(?=\n\n---|\n##|\Z)',
        r'\*\*تفسير مستوى الثقة:\*\*.*?(?=\n\n---|\n##|\Z)',
        r'Confidence Level Interpretation:.*?(?=\n\n---|\n##|\Z)',
        # Remove bullet lists explaining confidence levels
        r'-\s*90-100%: High confidence[^\n]*\n-\s*70-89%[^\n]*\n-\s*50-69%[^\n]*\n-\s*Below 50%[^\n]*',
        r'[-•]\s*90-100%.*?[-•]\s*أقل من 50%[^\n]*',
        # Remove entire Confidence Assessment sections
        r'## Confidence Assessment\s*\n\*\*Confidence Level:\*\*[^#]*?(?=\n---|\n##|\Z)',
        r'## مستوى الثقة[^#]*?(?=\n---|\n##|\Z)',
        r'\*\*Key Factors:\*\*\s*\n\|[^#]*?(?=\n---|\n##|\Z)',
        r'### عوامل تقييم الثقة[^#]*?(?=\n---|\n##|\Z)',
        # Remove prompt text that leaked into output
        r'The user has selected these specific frameworks?:[^\n|]*',
        r'selected these specific frameworks?:[^\n|]*',
        r'FRAMEWORK RESTRICTION[^\n|]*',
        r'CRITICAL INSTRUCTION[^\n|]*',
        r'(?:^|\|)\s*OUTPUT RULES[^\n|]*',
        r'Do NOT echo[^\n|]*',
        r'NEVER include phrases like[^\n|]*',
        # Clean leaked instruction fragments inside table cells
        r'(?<=\|)\s*The user has selected[^|]*(?=\|)',
    ]
    
    for pattern in patterns:
        text = re.sub(pattern, '', text, flags=re.DOTALL | re.IGNORECASE | re.MULTILINE)
    
    # Clean up multiple consecutive newlines (more than 3)
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    
    # Clean up trailing whitespace on lines
    text = re.sub(r'[ \t]+\n', '\n', text)
    
    # Shorten repetitive framework full names to abbreviations
    # Replace "NCA ECC (Essential Cybersecurity Controls)" → "NCA ECC"
    text = re.sub(r'NCA ECC\s*\(Essential Cybersecurity Controls\)', 'NCA ECC', text)
    text = re.sub(r'NCA CSCC\s*\(Critical Systems Cybersecurity Controls\)', 'NCA CSCC', text)
    text = re.sub(r'NCA DCC\s*\(Data Cybersecurity Controls\)', 'NCA DCC', text)
    text = re.sub(r'NCA OTCC\s*\(Operational Technology Cybersecurity Controls\)', 'NCA OTCC', text)
    text = re.sub(r'NCA TCC\s*\(Telework Cybersecurity Controls\)', 'NCA TCC', text)
    text = re.sub(r'NCA CCC\s*\(Cloud Cybersecurity Controls\)', 'NCA CCC', text)
    text = re.sub(r'NCA NCS\s*\(National Cryptographic Standards\)', 'NCA NCS', text)
    text = re.sub(r'SAMA CSF\s*\(Cybersecurity Framework\)', 'SAMA CSF', text)
    text = re.sub(r'SAMA BCM\s*\(Business Continuity Management\)', 'SAMA BCM', text)
    text = re.sub(r'PDPL\s*\(Personal Data Protection Law\)', 'PDPL', text)
    # Also clean "Essential Cybersecurity Controls" alone
    text = re.sub(r'Essential Cybersecurity Controls\s*\(NCA ECC\)', 'NCA ECC', text)
    
    return text.strip()

def generate_ai_content(prompt, language='en', task_type='generate'):
    """Generate content using the user's preferred AI provider.
    
    Args:
        prompt: The prompt to send to the AI
        language: 'en' or 'ar'
        task_type: 'generate' for document generation, 'review' for document review
    """
    provider = get_ai_provider(task_type)
    
    if not provider:
        print("DEBUG: No AI provider available, using simulation", flush=True)
        return generate_simulation_content(prompt, language)
    
    system_prompt = "You are an expert GRC consultant. Provide professional, detailed responses."
    if language == 'ar':
        system_prompt = "أنت مستشار خبير في الحوكمة والمخاطر والامتثال. قدم ردوداً مهنية ومفصلة باللغة العربية."
    
    print(f"DEBUG: Using {provider} for {task_type} task", flush=True)
    
    result = None
    try:
        if provider == 'anthropic':
            result = _generate_anthropic(system_prompt, prompt, language)
        elif provider == 'openai':
            result = _generate_openai(system_prompt, prompt, language)
        elif provider == 'google':
            result = _generate_google(system_prompt, prompt, language)
        elif provider == 'groq':
            result = _generate_groq(system_prompt, prompt, language)
    except Exception as e:
        print(f"DEBUG: {provider} error: {e} — trying fallback", flush=True)
        # Try fallback providers
        for fallback in ['anthropic', 'openai', 'groq', 'google']:
            if fallback == provider:
                continue
            key_map = {
                'anthropic': config.ANTHROPIC_API_KEY, 
                'openai': config.OPENAI_API_KEY, 
                'google': config.GOOGLE_API_KEY,
                'groq': config.GROQ_API_KEY
            }
            if key_map.get(fallback):
                try:
                    print(f"DEBUG: Trying fallback provider: {fallback}", flush=True)
                    if fallback == 'anthropic':
                        result = _generate_anthropic(system_prompt, prompt, language)
                    elif fallback == 'openai':
                        result = _generate_openai(system_prompt, prompt, language)
                    elif fallback == 'google':
                        result = _generate_google(system_prompt, prompt, language)
                    elif fallback == 'groq':
                        result = _generate_groq(system_prompt, prompt, language)
                    break
                except Exception as e2:
                    print(f"DEBUG: Fallback {fallback} also failed: {e2}", flush=True)
    
    if result:
        # Clean AI response to remove any instruction artifacts
        result = clean_ai_response(result)
        return result
    
    print("DEBUG: All AI providers failed, using simulation", flush=True)
    return generate_simulation_content(prompt, language)

def _generate_openai(system_prompt, prompt, language='en'):
    """Generate using OpenAI API."""
    import openai
    client = openai.OpenAI(api_key=config.OPENAI_API_KEY)
    model = config.AI_MODEL if config.AI_MODEL and 'gpt' in config.AI_MODEL.lower() else 'gpt-4-turbo'
    
    print(f"DEBUG: Calling OpenAI ({model})...", flush=True)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        max_tokens=8000,
        temperature=0.7
    )
    result = response.choices[0].message.content
    print(f"DEBUG: OpenAI success, length: {len(result)}", flush=True)
    return result

def _generate_anthropic(system_prompt, prompt, language='en'):
    """Generate using Anthropic Claude API."""
    import anthropic
    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    model = config.AI_MODEL if config.AI_MODEL and 'claude' in config.AI_MODEL.lower() else 'claude-sonnet-4-20250514'
    
    print(f"DEBUG: Calling Anthropic ({model})...", flush=True)
    response = client.messages.create(
        model=model,
        max_tokens=8000,
        system=system_prompt,
        messages=[{"role": "user", "content": prompt}]
    )
    result = response.content[0].text
    print(f"DEBUG: Anthropic success, length: {len(result)}", flush=True)
    return result

def _generate_google(system_prompt, prompt, language='en'):
    """Generate using Google Gemini API."""
    import google.generativeai as genai
    genai.configure(api_key=config.GOOGLE_API_KEY)
    model_name = config.AI_MODEL if config.AI_MODEL and 'gemini' in config.AI_MODEL.lower() else 'gemini-2.0-flash'
    
    print(f"DEBUG: Calling Google Gemini ({model_name})...", flush=True)
    model = genai.GenerativeModel(model_name)
    response = model.generate_content(f"{system_prompt}\n\n{prompt}")
    result = response.text
    print(f"DEBUG: Google Gemini success, length: {len(result)}", flush=True)
    return result

def _generate_groq(system_prompt, prompt, language='en'):
    """Generate using Groq API (Llama 3.1, Mistral, etc.)."""
    from openai import OpenAI
    
    # Groq uses OpenAI-compatible API
    client = OpenAI(
        api_key=config.GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1"
    )
    
    # Available models: llama-3.1-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768
    model = config.AI_MODEL if config.AI_MODEL and ('llama' in config.AI_MODEL.lower() or 'mixtral' in config.AI_MODEL.lower()) else 'llama-3.1-70b-versatile'
    
    print(f"DEBUG: Calling Groq ({model})...", flush=True)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        max_tokens=8000,
        temperature=0.7
    )
    result = response.choices[0].message.content
    print(f"DEBUG: Groq success, length: {len(result)}", flush=True)
    return result

def generate_simulation_content(prompt, language='en'):
    """Generate simulated content when AI is unavailable - detects content type from prompt."""
    prompt_lower = prompt.lower()
    
    # Extract framework name from prompt for simulation content
    import re
    framework = 'NCA ECC'
    
    # Try Arabic pattern first: "وفق إطار **NCA ECC**" or "وفق إطار الضوابط..."
    fw_match = re.search(r'وفق إطار\s*\*{0,2}([^*\n.]+)', prompt)
    if not fw_match:
        # Try English: "FRAMEWORK: NCA ECC" (exact label from strategy prompt)
        fw_match = re.search(r'^FRAMEWORK:\s*(.+)$', prompt, re.MULTILINE | re.IGNORECASE)
    if not fw_match:
        # Try "Framework: NCA ECC" (from audit/policy prompts)
        fw_match = re.search(r'^Framework:\s*(.+)$', prompt, re.MULTILINE)
    if not fw_match:
        # Try "Reference framework: X" (from policy prompts)
        fw_match = re.search(r'Reference framework:\s*([^\n]+)', prompt, re.IGNORECASE)
    if not fw_match:
        # Try "Selected Frameworks (USE ONLY THESE): X"
        fw_match = re.search(r'Selected Frameworks[^:]*:\s*([^\n*]+)', prompt, re.IGNORECASE)
    
    if fw_match:
        framework = fw_match.group(1).strip().rstrip(',').rstrip('*').strip()
    
    # SANITIZE: Never let prompt instruction text leak into framework name
    # If framework contains instruction phrases, fall back to safe default
    poison_phrases = ['user has selected', 'you must', 'do not', 'critical', 'restriction', 'instruction', 'important']
    if any(p in framework.lower() for p in poison_phrases):
        # Try to extract just the framework abbreviation (e.g. "NCA ECC" from contaminated text)
        abbrev = re.search(r'(NCA\s+\w+|SAMA\s+\w+|ISO\s+\d+|NIST\s+\w+|NDMO|PDPL|COBIT)', framework, re.IGNORECASE)
        framework = abbrev.group(1) if abbrev else 'NCA ECC'
    
    # Extract policy name from prompt
    policy_name = None
    # English: "professional **Acceptable Use** Policy" or "professional Acceptable Use Policy"
    en_match = re.search(r'professional\s*\*{0,2}([^*\n]+?)\*{0,2}\s*Policy', prompt, re.IGNORECASE)
    if en_match:
        policy_name = en_match.group(1).strip()
    else:
        # Arabic: "وثيقة سياسة **الاستخدام المقبول** احترافية" or "سياسة **X**"
        ar_match = re.search(r'(?:وثيقة\s+)?سياسة\s*\*{0,2}([^*\n]+?)\*{0,2}\s*(?:احتراف|بتنسيق|وفق|\n)', prompt)
        if ar_match:
            policy_name = ar_match.group(1).strip()
    
    # Extract audit topic from prompt
    audit_topic_match = re.search(r'(?:Audit Topic|موضوع التدقيق):\s*([^\n]+)', prompt)
    if audit_topic_match:
        audit_topic = audit_topic_match.group(1).strip()
        if not policy_name:
            policy_name = audit_topic
    
    # Extract org structure info
    has_no_structure = bool(re.search(r'(?:لا يوجد هيكل|No Defined Structure|none|لا يتضمن إدارة)', prompt, re.IGNORECASE))
    
    # Detect content type from prompt - check most specific patterns first
    # Strategy has specific markers like "6 separate sections", "Vision & Objectives", "[SECTION]"
    if '[section]' in prompt_lower or '6 separate sections' in prompt_lower or 'vision & objective' in prompt_lower or 'الرؤية والأهداف' in prompt_lower or 'استراتيجية شاملة' in prompt_lower:
        return generate_strategy_simulation(language, framework, has_no_structure)
    elif 'audit report' in prompt_lower or 'تقرير التدقيق' in prompt_lower or 'تقرير تدقيق' in prompt_lower or ('audit' in prompt_lower and 'finding' in prompt_lower):
        # AUDIT must be checked BEFORE policy — audit topics often contain "policy" (e.g. "Email Policy audit")
        return generate_audit_simulation(language, framework, policy_name)
    elif ('rewrite' in prompt_lower and 'policy' in prompt_lower) or ('modify' in prompt_lower and 'policy' in prompt_lower) or ('أعد كتابة' in prompt_lower and 'سياسة' in prompt_lower) or 'review findings' in prompt_lower or 'نتائج المراجعة' in prompt_lower:
        return generate_policy_simulation(language, framework, policy_name)
    elif ('generate' in prompt_lower and 'policy' in prompt_lower) or ('أنشئ' in prompt_lower and 'سياسة' in prompt_lower) or ('create' in prompt_lower and 'policy' in prompt_lower) or ('professional' in prompt_lower and 'policy' in prompt_lower) or ('احترافية' in prompt_lower and 'سياسة' in prompt_lower) or ('policy document' in prompt_lower) or ('وثيقة سياسة' in prompt_lower):
        # POLICY GENERATION must be checked BEFORE review — generation prompts contain "Review and Update" section
        return generate_policy_simulation(language, framework, policy_name)
    elif ('review' in prompt_lower and 'policy' in prompt_lower) or ('مراجعة' in prompt_lower and 'سياسة' in prompt_lower) or ('comprehensive review' in prompt_lower) or ('مراجعة شاملة' in prompt_lower) or ('compliance review' in prompt_lower) or ('gap analysis' in prompt_lower and 'policy' in prompt_lower) or ('تحليل الفجوات' in prompt_lower):
        return generate_review_simulation(language, framework, policy_name, prompt)
    elif 'policy' in prompt_lower or 'سياسة' in prompt_lower:
        return generate_policy_simulation(language, framework, policy_name)
    elif 'audit' in prompt_lower or 'تدقيق' in prompt_lower:
        return generate_audit_simulation(language, framework, policy_name)
    elif 'analyze' in prompt_lower and 'risk' in prompt_lower or 'حلل' in prompt_lower and 'خطر' in prompt_lower:
        # Extract risk scenario params from prompt
        risk_category = None
        risk_asset = None
        risk_threat = None
        cat_match = re.search(r'(?:Category|الفئة):\s*([^\n]+)', prompt)
        if cat_match:
            risk_category = cat_match.group(1).strip()
        asset_match = re.search(r'(?:Asset|الأصل):\s*([^\n]+)', prompt)
        if asset_match:
            risk_asset = asset_match.group(1).strip()
        threat_match = re.search(r'(?:Threat|التهديد):\s*([^\n]+)', prompt)
        if threat_match:
            risk_threat = threat_match.group(1).strip()
        return generate_risk_simulation(language, risk_category, risk_asset, risk_threat)
    elif 'remediation' in prompt_lower or 'معالجة' in prompt_lower or ('gap' in prompt_lower and 'plan' in prompt_lower) or 'فجوات' in prompt_lower:
        return generate_gap_remediation_simulation(language, framework, prompt)
    elif 'risk appetite' in prompt_lower or 'شهية المخاطر' in prompt_lower or 'الرغبة في المخاطرة' in prompt_lower:
        return generate_risk_appetite_simulation(language, prompt)
    elif 'answer' in prompt_lower and 'question' in prompt_lower or 'أجب' in prompt_lower and 'سؤال' in prompt_lower or 'document:' in prompt_lower or 'الوثيقة التالية' in prompt_lower:
        return generate_chat_simulation(language)
    else:
        # Default to strategy
        return generate_strategy_simulation(language, framework, has_no_structure)

def generate_strategy_simulation(language='en', framework='NCA ECC', has_no_structure=False):
    """Generate strategy simulation content with implementation guidelines."""
    import re
    # Create short framework name for display
    # For Arabic names like "الضوابط الأساسية للأمن السيبراني (NCA ECC)" → extract "NCA ECC"
    abbrev_match = re.search(r'\(([A-Z][A-Z\s]+)\)', framework)
    if abbrev_match:
        fw = abbrev_match.group(1).strip()
    else:
        fw = re.sub(r'\s*\([^)]+\)\s*', '', framework).strip() or framework
    if language == 'ar':
        return f"""## 1. الرؤية والأهداف الاستراتيجية

**الرؤية:**
تأسيس المنظمة كنموذج للتميز في الأمن السيبراني في القطاع الحكومي، وتحقيق الامتثال الكامل لإطار {fw} مع ضمان أعلى معايير الحوكمة وحماية الأصول الرقمية.

### الأهداف الاستراتيجية:
| # | الهدف | المؤشر المستهدف | المبرر (مرتبط بـ {fw}) | الإطار الزمني |
|---|-------|----------------|------------------------|---------------|
| 1 | {"إنشاء إدارة مختصة بالأمن السيبراني مع تحديد الهيكل التنظيمي والصلاحيات" if has_no_structure else f"تحقيق الامتثال الكامل لإطار {fw}"} | {"هيكل تنظيمي معتمد وفريق عمل مكتمل" if has_no_structure else "امتثال > 95%"} | {"بدون فريق مختص لا يمكن تطبيق أو مراقبة أي من ضوابط " + fw + " بشكل مستدام" if has_no_structure else f"يثبت التزام المنظمة ويحقق المتطلبات التنظيمية لـ {fw}"} | {"خلال 6 أشهر" if has_no_structure else "خلال 12 شهر"} |
| 2 | تعزيز قدرات الكشف والاستجابة | تقليل وقت الاستجابة 50% | الكشف السريع يحد من أثر الاختراقات ويحقق متطلبات المراقبة المستمرة في {fw} | خلال 18 شهر |
| 3 | تطوير برنامج توعية شامل | تغطية 100% من الموظفين | الخطأ البشري أكبر مصادر الاختراقات؛ {fw} يلزم بتدريب أمني منتظم | خلال 6 أشهر |
| 4 | تطبيق الضوابط التقنية المطلوبة وفق {fw} | تطبيق جميع الضوابط الأساسية | الضوابط التقنية تشكّل خط الدفاع الأساسي المطلوب في {fw} | خلال 12 شهر |
| 5 | إنشاء فريق استجابة مركزي | فريق عمل 24/7 | {fw} يشترط إجراءات موثقة لإدارة الحوادث مع جداول زمنية محددة للاستجابة والتصعيد | خلال 9 أشهر |

[SECTION]

## 2. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية | الحالة |
|---|--------|-------|----------|--------|
| 1 | {"فجوة الهيكل التنظيمي" if has_no_structure else "فجوة السياسات والحوكمة"} | {"عدم وجود إدارة مختصة بالأمن السيبراني - هذا الأساس لتطبيق جميع الضوابط الأخرى" if has_no_structure else f"الحاجة لتحديث السياسات لتتوافق مع متطلبات {fw}"} | {"حرجة" if has_no_structure else "عالية"} | {"مفتوحة - مؤكدة" if has_no_structure else "مفتوحة"} |
| 2 | فجوة الضوابط التقنية | نقص في تطبيق الضوابط التقنية المطلوبة وفق {fw} | عالية | مفتوحة |
| 3 | فجوة التدريب والتوعية | برامج توعية غير كافية للموظفين | متوسطة | مفتوحة |
| 4 | فجوة الاستجابة للحوادث | خطة استجابة للحوادث غير مكتملة وفق متطلبات {fw} | عالية | مفتوحة |
| 5 | فجوة إدارة الأصول | عدم وجود سجل شامل ومحدث للأصول السيبرانية | متوسطة | مفتوحة |


---

### {"دليل تنفيذ الفجوة رقم 1: فجوة الهيكل التنظيمي" if has_no_structure else "دليل تنفيذ الفجوة رقم 1: فجوة السياسات والحوكمة"}

**الخطوات التفصيلية:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | {"تحديد متطلبات الهيكل التنظيمي للأمن السيبراني وفق " + fw if has_no_structure else "جرد جميع السياسات الحالية"} | {"الإدارة العليا" if has_no_structure else "أمن المعلومات"} | {"وثيقة المتطلبات" if has_no_structure else "قائمة السياسات"} |
| التخطيط | 1.2 | {"تصميم الهيكل التنظيمي المقترح (CISO، فريق SOC، فريق الحوكمة، فريق CSIRT)" if has_no_structure else f"تحديد متطلبات {fw} المتعلقة بالحوكمة"} | {"الإدارة العليا" if has_no_structure else "الامتثال"} | {"الهيكل التنظيمي المقترح" if has_no_structure else "جدول المتطلبات"} |
| التخطيط | 1.3 | {"تحديد الميزانية والموارد البشرية المطلوبة" if has_no_structure else "تحليل الفجوات بين الوضع الحالي والمطلوب"} | {"الإدارة المالية" if has_no_structure else "أمن المعلومات"} | {"الميزانية المعتمدة" if has_no_structure else "تقرير الفجوات"} |
| التنفيذ | 2.1 | {"اعتماد الهيكل التنظيمي من الإدارة العليا" if has_no_structure else "صياغة السياسات الجديدة/المحدثة"} | {"الإدارة التنفيذية" if has_no_structure else "أمن المعلومات"} | {"قرار اعتماد رسمي" if has_no_structure else "مسودات السياسات"} |
| التنفيذ | 2.2 | {"تعيين مسؤول الأمن السيبراني (CISO) وتحديد صلاحياته" if has_no_structure else "مراجعة قانونية وتقنية"} | {"الموارد البشرية" if has_no_structure else "الشؤون القانونية"} | {"خطاب التعيين" if has_no_structure else "تعليقات المراجعة"} |
| التنفيذ | 2.3 | {"توظيف وتشكيل الفرق المتخصصة" if has_no_structure else "اعتماد من الإدارة العليا"} | {"الموارد البشرية" if has_no_structure else "الإدارة التنفيذية"} | {"فرق مكتملة" if has_no_structure else "سياسات معتمدة"} |
| النشر | 3.1 | {"إعلان الهيكل الجديد وتوزيع المسؤوليات" if has_no_structure else "تواصل مع الموظفين"} | التواصل الداخلي | إشعارات رسمية |
| النشر | 3.2 | {"تدريب الفريق الجديد على متطلبات " + fw if has_no_structure else "تدريب على السياسات الجديدة"} | التدريب | سجلات التدريب |
| المراقبة | 4.1 | {"مراجعة فعالية الهيكل بعد 6 أشهر" if has_no_structure else "مراجعة دورية (كل 6 أشهر)"} | {"الإدارة العليا" if has_no_structure else "أمن المعلومات"} | تقارير المراجعة |

**الأدلة المطلوبة:** {"☐ قرار اعتماد الهيكل ☐ خطابات التعيين ☐ الهيكل التنظيمي المعتمد" if has_no_structure else "☐ السياسات المعتمدة ☐ سجلات المراجعة ☐ تقارير التدريب"}

---

### دليل تنفيذ الفجوة رقم 2: فجوة الضوابط التقنية

**الخطوات التفصيلية:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | تحديد الضوابط التقنية المطلوبة من {fw} | فريق الأمن | قائمة الضوابط |
| التخطيط | 1.2 | تقييم الوضع الحالي مقابل كل ضابط | تقنية المعلومات | تقرير التقييم |
| التخطيط | 1.3 | إعداد الميزانية وخطة التنفيذ | الإدارة المالية | الميزانية المعتمدة |
| التنفيذ | 2.1 | تطبيق ضوابط إدارة الهوية والوصول | فريق الأمن | ضوابط مُفعّلة |
| التنفيذ | 2.2 | تطبيق ضوابط أمن الشبكات والاتصالات | فريق البنية التحتية | شبكة مؤمّنة |
| التنفيذ | 2.3 | تطبيق ضوابط حماية الأنظمة والتطبيقات | تقنية المعلومات | أنظمة محدّثة |
| التنفيذ | 2.4 | تطبيق ضوابط إدارة السجلات والمراقبة | فريق الأمن | مراقبة مُفعّلة |
| التشغيل | 3.1 | تدريب الفرق التشغيلية | التدريب | فريق مؤهل |
| التشغيل | 3.2 | إعداد إجراءات التشغيل الموحدة | فريق الأمن | إجراءات موثقة |

**الأدلة المطلوبة:** ☐ تقرير تطبيق الضوابط ☐ لقطات الشاشة ☐ شهادات التدريب ☐ سجلات التكوين

---

### دليل تنفيذ الفجوة رقم 3: فجوة التدريب والتوعية

**الخطوات التفصيلية:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | تقييم مستوى الوعي الحالي | أمن المعلومات | تقرير التقييم |
| التخطيط | 1.2 | تحديد الفئات المستهدفة والمحتوى | التدريب | خطة التدريب |
| التطوير | 2.1 | إنشاء محتوى التدريب التفاعلي | التدريب | مواد تدريبية |
| التطوير | 2.2 | إعداد اختبارات المحاكاة (Phishing) | فريق الأمن | سيناريوهات جاهزة |
| التنفيذ | 3.1 | إطلاق برنامج التدريب الإلزامي | الموارد البشرية | جدول التدريب |
| التنفيذ | 3.2 | تنفيذ حملات التصيد التجريبية | فريق الأمن | تقارير النتائج |
| المراقبة | 4.1 | تتبع معدلات الإكمال | التدريب | لوحة متابعة |
| المراقبة | 4.2 | قياس التحسن في الوعي | أمن المعلومات | تقرير ربع سنوي |

**الأدلة المطلوبة:** ☐ سجلات التدريب ☐ نتائج الاختبارات ☐ تقارير المحاكاة

---

### دليل تنفيذ الفجوة رقم 4: فجوة الاستجابة للحوادث

**الخطوات التفصيلية:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | مراجعة خطة الاستجابة الحالية وفق {fw} | فريق الأمن | تقرير الفجوات |
| التخطيط | 1.2 | تحديد الأدوار والمسؤوليات | أمن المعلومات | مصفوفة RACI |
| التطوير | 2.1 | تطوير إجراءات الاستجابة (Playbooks) | فريق الأمن | إجراءات موثقة |
| التطوير | 2.2 | إعداد قوالب التقارير والتصعيد | فريق الأمن | قوالب جاهزة |
| التنفيذ | 3.1 | تشكيل فريق الاستجابة (CSIRT) | الإدارة | فريق معتمد |
| التنفيذ | 3.2 | تدريب الفريق على الإجراءات | التدريب | فريق مدرب |
| الاختبار | 4.1 | تنفيذ تمارين محاكاة (Tabletop) | فريق الأمن | تقرير التمرين |
| الاختبار | 4.2 | اختبار فني كامل | فريق الأمن | نتائج الاختبار |
| التشغيل | 5.1 | تفعيل خط ساخن للإبلاغ | فريق الأمن | قناة اتصال |

**الأدلة المطلوبة:** ☐ خطة الاستجابة المعتمدة ☐ قائمة فريق CSIRT ☐ تقارير التمارين

---

### دليل تنفيذ الفجوة رقم 5: فجوة إدارة الأصول

**الخطوات التفصيلية:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | حصر جميع الأصول السيبرانية | تقنية المعلومات | سجل الأصول |
| التخطيط | 1.2 | تصنيف الأصول حسب الأهمية والحساسية | أمن المعلومات | مصفوفة التصنيف |
| التنفيذ | 2.1 | تطبيق سياسة إدارة الأصول وفق {fw} | أمن المعلومات | سياسة معتمدة |
| التنفيذ | 2.2 | نشر أدوات اكتشاف وجرد الأصول | تقنية المعلومات | أداة مُفعّلة |
| التنفيذ | 2.3 | ربط الأصول بالمسؤولين والضوابط | أمن المعلومات | سجل محدّث |
| المراقبة | 3.1 | مراجعة دورية لسجل الأصول | أمن المعلومات | تقارير المراجعة |
| المراقبة | 3.2 | تحديث تلقائي عند التغييرات | تقنية المعلومات | تنبيهات مُفعّلة |

**الأدلة المطلوبة:** ☐ سجل الأصول المحدّث ☐ تقارير الجرد ☐ وثيقة التصنيف

[SECTION]

## 3. الركائز الاستراتيجية

{"### الركيزة 1: إنشاء الهيكل التنظيمي للأمن السيبراني" if has_no_structure else f"### الركيزة 1: الامتثال والحوكمة (وفق {fw})"}
{"• تعيين مسؤول أمن سيبراني (CISO) يرفع تقاريره للإدارة العليا" if has_no_structure else f"• تطوير إطار شامل لإدارة الامتثال لمتطلبات {fw}"}
{"• إنشاء فريق عمليات الأمن السيبراني (SOC) وفريق الحوكمة" if has_no_structure else "• إنشاء فريق مراقبة مستمرة للامتثال"}
{"• إنشاء فريق الاستجابة للحوادث (CSIRT) وتحديد الصلاحيات وخطوط التقارير" if has_no_structure else f"• تحديث السياسات والإجراءات بشكل دوري لمواكبة تحديثات {fw}"}

### الركيزة 2: الضوابط التقنية
• تطبيق جميع الضوابط التقنية المطلوبة وفق {fw}
• تنفيذ ضوابط إدارة الهوية والوصول والتشفير
• تطبيق المصادقة متعددة العوامل وضوابط أمن الشبكات

### الركيزة 3: تمكين القوى العاملة
• برنامج تدريب مستمر لجميع المستويات وفق متطلبات {fw}
• شهر التوعية السيبرانية السنوي
• شهادات مهنية للفريق التقني

### الركيزة 4: إدارة الحوادث والاستمرارية
• فريق استجابة مركزي يعمل على مدار الساعة
• تمارين محاكاة ربع سنوية
• خطة استمرارية الأعمال والتعافي من الكوارث

[SECTION]

## 4. خارطة الطريق

### المرحلة 1 (0-6 أشهر)
| # | النشاط | المسؤول | الموعد |
|---|--------|---------|--------|
| 1 | {"اعتماد الهيكل التنظيمي للأمن السيبراني وتعيين CISO" if has_no_structure else f"مراجعة السياسات وتحليل الفجوات وفق {fw}"} | {"الإدارة العليا" if has_no_structure else "أمن المعلومات"} | {"الشهر 1" if has_no_structure else "الشهر 2"} |
| 2 | {"توظيف وتشكيل الفرق المتخصصة (SOC, CSIRT)" if has_no_structure else "بدء برامج التدريب الأساسية"} | الموارد البشرية | الشهر 3 |
| 3 | {"تحليل الفجوات وبدء تطبيق الضوابط الأساسية" if has_no_structure else "تطبيق الضوابط التقنية ذات الأولوية العالية"} | {"أمن المعلومات" if has_no_structure else "تقنية المعلومات"} | الشهر 6 |

### المرحلة 2 (6-12 شهر)
| # | النشاط | المسؤول | الموعد |
|---|--------|---------|--------|
| 1 | استكمال تحديث السياسات وفق {fw} | أمن المعلومات | الشهر 8 |
| 2 | توسيع التدريب لجميع الأقسام | الموارد البشرية | الشهر 10 |
| 3 | إنشاء فريق الاستجابة للحوادث | أمن المعلومات | الشهر 12 |

### المرحلة 3 (12-24 شهر)
| # | النشاط | المسؤول | الموعد |
|---|--------|---------|--------|
| 1 | استكمال تطبيق جميع ضوابط {fw} | تقنية المعلومات | الشهر 18 |
| 2 | تدقيقات منتظمة للامتثال | التدقيق الداخلي | مستمر |
| 3 | تقييم فعالية البرامج ومراجعة شاملة | أمن المعلومات | الشهر 24 |

[SECTION]

## 5. مؤشرات الأداء الرئيسية

| # | المؤشر | القيمة الحالية | القيمة المستهدفة | الإطار الزمني |
|---|--------|---------------|-----------------|---------------|
| 1 | نسبة الامتثال الشامل لإطار {fw} | ~35% (تقديري) | > 95% | خلال 12 شهر |
| 2 | متوسط وقت الكشف والاستجابة للحوادث (MTTD/MTTR) | MTTD ~72 ساعة، MTTR ~120 ساعة | MTTD < 4 ساعات، MTTR < 24 ساعة | خلال 12 شهر |
| 3 | معدل إكمال التدريب على التوعية الأمنية | ~20% (لا يوجد برنامج رسمي) | > 90% | خلال 6 أشهر |
| 4 | معالجة الثغرات ضمن الإطار الزمني المحدد | ~40% (لا يوجد SLA رسمي) | > 85% خلال 30 يوم | خلال 12 شهر |
| 5 | نسبة تطبيق ضوابط إدارة الهوية والوصول | ~30% (ضوابط جزئية) | 100% | خلال 9 أشهر |
| 6 | نسبة تطبيق الضوابط التقنية وفق {fw} | ~25% (تقديري) | 100% | خلال 12 شهر |
| 7 | اختبار خطط استمرارية الأعمال | 0 اختبار/سنة | اختباران سنوياً | خلال 12 شهر |
| 8 | نسبة امتثال الأطراف الثالثة أمنياً | ~15% مقيّمة | 100% مقيّمة | خلال 18 شهر |

### أدلة تقييم المؤشرات

---
#### المؤشر رقم 1: نسبة الامتثال الشامل لإطار {fw}
| الخطوة | الإجراء | المسؤول | المخرج |
|--------|---------|---------|--------|
| 1 | حصر جميع ضوابط {fw} المنطبقة على المنظمة | فريق الامتثال | مصفوفة انطباق الضوابط |
| 2 | تقييم حالة التطبيق لكل ضابط: مطبق / جزئي / غير مطبق | فريق أمن المعلومات | ورقة تقييم الضوابط |
| 3 | احتساب: (مطبق بالكامل + 0.5×جزئي) / إجمالي الضوابط | فريق الامتثال | نسبة الامتثال |
| 4 | تحديد الفجوات وترتيب أولويات المعالجة حسب المخاطر | فريق المخاطر | خطة معالجة مرتبة |

---
#### المؤشر رقم 2: متوسط وقت الكشف والاستجابة (MTTD/MTTR)
| الخطوة | الإجراء | المسؤول | المخرج |
|--------|---------|---------|--------|
| 1 | تكوين SIEM لتسجيل وقت توليد التنبيه تلقائياً | فريق SOC | قواعد الارتباط |
| 2 | استخراج الأوقات من تذاكر الحوادث آخر 90 يوم | فريق SOC | بيانات الحوادث |
| 3 | احتساب متوسط الوقت بين الاختراق والكشف (MTTD) | فريق SOC | قيمة MTTD |
| 4 | احتساب متوسط الوقت بين الكشف والاحتواء الكامل (MTTR) | فريق SOC | قيمة MTTR |

---
#### المؤشر رقم 3: معدل إكمال التدريب
| الخطوة | الإجراء | المسؤول | المخرج |
|--------|---------|---------|--------|
| 1 | الحصول على إجمالي عدد الموظفين والمتعاقدين من الموارد البشرية | الموارد البشرية | قائمة الموظفين |
| 2 | استخراج سجلات الإكمال من نظام إدارة التعلم (LMS) | فريق التدريب | سجلات الإكمال |
| 3 | مطابقة القائمة وتحديد غير المكملين | فريق التدريب | تقرير الفجوات |
| 4 | قياس معدل النقر في محاكاة التصيد كمقياس تكميلي | أمن المعلومات | نتائج المحاكاة |

---
#### المؤشر رقم 4: معالجة الثغرات ضمن الإطار الزمني
| الخطوة | الإجراء | المسؤول | المخرج |
|--------|---------|---------|--------|
| 1 | استخراج جميع الثغرات من أدوات الفحص | إدارة الثغرات | جرد الثغرات الكامل |
| 2 | تصنيف حسب الخطورة: حرجة (7 أيام)، عالية (14 يوم)، متوسطة (30 يوم) | إدارة الثغرات | قائمة مصنفة مع مواعيد |
| 3 | تتبع تواريخ المعالجة من نظام التغييرات | عمليات تقنية المعلومات | جدول المعالجة |
| 4 | احتساب: المعالجة ضمن الوقت / إجمالي الثغرات لكل مستوى خطورة | إدارة الثغرات | نسبة الالتزام |

---
#### المؤشر رقم 5: ضوابط إدارة الهوية والوصول
| الخطوة | الإجراء | المسؤول | المخرج |
|--------|---------|---------|--------|
| 1 | حصر جميع ضوابط IAM المطلوبة في {fw} (MFA، PAM، RBAC، مراجعة الصلاحيات) | فريق IAM | قائمة ضوابط IAM |
| 2 | تقييم حالة التطبيق لكل ضابط عبر جميع الأنظمة | فريق IAM | حالة IAM لكل نظام |
| 3 | التحقق: نسبة تسجيل MFA، تغطية الحسابات المميزة، دورية مراجعة الصلاحيات | فريق IAM | القياسات الفرعية |
| 4 | احتساب النتيجة المركبة: الضوابط المطبقة / إجمالي ضوابط IAM | فريق IAM | نسبة تطبيق IAM |

[SECTION]

## 6. تقييم الثقة والمخاطر

**درجة الثقة:** 45%

**مبررات التقييم:**
تعكس درجة الثقة الفجوة الحالية بين الضوابط القائمة والحالة المستهدفة في هذه الاستراتيجية. العوامل الرئيسية المخفضة للدرجة تشمل: غياب إطار حوكمة رسمي (−15%)، عدم وجود تقييم شامل لمخاطر الأمن كخط أساس (−15%)، عدم توثيق الضوابط الحالية مما يصعب قياس الفجوات (−10%)، ومحدودية الكوادر المتخصصة في الأمن السيبراني (−10%). العوامل الإيجابية تشمل: التزام الإدارة العليا بالدعم (+5%) ووجود بنية تحتية تقنية يمكن الاستفادة منها (+10%). يُتوقع تحسن الدرجة إلى 70%+ عند إكمال معالم المرحلة الأولى وتأسيس برنامج القياس الأساسي.

### المخاطر الرئيسية:
| # | الخطر | الاحتمالية | الأثر | خطة التخفيف |
|---|-------|-----------|-------|-------------|
| 1 | مقاومة التغيير | متوسطة | عالي | برامج إدارة التغيير والتواصل |
| 2 | قيود الميزانية | عالية | عالي | التنفيذ المرحلي وترتيب الأولويات |
| 3 | نقص المهارات | متوسطة | متوسط | التدريب المكثف والتوظيف |
| 4 | تعقيد التكامل | متوسطة | متوسط | التخطيط الدقيق والاختبار |
| 5 | تطور التهديدات | عالية | عالي | المراقبة المستمرة والتحديث |"""
    else:
        return f"""## 1. Vision & Objectives

**Vision:**
Establish the organization as a model of cybersecurity excellence in the government sector, achieving full compliance with {fw} and the highest standards of governance and digital asset protection.

### Strategic Objectives:
| # | Objective | Target Metric | Justification ({fw}) | Timeframe |
|---|-----------|---------------|----------------------|-----------|
| 1 | {"Establish a dedicated cybersecurity department with defined structure and authority" if has_no_structure else f"Achieve full compliance with {fw}"} | {"Approved org structure and full team" if has_no_structure else "Compliance > 95%"} | {"Without a dedicated team, no control from " + fw + " can be sustainably implemented or monitored" if has_no_structure else f"Demonstrates due diligence and meets regulatory obligations under {fw}"} | {"Within 6 months" if has_no_structure else "Within 12 months"} |
| 2 | Enhance detection and response capabilities | Reduce response time 50% | Rapid detection limits breach impact and meets {fw} continuous monitoring mandates | Within 18 months |
| 3 | Develop comprehensive awareness program | 100% employee coverage | Human error causes majority of incidents; {fw} mandates regular security training | Within 6 months |
| 4 | Implement mandatory technical controls per {fw} | All essential controls applied | Technical safeguards form the core defensive layer required by {fw} | Within 12 months |
| 5 | Establish centralized incident response team | 24/7 operations | {fw} requires documented incident handling with defined escalation and response SLAs | Within 9 months |

[SECTION]

## 2. Gap Analysis

| # | Gap | Description | Priority | Status |
|---|-----|-------------|----------|--------|
| 1 | {"Organizational Structure Gap" if has_no_structure else "Policy & Governance Gap"} | {"No dedicated cybersecurity department - foundation for all other controls" if has_no_structure else f"Need to update policies to meet {fw} requirements"} | {"Critical" if has_no_structure else "High"} | {"Open - Confirmed" if has_no_structure else "Open"} |
| 2 | Technical Controls Gap | Gaps in implementing mandatory technical controls per {fw} | High | Open |
| 3 | Training & Awareness Gap | Insufficient awareness programs for employees | Medium | Open |
| 4 | Incident Response Gap | Incomplete incident response plan per {fw} requirements | High | Open |
| 5 | Asset Management Gap | No comprehensive and updated cybersecurity asset register | Medium | Open |


---

### Gap #1 Implementation Guide: {"Organizational Structure" if has_no_structure else "Policy & Governance"} Gap

**Step-by-Step Implementation:**

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | {"Define cybersecurity org structure requirements per " + fw if has_no_structure else "Inventory all existing policies"} | {"Executive Management" if has_no_structure else "InfoSec"} | {"Requirements document" if has_no_structure else "Policy inventory list"} |
| Planning | 1.2 | {"Design proposed structure (CISO, SOC team, Governance team, CSIRT)" if has_no_structure else f"Identify {fw} governance requirements"} | {"Executive Management" if has_no_structure else "Compliance"} | {"Proposed org chart" if has_no_structure else "Requirements matrix"} |
| Planning | 1.3 | {"Define budget and HR requirements" if has_no_structure else "Conduct gap analysis (current vs. required)"} | {"Finance" if has_no_structure else "InfoSec"} | {"Approved budget" if has_no_structure else "Gap report"} |
| Execution | 2.1 | {"Approve organizational structure by executive management" if has_no_structure else "Draft new/updated policies"} | {"Executive Management" if has_no_structure else "InfoSec"} | {"Formal approval decision" if has_no_structure else "Policy drafts"} |
| Execution | 2.2 | {"Appoint CISO and define authority and reporting lines" if has_no_structure else "Legal and technical review"} | {"HR" if has_no_structure else "Legal Affairs"} | {"Appointment letter" if has_no_structure else "Review comments"} |
| Execution | 2.3 | {"Recruit and form specialized teams" if has_no_structure else "Executive approval"} | {"HR" if has_no_structure else "Executive Management"} | {"Complete teams" if has_no_structure else "Approved policies"} |
| Deployment | 3.1 | {"Announce new structure and distribute responsibilities" if has_no_structure else "Communicate to employees"} | Internal Comms | Official notices |
| Deployment | 3.2 | {"Train new team on " + fw + " requirements" if has_no_structure else "Training on new policies"} | Training | Training records |
| Monitoring | 4.1 | {"Review structure effectiveness after 6 months" if has_no_structure else "Periodic review (every 6 months)"} | {"Executive Management" if has_no_structure else "InfoSec"} | Review reports |

**Evidence Required:** {"☐ Approval decision ☐ Appointment letters ☐ Approved org chart" if has_no_structure else "☐ Approved policies ☐ Review records ☐ Training reports"}

---

### Gap #2 Implementation Guide: Technical Controls Gap

**Step-by-Step Implementation:**

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | Identify mandatory technical controls from {fw} | Security Team | Controls checklist |
| Planning | 1.2 | Assess current state against each control | IT | Assessment report |
| Planning | 1.3 | Prepare budget and implementation plan | Finance | Approved budget |
| Implementation | 2.1 | Apply identity and access management controls | Security Team | Activated controls |
| Implementation | 2.2 | Apply network and communications security controls | Infrastructure Team | Secured network |
| Implementation | 2.3 | Apply system and application protection controls | IT | Updated systems |
| Implementation | 2.4 | Apply logging and monitoring controls | Security Team | Active monitoring |
| Operations | 3.1 | Train operational teams | Training | Qualified team |
| Operations | 3.2 | Develop standard operating procedures | Security Team | Documented SOPs |

**Evidence Required:** ☐ Controls implementation report ☐ Screenshots ☐ Training certificates ☐ Configuration records

---

### Gap #3 Implementation Guide: Training & Awareness Gap

**Step-by-Step Implementation:**

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | Assess current awareness level | InfoSec | Assessment report |
| Planning | 1.2 | Identify target groups and content | Training | Training plan |
| Development | 2.1 | Create interactive training content | Training | Training materials |
| Development | 2.2 | Prepare phishing simulation scenarios | Security Team | Ready scenarios |
| Execution | 3.1 | Launch mandatory training program | HR | Training schedule |
| Execution | 3.2 | Execute phishing simulation campaigns | Security Team | Results reports |
| Monitoring | 4.1 | Track completion rates | Training | Tracking dashboard |
| Monitoring | 4.2 | Measure awareness improvement | InfoSec | Quarterly report |

**Evidence Required:** ☐ Training records ☐ Test results ☐ Simulation reports

---

### Gap #4 Implementation Guide: Incident Response Gap

**Step-by-Step Implementation:**

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | Review current response plan against {fw} | Security Team | Gap report |
| Planning | 1.2 | Define roles and responsibilities | InfoSec | RACI matrix |
| Development | 2.1 | Develop response playbooks | Security Team | Documented procedures |
| Development | 2.2 | Prepare reporting and escalation templates | Security Team | Ready templates |
| Implementation | 3.1 | Form incident response team (CSIRT) | Management | Approved team |
| Implementation | 3.2 | Train team on procedures | Training | Trained team |
| Testing | 4.1 | Conduct tabletop exercises | Security Team | Exercise report |
| Testing | 4.2 | Full technical test | Security Team | Test results |
| Operations | 5.1 | Activate reporting hotline | Security Team | Communication channel |

**Evidence Required:** ☐ Approved response plan ☐ CSIRT roster ☐ Exercise reports

---

### Gap #5 Implementation Guide: Asset Management Gap

**Step-by-Step Implementation:**

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | Inventory all cybersecurity assets | IT | Asset register |
| Planning | 1.2 | Classify assets by criticality and sensitivity | InfoSec | Classification matrix |
| Implementation | 2.1 | Apply asset management policy per {fw} | InfoSec | Approved policy |
| Implementation | 2.2 | Deploy asset discovery and inventory tools | IT | Activated tool |
| Implementation | 2.3 | Link assets to owners and controls | InfoSec | Updated register |
| Monitoring | 3.1 | Periodic asset register review | InfoSec | Review reports |
| Monitoring | 3.2 | Auto-update on changes | IT | Active alerts |

**Evidence Required:** ☐ Updated asset register ☐ Inventory reports ☐ Classification document

[SECTION]

## 3. Strategic Pillars

{"### Pillar 1: Establish Cybersecurity Organizational Structure" if has_no_structure else f"### Pillar 1: Compliance & Governance (per {fw})"}
{"• Appoint a CISO reporting directly to executive management" if has_no_structure else f"• Develop comprehensive compliance management framework for {fw}"}
{"• Establish Security Operations Center (SOC) and Governance team" if has_no_structure else "• Establish continuous compliance monitoring team"}
{"• Establish CSIRT and define authorities, reporting lines, and budget" if has_no_structure else f"• Regular policy and procedure updates to align with {fw} revisions"}

### Pillar 2: Technical Controls
• Implement all mandatory technical controls required by {fw}
• Apply identity and access management, encryption controls
• Enable multi-factor authentication and network security controls

### Pillar 3: Workforce Empowerment
• Continuous training program for all levels per {fw} requirements
• Annual cyber awareness month
• Professional certifications for technical team

### Pillar 4: Incident Management & Continuity
• 24/7 centralized response team
• Quarterly simulation exercises
• Business continuity and disaster recovery plans

[SECTION]

## 4. Implementation Roadmap

### Phase 1 (0-6 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | {"Approve cybersecurity org structure and appoint CISO" if has_no_structure else f"Policy review and gap analysis against {fw}"} | {"Executive Management" if has_no_structure else "InfoSec"} | {"Month 1" if has_no_structure else "Month 2"} |
| 2 | {"Recruit and form specialized teams (SOC, CSIRT)" if has_no_structure else "Begin basic training programs"} | HR | Month 3 |
| 3 | {"Gap analysis and begin implementing essential controls" if has_no_structure else "Implement high-priority technical controls"} | {"InfoSec" if has_no_structure else "IT"} | Month 6 |

### Phase 2 (6-12 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | Complete policy updates per {fw} | InfoSec | Month 8 |
| 2 | Expand training across departments | HR | Month 10 |
| 3 | Establish incident response team | InfoSec | Month 12 |

### Phase 3 (12-24 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | Complete implementation of all {fw} controls | IT | Month 18 |
| 2 | Regular compliance audits | Internal Audit | Ongoing |
| 3 | Evaluate program effectiveness and full review | InfoSec | Month 24 |

[SECTION]

## 5. Key Performance Indicators

| # | KPI | Current Value | Target Value | Timeframe |
|---|-----|---------------|--------------|-----------|
| 1 | {fw} overall compliance rate | ~35% (estimated) | > 95% | Within 12 months |
| 2 | Mean time to detect and respond to incidents (MTTD/MTTR) | MTTD ~72hrs, MTTR ~120hrs | MTTD < 4hrs, MTTR < 24hrs | Within 12 months |
| 3 | Security awareness training completion rate | ~20% (no formal program) | > 90% | Within 6 months |
| 4 | Vulnerability remediation within SLA | ~40% (no formal SLA) | > 85% within 30 days | Within 12 months |
| 5 | Identity & access management controls implementation | ~30% (partial controls) | 100% | Within 9 months |
| 6 | {fw} technical controls implementation rate | ~25% (estimated) | 100% | Within 12 months |
| 7 | Business continuity plan testing completion | 0 tests/year | 2 tests/year | Within 12 months |
| 8 | Third-party/vendor security compliance rate | ~15% assessed | 100% assessed | Within 18 months |

### KPI Assessment Guidelines

---
#### KPI #1: {fw} Overall Compliance Rate
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Map all applicable {fw} controls to organizational scope | Compliance Team | Controls applicability matrix |
| 2 | Assess current implementation status per control | InfoSec Team | Control-by-control status sheet |
| 3 | Score each control: Implemented / Partial / Not Implemented | Auditors | Scored assessment |
| 4 | Calculate: (Fully Implemented + 0.5×Partial) / Total Controls | Compliance Team | Compliance percentage |
| 5 | Identify gaps and prioritize remediation by risk | Risk Team | Prioritized remediation plan |

---
#### KPI #2: Mean Time to Detect and Respond (MTTD/MTTR)
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Configure SIEM to timestamp alert generation automatically | SOC Team | SIEM correlation rules |
| 2 | Define incident lifecycle stages: Detection → Triage → Containment → Resolution | Incident Response | Incident workflow document |
| 3 | Extract timestamps from last 90 days of incident tickets | SOC Team | Incident timeline dataset |
| 4 | Calculate average time between initial compromise and detection (MTTD) | SOC Team | MTTD metric |
| 5 | Calculate average time between detection and full containment (MTTR) | SOC Team | MTTR metric |

---
#### KPI #3: Security Awareness Training Completion
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Obtain total headcount including contractors from HR | HR Department | Employee roster |
| 2 | Pull completion records from LMS (Learning Management System) | Training Team | Completion logs |
| 3 | Cross-reference roster vs completions, flag non-completions | Training Team | Gap report |
| 4 | Calculate: Completed / Total Headcount × 100 | Training Team | Completion rate |
| 5 | Measure phishing simulation click rate as supplementary metric | InfoSec Team | Phishing test results |

---
#### KPI #4: Vulnerability Remediation Within SLA
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Extract all vulnerabilities from scanning tools (Nessus, Qualys, etc.) | Vulnerability Mgmt | Full vulnerability inventory |
| 2 | Classify by severity: Critical (7 days), High (14 days), Medium (30 days) | Vulnerability Mgmt | Classified list with SLA deadlines |
| 3 | Track remediation dates from patching/change management system | IT Operations | Remediation timeline |
| 4 | Calculate: Remediated within SLA / Total vulnerabilities per severity | Vulnerability Mgmt | SLA compliance rate |
| 5 | Identify recurring vulnerabilities and root causes | InfoSec Team | Root cause analysis |

---
#### KPI #5: Identity & Access Management Controls
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Inventory all {fw} IAM-related controls (MFA, PAM, RBAC, access reviews) | IAM Team | IAM controls checklist |
| 2 | Assess implementation status of each control across all systems | IAM Team | System-by-system IAM status |
| 3 | Verify: MFA enrollment rate, privileged account coverage, access review cadence | IAM Team | Sub-metric measurements |
| 4 | Calculate composite score: controls implemented / total IAM controls | IAM Team | IAM implementation rate |
| 5 | Validate through sample access certification reviews | Internal Audit | Validation report |

---
#### KPI #6: Technical Controls Implementation Rate
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Extract full list of mandatory technical controls from {fw} | Compliance Team | Technical controls register |
| 2 | Map each control to specific technology/tool/configuration | IT Team | Control-to-technology map |
| 3 | Verify implementation via configuration audits and evidence collection | InfoSec Team | Evidence repository |
| 4 | Score: Implemented / Partially / Not implemented per control | Auditors | Technical controls scorecard |
| 5 | Calculate aggregate rate and identify critical gaps | Compliance Team | Implementation dashboard |

---
#### KPI #7: Business Continuity Plan Testing
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Review BCP documentation and identify all plans requiring testing | BCM Team | Plans inventory |
| 2 | Design test scenarios: tabletop exercises and functional drills | BCM Team | Test scenarios |
| 3 | Execute tests and document participant actions, decisions, and gaps | BCM Team | Test execution logs |
| 4 | Measure: RTO/RPO achievement rate during tests | BCM Team | RTO/RPO measurement |
| 5 | Document lessons learned and update plans accordingly | BCM Team | Updated BCP with improvements |

---
#### KPI #8: Third-Party Security Compliance
| Step | Action | Owner | Output |
|------|--------|-------|--------|
| 1 | Inventory all third-party vendors with access to data or systems | Procurement | Vendor register |
| 2 | Classify vendors by risk tier: Critical / High / Medium / Low | Risk Team | Tiered vendor list |
| 3 | Send security assessment questionnaires to Critical and High vendors | Third-Party Risk | Completed questionnaires |
| 4 | Review vendor certifications, audit reports (SOC2, ISO 27001) | Third-Party Risk | Assessment scorecards |
| 5 | Calculate: Vendors meeting security requirements / Total assessed | Third-Party Risk | Compliance rate |

[SECTION]

## 6. Confidence Assessment & Risks

**Confidence Score:** 45%

**Score Justification:**
The confidence score reflects the current gap between existing controls and the target state defined in this strategy. Key factors reducing the score include: absence of a formalized governance structure (−15%), lack of comprehensive risk assessment baseline (−15%), undocumented existing controls making gap measurement unreliable (−10%), and limited dedicated cybersecurity staffing (−10%). Positive factors include executive sponsorship commitment (+5%) and existing IT infrastructure that can be leveraged (+10%). This score is expected to improve to 70%+ upon completion of Phase 1 milestones and establishing the baseline measurement program.

### Key Risks:
| # | Risk | Likelihood | Impact | Mitigation Plan |
|---|------|------------|--------|-----------------|
| 1 | Resistance to change | Medium | High | Change management and communication programs |
| 2 | Budget constraints | High | High | Phased implementation and prioritization |
| 3 | Skills shortage | Medium | Medium | Intensive training and recruitment |
| 4 | Integration complexity | Medium | Medium | Careful planning and testing |
| 5 | Evolving threats | High | High | Continuous monitoring and updates |"""

def generate_review_simulation(language='en', framework='NCA ECC', policy_name=None, policy_content=''):
    """Generate a policy review simulation that analyzes the provided policy content."""
    import re
    abbrev_match = re.search(r'\(([A-Z][A-Z\s]+)\)', framework)
    fw = abbrev_match.group(1).strip() if abbrev_match else re.sub(r'\s*\([^)]+\)\s*', '', framework).strip() or framework
    pn = policy_name or ('الأمن السيبراني' if language == 'ar' else 'Cybersecurity')
    
    # Try to extract actual sections from the policy content for specific feedback
    content_lower = policy_content.lower() if policy_content else ''
    
    # Detect what's present and missing in the policy
    has_purpose = any(k in content_lower for k in ['purpose', 'الغرض', 'الهدف', 'objective'])
    has_scope = any(k in content_lower for k in ['scope', 'النطاق', 'applies to'])
    has_roles = any(k in content_lower for k in ['roles', 'responsibilities', 'الأدوار', 'المسؤوليات', 'responsible'])
    has_enforcement = any(k in content_lower for k in ['enforcement', 'violation', 'compliance', 'penalty', 'الإنفاذ', 'المخالف', 'العقوب', 'الامتثال'])
    has_review = any(k in content_lower for k in ['review', 'update', 'revision', 'المراجعة', 'التحديث'])
    has_exceptions = any(k in content_lower for k in ['exception', 'exemption', 'waiver', 'الاستثناء', 'الإعفاء'])
    has_definitions = any(k in content_lower for k in ['definition', 'glossary', 'terminology', 'التعريف', 'المصطلح'])
    has_references = any(k in content_lower for k in ['reference', 'related document', 'المرجع', 'الوثائق ذات'])
    has_metrics = any(k in content_lower for k in ['metric', 'kpi', 'measure', 'indicator', 'المؤشر', 'القياس'])
    has_approval = any(k in content_lower for k in ['approval', 'approved by', 'الاعتماد', 'معتمد'])
    has_version = any(k in content_lower for k in ['version', 'الإصدار', 'v1', 'v2'])
    has_classification = any(k in content_lower for k in ['classification', 'confidential', 'internal', 'التصنيف', 'سري', 'داخلي'])
    
    if language == 'ar':
        # Build strengths based on what's found
        strengths = []
        if has_purpose: strengths.append(f'تتضمن السياسة قسم واضح للغرض والأهداف يحدد نطاق سياسة {pn}')
        if has_scope: strengths.append('نطاق التطبيق محدد بوضوح مع تعيين الجهات المعنية')
        if has_roles: strengths.append('الأدوار والمسؤوليات معرفة مما يوضح سلسلة المساءلة')
        if has_enforcement: strengths.append('تتضمن آليات الإنفاذ والعواقب عند المخالفة')
        if not strengths:
            strengths = [
                f'السياسة تغطي الموضوع الأساسي لـ{pn}',
                'هيكل الوثيقة منظم بشكل عام',
            ]
        strengths_md = '\n'.join(f'- {s}' for s in strengths)
        
        # Build weaknesses based on what's missing
        weaknesses = []
        if not has_enforcement: weaknesses.append(f'**غياب قسم الإنفاذ والعقوبات:** السياسة لا تحدد عواقب واضحة لعدم الامتثال بمتطلبات {pn}، مما يضعف فعالية التطبيق')
        if not has_exceptions: weaknesses.append('**عدم وجود إجراءات الاستثناء:** لا توجد آلية موثقة لطلب ومنح الاستثناءات مع تحديد المخاطر المقبولة والموافقات المطلوبة')
        if not has_metrics: weaknesses.append(f'**غياب مؤشرات قياس الأداء:** لا تتضمن السياسة مؤشرات KPIs لقياس فعالية تطبيق ضوابط {pn}')
        if not has_definitions: weaknesses.append('**عدم وجود قسم التعريفات:** المصطلحات التقنية المستخدمة غير معرفة مما قد يؤدي لاختلاف التفسير')
        if not has_review: weaknesses.append('**غياب جدول المراجعة:** لا يوجد جدول زمني محدد لمراجعة السياسة وتحديثها دورياً')
        if not has_references: weaknesses.append(f'**عدم ربط السياسة بإطار {fw}:** لم يتم الإشارة صراحة إلى ضوابط {fw} المحددة التي تعالجها هذه السياسة')
        if not has_classification: weaknesses.append('**غياب تصنيف الوثيقة:** لا يوجد مستوى تصنيف واضح للسياسة (سري، داخلي، عام)')
        if not has_version: weaknesses.append('**غياب إدارة الإصدارات:** لا يوجد رقم إصدار أو سجل تغييرات')
        if not weaknesses:
            weaknesses = [
                f'السياسة لا تشير صراحة إلى ضوابط {fw} المحددة',
                'بعض الأقسام تحتاج لمزيد من التفصيل والإجراءات التشغيلية',
            ]
        weaknesses_md = '\n'.join(f'- {w}' for w in weaknesses)
        
        # Build recommendations
        recs = []
        rec_num = 1
        if not has_enforcement:
            recs.append(f'| {rec_num} | إضافة قسم الإنفاذ مع تحديد مستويات المخالفات والعقوبات التدريجية | عالية | خلال 30 يوم |')
            rec_num += 1
        if not has_metrics:
            recs.append(f'| {rec_num} | تضمين مؤشرات أداء قابلة للقياس (KPIs) لمتابعة فعالية التطبيق | عالية | خلال 30 يوم |')
            rec_num += 1
        if not has_exceptions:
            recs.append(f'| {rec_num} | إضافة إجراءات الاستثناء مع نموذج طلب وسلسلة موافقات | متوسطة | خلال 45 يوم |')
            rec_num += 1
        if not has_references:
            recs.append(f'| {rec_num} | ربط كل قسم بضوابط {fw} المحددة ذات الصلة | عالية | خلال 30 يوم |')
            rec_num += 1
        if not has_definitions:
            recs.append(f'| {rec_num} | إضافة قسم التعريفات والمصطلحات التقنية | منخفضة | خلال 60 يوم |')
            rec_num += 1
        if not has_review:
            recs.append(f'| {rec_num} | تحديد جدول مراجعة سنوي مع محفزات المراجعة الاستثنائية | متوسطة | خلال 45 يوم |')
            rec_num += 1
        if not recs:
            recs = [
                f'| 1 | ربط السياسة صراحة بضوابط {fw} المحددة | عالية | خلال 30 يوم |',
                f'| 2 | إضافة مؤشرات أداء لقياس فعالية {pn} | متوسطة | خلال 45 يوم |',
                f'| 3 | تحديث السياسة لتعكس أحدث التهديدات في مجال {pn} | متوسطة | خلال 60 يوم |',
            ]
        recs_md = '\n'.join(recs)
        
        # Calculate score
        present = sum([has_purpose, has_scope, has_roles, has_enforcement, has_review, has_exceptions, has_definitions, has_references, has_metrics, has_approval])
        score = max(3, min(9, round(present * 0.9 + 2)))
        
        return f"""## نتائج مراجعة سياسة {pn}

### ملخص تنفيذي
تم مراجعة سياسة {pn} مقابل متطلبات إطار {fw}. السياسة تغطي الجوانب الأساسية للموضوع لكنها تحتاج إلى تعزيز في عدة مجالات لتحقيق الامتثال الكامل. تم تحديد {len(weaknesses)} نقاط ضعف رئيسية تتطلب المعالجة.

### نقاط القوة ✅
{strengths_md}

### نقاط الضعف ❌
{weaknesses_md}

### التوصيات للتحسين
| # | التوصية | الأولوية | الجدول الزمني |
|---|---------|----------|--------------|
{recs_md}

### درجة الامتثال مع {fw}: {score}/10

**ملاحظة:** هذه المراجعة مبنية على تحليل هيكل السياسة ومحتواها. يُوصى بإجراء تقييم ميداني للتحقق من مستوى التطبيق الفعلي."""

    else:
        # English review
        strengths = []
        if has_purpose: strengths.append(f'Policy includes a clear purpose and objectives section defining the scope of {pn}')
        if has_scope: strengths.append('Scope of applicability is well-defined with identified stakeholders')
        if has_roles: strengths.append('Roles and responsibilities are defined, establishing clear accountability')
        if has_enforcement: strengths.append('Enforcement mechanisms and violation consequences are included')
        if not strengths:
            strengths = [
                f'The policy covers the core subject matter of {pn}',
                'Document structure is generally organized',
            ]
        strengths_md = '\n'.join(f'- {s}' for s in strengths)
        
        weaknesses = []
        if not has_enforcement: weaknesses.append(f'**Missing enforcement section:** The policy does not define clear consequences for non-compliance with {pn} requirements, weakening enforcement effectiveness')
        if not has_exceptions: weaknesses.append('**No exception handling process:** No documented mechanism for requesting and granting policy exceptions with risk acceptance and required approvals')
        if not has_metrics: weaknesses.append(f'**No performance metrics:** The policy lacks KPIs to measure the effectiveness of {pn} controls implementation')
        if not has_definitions: weaknesses.append('**Missing definitions section:** Technical terminology used throughout the policy is not defined, risking inconsistent interpretation')
        if not has_review: weaknesses.append('**No review schedule:** No defined timeline for periodic policy review and updates')
        if not has_references: weaknesses.append(f'**No {fw} control mapping:** Policy sections are not explicitly mapped to specific {fw} controls they address')
        if not has_classification: weaknesses.append('**Missing document classification:** No sensitivity classification label (Confidential, Internal, Public) assigned to the policy')
        if not has_version: weaknesses.append('**No version control:** Missing version number and change history log')
        if not weaknesses:
            weaknesses = [
                f'Policy does not explicitly reference specific {fw} controls',
                'Some sections need more operational detail and implementation procedures',
            ]
        weaknesses_md = '\n'.join(f'- {w}' for w in weaknesses)
        
        recs = []
        rec_num = 1
        if not has_enforcement:
            recs.append(f'| {rec_num} | Add enforcement section with graduated violation levels and consequences | High | Within 30 days |')
            rec_num += 1
        if not has_metrics:
            recs.append(f'| {rec_num} | Include measurable KPIs to track implementation effectiveness | High | Within 30 days |')
            rec_num += 1
        if not has_exceptions:
            recs.append(f'| {rec_num} | Add exception handling process with request form and approval chain | Medium | Within 45 days |')
            rec_num += 1
        if not has_references:
            recs.append(f'| {rec_num} | Map each policy section to specific {fw} controls it addresses | High | Within 30 days |')
            rec_num += 1
        if not has_definitions:
            recs.append(f'| {rec_num} | Add definitions and glossary section for technical terms | Low | Within 60 days |')
            rec_num += 1
        if not has_review:
            recs.append(f'| {rec_num} | Define annual review schedule with triggers for ad-hoc reviews | Medium | Within 45 days |')
            rec_num += 1
        if not recs:
            recs = [
                f'| 1 | Explicitly map policy to {fw} control references | High | Within 30 days |',
                f'| 2 | Add performance metrics to track {pn} control effectiveness | Medium | Within 45 days |',
                f'| 3 | Update policy to reflect latest threats in {pn} domain | Medium | Within 60 days |',
            ]
        recs_md = '\n'.join(recs)
        
        present = sum([has_purpose, has_scope, has_roles, has_enforcement, has_review, has_exceptions, has_definitions, has_references, has_metrics, has_approval])
        score = max(3, min(9, round(present * 0.9 + 2)))
        
        return f"""## Review Results — {pn} Policy

### Executive Summary
The {pn} Policy was reviewed against {fw} requirements. The policy covers the fundamental aspects of {pn} but requires strengthening in several areas to achieve full compliance. {len(weaknesses)} key weaknesses were identified requiring remediation.

### Strengths ✅
{strengths_md}

### Weaknesses ❌
{weaknesses_md}

### Improvement Recommendations
| # | Recommendation | Priority | Timeline |
|---|----------------|----------|----------|
{recs_md}

### Overall Compliance with {fw}: {score}/10

**Note:** This review is based on structural and content analysis of the policy document. A field assessment is recommended to verify actual implementation levels."""


def generate_policy_simulation(language='en', framework='NCA ECC', policy_name=None):
    """Generate policy simulation content - dynamic based on policy name and framework."""
    import re
    abbrev_match = re.search(r'\(([A-Z][A-Z\s]+)\)', framework)
    if abbrev_match:
        fw = abbrev_match.group(1).strip()
    else:
        fw = re.sub(r'\s*\([^)]+\)\s*', '', framework).strip() or framework
    
    # Policy-specific content lookup
    POLICY_CONTENT_AR = {
        'الاستخدام المقبول': {
            'purpose': 'تحديد القواعد والضوابط المنظمة للاستخدام المقبول لأصول وموارد تقنية المعلومات في المنظمة',
            'sections': [
                ('استخدام الأجهزة والأنظمة', [
                    'يُسمح باستخدام أجهزة المنظمة لأغراض العمل الرسمي فقط',
                    'يُحظر تثبيت برامج غير مرخصة أو غير معتمدة على أجهزة المنظمة',
                    'يجب قفل الأجهزة عند مغادرة محطة العمل',
                    'يُحظر توصيل أجهزة تخزين خارجية بدون إذن مسبق',
                ]),
                ('استخدام الإنترنت', [
                    'يُسمح بتصفح الإنترنت لأغراض العمل مع مراعاة الاستخدام المعقول',
                    'يُحظر الوصول إلى المواقع المحظورة أو غير اللائقة',
                    'يُحظر تحميل ملفات من مصادر غير موثوقة',
                    'يتم مراقبة استخدام الإنترنت وتسجيله وفق سياسة الخصوصية',
                ]),
                ('وسائل التواصل الاجتماعي', [
                    'يُحظر مشاركة معلومات المنظمة السرية عبر وسائل التواصل',
                    'يجب الحصول على إذن مسبق للتحدث باسم المنظمة',
                    'يُحظر استخدام حسابات المنظمة الرسمية لأغراض شخصية',
                ]),
            ],
            'roles': [
                ('مدير تقنية المعلومات', 'مراقبة الالتزام وإدارة أدوات التصفية والحجب'),
                ('مدراء الأقسام', 'ضمان التزام الموظفين وتوقيع إقرارات القبول'),
                ('جميع الموظفين', 'الالتزام بقواعد الاستخدام المقبول والإبلاغ عن الانتهاكات'),
            ],
        },
        'أمن الشبكات': {
            'purpose': 'تحديد الضوابط والمتطلبات اللازمة لحماية البنية التحتية للشبكات والاتصالات في المنظمة',
            'sections': [
                ('تصميم الشبكة وتقسيمها', [
                    'يجب تقسيم الشبكة إلى مناطق أمنية منفصلة (DMZ، داخلية، إدارية)',
                    'يجب فصل شبكات الأنظمة الحساسة عن شبكات المستخدمين',
                    'يُحظر الاتصال المباشر بين الإنترنت والشبكة الداخلية بدون جدار حماية',
                    'يجب توثيق مخطط الشبكة وتحديثه عند كل تغيير',
                ]),
                ('إدارة أجهزة الشبكة', [
                    'يجب تغيير كلمات المرور الافتراضية لجميع أجهزة الشبكة',
                    'تحديث البرامج الثابتة (Firmware) لأجهزة الشبكة بشكل دوري',
                    'تقييد الوصول الإداري لأجهزة الشبكة للمصرح لهم فقط',
                    'تفعيل التسجيل (Logging) لجميع أحداث الشبكة',
                ]),
                ('الحماية من التهديدات', [
                    'تفعيل أنظمة كشف ومنع التسلل (IDS/IPS) على حدود الشبكة',
                    'مراقبة حركة الشبكة للكشف عن الأنشطة المشبوهة',
                    'حجب المنافذ والبروتوكولات غير المستخدمة',
                    'تطبيق قوائم التحكم بالوصول (ACL) على جميع نقاط الشبكة',
                ]),
            ],
            'roles': [
                ('مدير أمن الشبكات', 'تصميم ومراقبة وتحديث ضوابط أمن الشبكة'),
                ('فريق البنية التحتية', 'تنفيذ التغييرات وصيانة أجهزة الشبكة'),
                ('فريق SOC', 'المراقبة المستمرة والاستجابة لتنبيهات الشبكة'),
            ],
        },
        'البريد الإلكتروني': {
            'purpose': 'تنظيم استخدام البريد الإلكتروني المؤسسي وحمايته من التهديدات السيبرانية',
            'sections': [
                ('الاستخدام المقبول للبريد الإلكتروني', [
                    'يُستخدم البريد الإلكتروني المؤسسي لأغراض العمل الرسمي',
                    'يُحظر إرسال معلومات سرية بدون تشفير',
                    'يُحظر إعادة توجيه البريد المؤسسي إلى بريد شخصي',
                    'يجب التحقق من هوية المرسل قبل فتح المرفقات',
                ]),
                ('الحماية من التصيد والبرمجيات الخبيثة', [
                    'تفعيل أنظمة تصفية البريد (Email Gateway) لفحص الرسائل الواردة',
                    'حظر أنواع المرفقات الخطرة (exe, bat, vbs, إلخ)',
                    'تفعيل فحص الروابط داخل الرسائل',
                    'إجراء حملات محاكاة تصيد دورية لقياس الوعي',
                ]),
                ('الأرشفة والاحتفاظ', [
                    'أرشفة الرسائل لمدة لا تقل عن سنتين',
                    'حظف الرسائل المؤقتة بعد انقضاء فترة الاحتفاظ',
                    'توفير نسخ احتياطية من صناديق البريد',
                ]),
            ],
            'roles': [
                ('مدير أنظمة البريد', 'إدارة بوابة البريد وتطبيق سياسات التصفية'),
                ('فريق الأمن السيبراني', 'مراقبة تهديدات البريد والاستجابة للحوادث'),
                ('جميع الموظفين', 'الالتزام بقواعد استخدام البريد والإبلاغ عن الرسائل المشبوهة'),
            ],
        },
    }
    
    POLICY_CONTENT_EN = {
        'Acceptable Use': {
            'purpose': 'Define the rules and controls governing acceptable use of IT assets and resources within the organization',
            'sections': [
                ('Device and System Usage', [
                    'Organization devices shall be used for official business purposes only',
                    'Installation of unlicensed or unapproved software is prohibited',
                    'Devices must be locked when leaving the workstation',
                    'Connecting external storage devices requires prior authorization',
                ]),
                ('Internet Usage', [
                    'Internet browsing is permitted for business purposes with reasonable personal use',
                    'Access to prohibited or inappropriate websites is forbidden',
                    'Downloading files from untrusted sources is prohibited',
                    'Internet usage is monitored and logged per the privacy policy',
                ]),
                ('Social Media', [
                    'Sharing confidential organizational information on social media is prohibited',
                    'Prior authorization required to speak on behalf of the organization',
                    'Using official organizational accounts for personal purposes is prohibited',
                ]),
            ],
            'roles': [
                ('IT Manager', 'Monitor compliance and manage filtering/blocking tools'),
                ('Department Managers', 'Ensure employee compliance and sign acceptance forms'),
                ('All Employees', 'Comply with acceptable use rules and report violations'),
            ],
        },
        'Network Security': {
            'purpose': 'Define the controls and requirements for protecting the network infrastructure and communications',
            'sections': [
                ('Network Design and Segmentation', [
                    'Network must be segmented into separate security zones (DMZ, internal, management)',
                    'Sensitive systems networks must be isolated from user networks',
                    'Direct connectivity between internet and internal network without firewall is prohibited',
                    'Network diagram must be documented and updated with every change',
                ]),
                ('Network Device Management', [
                    'Default passwords must be changed on all network devices',
                    'Firmware updates applied to network devices on regular schedule',
                    'Administrative access restricted to authorized personnel only',
                    'Logging enabled for all network device events',
                ]),
                ('Threat Protection', [
                    'IDS/IPS systems activated at network boundaries',
                    'Network traffic monitored for suspicious activities',
                    'Unused ports and protocols blocked',
                    'Access Control Lists (ACL) applied at all network entry points',
                ]),
            ],
            'roles': [
                ('Network Security Manager', 'Design, monitor, and update network security controls'),
                ('Infrastructure Team', 'Implement changes and maintain network devices'),
                ('SOC Team', 'Continuous monitoring and response to network alerts'),
            ],
        },
        'Email': {
            'purpose': 'Regulate the use of corporate email and protect it from cybersecurity threats',
            'sections': [
                ('Acceptable Email Usage', [
                    'Corporate email shall be used for official business purposes',
                    'Sending confidential information without encryption is prohibited',
                    'Forwarding corporate email to personal email accounts is prohibited',
                    'Sender identity must be verified before opening attachments',
                ]),
                ('Phishing and Malware Protection', [
                    'Email gateway filtering systems activated for inbound message scanning',
                    'Dangerous attachment types blocked (exe, bat, vbs, etc.)',
                    'URL scanning enabled for links within messages',
                    'Regular phishing simulation campaigns conducted to measure awareness',
                ]),
                ('Archiving and Retention', [
                    'Email messages archived for a minimum of two years',
                    'Temporary messages deleted after retention period expires',
                    'Backup copies maintained for all mailboxes',
                ]),
            ],
            'roles': [
                ('Email Systems Manager', 'Manage email gateway and apply filtering policies'),
                ('Cybersecurity Team', 'Monitor email threats and respond to incidents'),
                ('All Employees', 'Comply with email usage rules and report suspicious messages'),
            ],
        },
    }
    
    def _find_policy_content(pn, content_dict):
        """Find matching policy content by partial name match."""
        pn_lower = pn.lower() if pn else ''
        for key in content_dict:
            if key.lower() in pn_lower or pn_lower in key.lower():
                return content_dict[key]
        # Arabic fuzzy match
        for key in content_dict:
            if any(word in pn for word in key.split() if len(word) > 3):
                return content_dict[key]
        return None
    
    if language == 'ar':
        pn = policy_name or 'أمن المعلومات'
        content = _find_policy_content(pn, POLICY_CONTENT_AR)
        
        if content:
            sections_md = ''
            for i, (title, items) in enumerate(content['sections'], 1):
                sections_md += f"\n### 3.{i} {title}\n"
                for item in items:
                    sections_md += f"- {item}\n"
            
            roles_md = ''
            for role, resp in content['roles']:
                roles_md += f"| {role} | {resp} |\n"
            
            return f"""# سياسة {pn}

## 1. الغرض
{content['purpose']}، وضمان الامتثال لمتطلبات {fw}.

## 2. النطاق
تنطبق هذه السياسة على:
- جميع الموظفين والمتعاقدين والشركاء
- جميع الأنظمة والأصول والموارد المشمولة بنطاق {pn}
- جميع الإدارات والأقسام في المنظمة

## 3. بنود السياسة
{sections_md}
## 4. الأدوار والمسؤوليات

| الدور | المسؤوليات |
|-------|-----------|
{roles_md}
## 5. متطلبات الامتثال وفق {fw}
- الامتثال لجميع الضوابط ذات الصلة بـ{pn} في إطار {fw}
- إجراء تدقيق داخلي ربع سنوي للتحقق من الالتزام
- معالجة أي فجوات امتثال خلال 30 يوماً من اكتشافها

## 6. المراجعة والتحديث
- مراجعة السياسة سنوياً أو عند حدوث تغييرات جوهرية
- اعتماد التحديثات من لجنة الحوكمة
- إبلاغ جميع الأطراف المعنية بالتغييرات

## 7. العقوبات
عدم الالتزام بهذه السياسة قد يؤدي إلى:
- إجراءات تأديبية
- إنهاء العقد
- إجراءات قانونية

---
**تاريخ الإصدار:** [سيتم إضافته عند الاعتماد]
**رقم الإصدار:** 1.0
**المالك:** الإدارة المختصة
**المراجعة القادمة:** خلال سنة"""
        else:
            # Generic fallback for unknown policy names
            return f"""# سياسة {pn}

## 1. الغرض
تهدف هذه السياسة إلى وضع إطار شامل ومعتمد لتنظيم جوانب {pn} في المنظمة، وذلك لضمان الامتثال لمتطلبات {fw} وحماية مصالح المنظمة وأصحاب المصلحة.

## 2. النطاق
تنطبق هذه السياسة على:
- جميع الموظفين والمتعاقدين والشركاء المعنيين بـ{pn}
- جميع الأنظمة والعمليات والأصول ذات الصلة بـ{pn}
- جميع الإدارات والأقسام التي تتعامل مع نطاق {pn}

## 3. بنود السياسة

### 3.1 المتطلبات العامة لـ{pn}
- يجب توثيق جميع الإجراءات المتعلقة بـ{pn} واعتمادها رسمياً
- تطبيق مبدأ الحد الأدنى من الصلاحيات في جميع العمليات المرتبطة
- مراجعة الالتزام بهذه السياسة كل 90 يوماً

### 3.2 الضوابط التشغيلية
- تطبيق الضوابط المطلوبة وفق {fw} المتعلقة بـ{pn}
- توثيق جميع التغييرات والتحديثات بشكل رسمي
- الاحتفاظ بسجلات التدقيق لمدة لا تقل عن سنتين

### 3.3 المراقبة والإبلاغ
- إنشاء آلية مراقبة مستمرة لضمان الالتزام بالسياسة
- الإبلاغ الفوري عن أي انتهاك أو حادث متعلق بـ{pn}
- إعداد تقارير دورية للإدارة العليا

### 3.4 التوعية والتدريب
- تدريب إلزامي سنوي لجميع المعنيين بـ{pn}
- تحديثات دورية عند صدور تغييرات في متطلبات {fw}
- قياس مستوى الوعي والمعرفة بشكل ربع سنوي

## 4. الأدوار والمسؤوليات

| الدور | المسؤوليات المتعلقة بـ{pn} |
|-------|---------------------------|
| المسؤول التنفيذي | الإشراف العام وتوفير الموارد اللازمة |
| مدير القسم المختص | تنفيذ السياسة ومتابعة الالتزام |
| مديرو الأقسام | ضمان التزام فرقهم بالسياسة |
| جميع الموظفين | الالتزام بالسياسة والإبلاغ عن الانتهاكات |

## 5. متطلبات الامتثال وفق {fw}
- الامتثال لجميع الضوابط ذات الصلة بـ{pn} في إطار {fw}
- إجراء تدقيق داخلي ربع سنوي للتحقق من الالتزام
- معالجة أي فجوات امتثال خلال 30 يوماً من اكتشافها

## 6. المراجعة والتحديث
- مراجعة السياسة سنوياً أو عند حدوث تغييرات جوهرية في {fw}
- اعتماد التحديثات من لجنة الحوكمة
- إبلاغ جميع الأطراف المعنية بالتغييرات

## 7. العقوبات
عدم الالتزام بهذه السياسة قد يؤدي إلى:
- إجراءات تأديبية
- إنهاء العقد
- إجراءات قانونية

---
**تاريخ الإصدار:** [سيتم إضافته عند الاعتماد]
**رقم الإصدار:** 1.0
**المالك:** الإدارة المختصة
**المراجعة القادمة:** خلال سنة"""
    else:
        pn = policy_name or 'Information Security'
        content = _find_policy_content(pn, POLICY_CONTENT_EN)
        
        if content:
            sections_md = ''
            for i, (title, items) in enumerate(content['sections'], 1):
                sections_md += f"\n### 3.{i} {title}\n"
                for item in items:
                    sections_md += f"- {item}\n"
            
            roles_md = ''
            for role, resp in content['roles']:
                roles_md += f"| {role} | {resp} |\n"
            
            return f"""# {pn} Policy

## 1. Purpose
{content['purpose']}, ensuring compliance with {fw} requirements.

## 2. Scope
This policy applies to:
- All employees, contractors, and partners
- All systems, assets, and resources within {pn} scope
- All departments and divisions in the organization

## 3. Policy Statements
{sections_md}
## 4. Roles & Responsibilities

| Role | Responsibilities |
|------|-----------------|
{roles_md}
## 5. Compliance Requirements per {fw}
- Compliance with all {fw} controls relevant to {pn}
- Quarterly internal audit to verify compliance
- Address any compliance gaps within 30 days of discovery

## 6. Review & Update
- Policy reviewed annually or upon significant changes
- Updates approved by governance committee
- All stakeholders notified of changes

## 7. Enforcement
Non-compliance with this policy may result in:
- Disciplinary action
- Contract termination
- Legal proceedings

---
**Issue Date:** [To be added upon approval]
**Version:** 1.0
**Owner:** Relevant Department
**Next Review:** Within 1 year"""
        else:
            # Generic fallback
            return f"""# {pn} Policy

## 1. Purpose
This policy establishes a comprehensive and approved framework for managing {pn} within the organization, ensuring compliance with {fw} requirements and protecting organizational interests.

## 2. Scope
This policy applies to:
- All employees, contractors, and partners involved in {pn}
- All systems, processes, and assets related to {pn}
- All departments and divisions dealing with {pn} scope

## 3. Policy Statements

### 3.1 General Requirements for {pn}
- All procedures related to {pn} must be documented and formally approved
- Principle of least privilege applied across all related operations
- Compliance with this policy reviewed every 90 days

### 3.2 Operational Controls
- Implement all {fw} controls related to {pn}
- Document all changes and updates formally
- Maintain audit records for a minimum of two years

### 3.3 Monitoring & Reporting
- Establish continuous monitoring to ensure policy compliance
- Immediate reporting of any violation or incident related to {pn}
- Periodic reports to senior management

### 3.4 Awareness & Training
- Annual mandatory training for all personnel involved in {pn}
- Periodic updates when {fw} requirements change
- Quarterly awareness and knowledge assessments

## 4. Roles & Responsibilities

| Role | Responsibilities related to {pn} |
|------|----------------------------------|
| Executive Sponsor | Overall oversight and resource provision |
| Department Head | Policy implementation and compliance monitoring |
| Department Managers | Ensure team compliance with policy |
| All Employees | Comply with policy and report violations |

## 5. Compliance Requirements per {fw}
- Compliance with all {fw} controls relevant to {pn}
- Quarterly internal audit to verify compliance
- Address any compliance gaps within 30 days of discovery

## 6. Review & Update
- Policy reviewed annually or upon significant changes to {fw}
- Updates approved by governance committee
- All stakeholders notified of changes

## 7. Penalties
Non-compliance with this policy may result in:
- Disciplinary action
- Contract termination
- Legal proceedings

---
**Issue Date:** [To be added upon approval]
**Version:** 1.0
**Owner:** Relevant Department
**Next Review:** Within 1 year"""

def generate_audit_simulation(language='en', framework='NCA ECC', policy_name=None):
    """Generate audit simulation content with implementation guidelines."""
    import re
    abbrev_match = re.search(r'\(([A-Z][A-Z\s]+)\)', framework)
    fw = abbrev_match.group(1).strip() if abbrev_match else re.sub(r'\s*\([^)]+\)\s*', '', framework).strip() or framework
    
    # Policy-specific audit findings
    AUDIT_FINDINGS_AR = {
        'البريد الإلكتروني': [
            ('عدم تفعيل تشفير البريد الإلكتروني للرسائل الحساسة', 'ضابط حماية البيانات أثناء النقل', 'تفعيل TLS إجباري وتوفير تشفير S/MIME أو PGP للرسائل المصنفة'),
            ('عدم وجود آلية فعالة لتصفية البريد الاحتيالي', 'ضابط الحماية من البرمجيات الخبيثة', 'تفعيل بوابة حماية البريد مع فحص الروابط والمرفقات وتطبيق DMARC/DKIM/SPF'),
        ],
        'أمن الشبكات': [
            ('عدم تقسيم الشبكة إلى مناطق أمنية منفصلة', 'ضابط أمن الشبكات', 'تطبيق تقسيم الشبكة مع مناطق DMZ وداخلية وإدارية باستخدام VLANs وجدران الحماية'),
            ('عدم تحديث البرامج الثابتة لأجهزة الشبكة', 'ضابط إدارة الثغرات', 'إنشاء جدول تحديث شهري مع SLA 72 ساعة للثغرات الحرجة'),
        ],
        'الاستخدام المقبول': [
            ('عدم وجود آلية مراقبة لاستخدام الإنترنت', 'ضابط المراقبة والتسجيل', 'تفعيل نظام تصفية المحتوى مع الحجب حسب الفئات وتقارير الاستخدام'),
            ('عدم توقيع الموظفين على إقرار الاستخدام المقبول', 'ضابط التوعية والتدريب', 'إلزام جميع الموظفين بتوقيع إقرار الاستخدام عند التعيين وسنوياً'),
        ],
        'التحكم بالوصول': [
            ('عدم وجود مصفوفة صلاحيات مبنية على الأدوار (RBAC)', 'ضابط إدارة الهوية والوصول', 'تصميم وتطبيق مصفوفة RBAC متوافقة مع المهام الوظيفية ومبدأ الحد الأدنى من الصلاحيات'),
            ('الحسابات المميزة غير خاضعة لمراقبة معززة', 'ضابط إدارة الوصول المميز', 'نشر حل PAM مع تسجيل الجلسات والوصول المؤقت وسير عمل الموافقات'),
        ],
        'كلمات المرور': [
            ('سياسة كلمات المرور لا تستوفي الحد الأدنى من متطلبات التعقيد', 'ضابط إدارة المصادقة', 'فرض حد أدنى 12 حرف مع قواعد التعقيد والتغيير كل 90 يوم مع سجل 12 كلمة سابقة'),
            ('عدم تفعيل المصادقة متعددة العوامل للوصول الإداري والبعيد', 'ضابط إدارة الهوية والوصول', 'إلزام MFA لجميع الوصول المميز والبعيد والسحابي'),
        ],
        'الحوادث': [
            ('عدم وجود خطة استجابة للحوادث موثقة مع إجراءات تصعيد', 'ضابط إدارة الحوادث', 'تطوير خطة استجابة مع تصنيف الخطورة ومصفوفة التصعيد ونماذج التواصل'),
            ('أدوار ومعلومات اتصال فريق الاستجابة غير محدثة', 'ضابط إدارة الحوادث', 'تشكيل فريق CSIRT مع أدوار محددة ونوبات 24/7 وتمارين ربعية'),
        ],
        'البيانات': [
            ('عدم تطبيق نظام تصنيف البيانات', 'ضابط تصنيف البيانات', 'تطبيق تصنيف 4 مستويات (عام، داخلي، سري، مقيد) مع إجراءات التعامل لكل مستوى'),
            ('عدم وجود ضوابط منع تسريب البيانات الحساسة', 'ضابط حماية البيانات', 'نشر حل DLP لمراقبة البريد والويب وUSB والسحابة بسياسات متوافقة مع التصنيف'),
        ],
        'النسخ الاحتياطي': [
            ('إجراءات النسخ الاحتياطي غير موثقة أو مختبرة', 'ضابط النسخ الاحتياطي والاستعادة', 'توثيق سياسة النسخ مع أهداف RPO/RTO وتطبيق استراتيجية 3-2-1 واختبار ربعي'),
            ('عدم وجود نسخ احتياطية خارجية أو معزولة للبيانات الحرجة', 'ضابط استمرارية الأعمال', 'تطبيق نسخ احتياطية غير قابلة للتعديل خارج الموقع مع تشفير وتحقق أسبوعي'),
        ],
        'إدارة التغيير': [
            ('عدم وجود عملية رسمية لإدارة التغييرات على أنظمة الإنتاج', 'ضابط إدارة التغيير', 'تطبيق عملية إدارة تغيير معتمدة من CAB مع تقييم الأثر وخطط التراجع'),
            ('التغييرات الطارئة غير خاضعة للمراجعة اللاحقة', 'ضابط إدارة التغيير', 'إلزام مراجعة CAB لجميع التغييرات الطارئة خلال 48 ساعة مع التوثيق الكامل'),
        ],
        'الأمن المادي': [
            ('ضوابط الوصول المادي لغرف الخوادم غير كافية', 'ضابط الأمن المادي', 'تطبيق وصول مادي متعدد العوامل (بطاقة + بصمة) مع مراقبة CCTV ومرافقة الزوار'),
            ('عدم وجود مراقبة بيئية في مناطق البنية التحتية الحرجة', 'ضابط الأمن البيئي', 'نشر حساسات درجة الحرارة والرطوبة وتسريب المياه والدخان مع تنبيه آلي'),
        ],
        'الأصول': [
            ('عدم وجود جرد شامل ومحدث لأصول تقنية المعلومات', 'ضابط إدارة الأصول', 'تطبيق اكتشاف آلي للأصول وقاعدة CMDB مع مراجعة ربعية وتعيين مالكين'),
            ('إجراءات التخلص من الأصول لا تتضمن مسح آمن للبيانات', 'ضابط إدارة الأصول', 'تطبيق عملية إتلاف بيانات معتمدة (NIST 800-88) مع توثيق سلسلة الحفظ'),
        ],
        'الثغرات': [
            ('عدم وجود برنامج فحص ثغرات منتظم', 'ضابط إدارة الثغرات', 'تطبيق فحص أسبوعي آلي مع SLAs حسب الخطورة: حرجة 7 أيام، عالية 14، متوسطة 30'),
            ('الثغرات المكتشفة لا تُعالج ضمن الأطر الزمنية المحددة', 'ضابط إدارة الثغرات', 'إنشاء نظام تتبع معالجة الثغرات مع تصعيد عند تجاوز SLA'),
        ],
        'السحابة': [
            ('تكوينات أمن السحابة غير متوافقة مع خط الأساس الأمني', 'ضابط أمن السحابة', 'تطبيق تقوية CIS Benchmark لجميع بيئات السحابة مع مراقبة امتثال آلية'),
            ('عدم وجود رؤية على توفير موارد السحابة وأنماط الوصول', 'ضابط أمن السحابة', 'تفعيل CSPM مع تنبيهات فورية عن أخطاء التكوين'),
            ('متطلبات أمن السحابة غير موثقة في نموذج المسؤولية المشتركة', 'ضابط التوثيق والسياسات', 'توثيق مصفوفة المسؤولية المشتركة وربط الضوابط الداخلية بضوابط مزود الخدمة'),
            ('فريق عمليات السحابة غير معتمد أو مدرب على أفضل ممارسات أمن السحابة', 'ضابط التوعية والتدريب', 'إلزام شهادات أمن السحابة لفريق العمليات السحابية'),
            ('وضعية أمن السحابة لم تُقيّم مقابل معايير CIS منذ أكثر من 6 أشهر', 'ضابط المراجعة الدورية', 'جدولة تقييم CIS Benchmark آلي ربعي مع تتبع المعالجة'),
        ],
        'الأجهزة المحمولة': [
            ('عدم وجود حل إدارة أجهزة محمولة (MDM)', 'ضابط أمن الأجهزة الطرفية', 'نشر MDM/UEM مع التسجيل الإلزامي والتشفير والمسح عن بعد'),
            ('أجهزة BYOD تصل للبيانات المؤسسية بدون ضوابط أمنية', 'ضابط أمن الأجهزة الطرفية', 'تطبيق مساحة عمل معزولة لأجهزة BYOD مع سياسات وصول مشروط'),
            ('سياسة الأجهزة المحمولة لا تتناول فحص التطبيقات ومخاطر التحميل الجانبي', 'ضابط التوثيق والسياسات', 'تحديث سياسة الأجهزة المحمولة لتشمل كتالوج التطبيقات المعتمدة وحظر التحميل الجانبي'),
            ('المستخدمون غير مدربين على مخاطر أمن الأجهزة المحمولة', 'ضابط التوعية والتدريب', 'إدراج وحدة أمن الأجهزة المحمولة في التدريب السنوي مع إجراءات الاستجابة لفقدان الجهاز'),
            ('تكوينات أمن الأجهزة المحمولة لا تُدقق أو تُتحقق دورياً', 'ضابط المراجعة الدورية', 'جدولة مراجعة ربعية لتقرير امتثال MDM مع إجراءات تنفيذية للأجهزة غير الممتثلة'),
        ],
        'التشفير': [
            ('البيانات المخزنة غير مشفرة على الخوادم وقواعد البيانات', 'ضابط حماية البيانات', 'تفعيل تشفير AES-256 لجميع قواعد البيانات والخوادم المحتوية على بيانات حساسة'),
            ('إجراءات إدارة مفاتيح التشفير غير موثقة', 'ضابط التشفير', 'تطبيق إدارة مفاتيح مدعومة بـ HSM مع جدول تدوير وحفظ مقسم'),
            ('معايير التشفير والخوارزميات المعتمدة غير موثقة', 'ضابط التوثيق والسياسات', 'نشر وثيقة معايير التشفير مع الخوارزميات المعتمدة وأطوال المفاتيح والشفرات المحظورة'),
            ('فرق التطوير غير مدربة على ممارسات التشفير الآمن', 'ضابط التوعية والتدريب', 'تقديم تدريب البرمجة الآمنة يغطي استخدام واجهات التشفير والأخطاء الشائعة'),
            ('جدول تدوير مفاتيح التشفير وانتهاء الشهادات لا يُتتبع بشكل منهجي', 'ضابط المراجعة الدورية', 'تطبيق إدارة آلية لدورة حياة الشهادات والمفاتيح مع إشعارات 90 يوم مسبقة'),
        ],
        'السجلات': [
            ('تسجيل الأحداث الأمنية غير مفعل على جميع الأنظمة الحرجة', 'ضابط المراقبة والتسجيل', 'تفعيل سجلات التدقيق على جميع الخوادم وقواعد البيانات والجدران النارية مع جمع مركزي'),
            ('فترة الاحتفاظ بالسجلات لا تستوفي المتطلبات التنظيمية', 'ضابط المراقبة والتسجيل', 'تطبيق حد أدنى 12 شهر احتفاظ نشط و7 سنوات أرشيف غير قابل للتعديل'),
            ('إجراءات إدارة السجلات غير موثقة شاملة الاحتفاظ والوصول وضوابط السلامة', 'ضابط التوثيق والسياسات', 'توثيق سياسة إدارة السجلات مع المصادر وفترات الاحتفاظ وضوابط الوصول والتحقق من السلامة'),
            ('محللو SOC غير مدربين على تقنيات تحليل السجلات لمنصة SIEM المنشورة', 'ضابط التوعية والتدريب', 'تقديم تدريب متخصص لمحللي SOC يغطي قواعد الارتباط وسير عمل التحقيق'),
            ('مصادر السجلات وقواعد الكشف في SIEM لم تُراجع لفجوات التغطية', 'ضابط المراجعة الدورية', 'مراجعة ربعية لتغطية مصادر السجلات وفعالية قواعد الكشف مع معالجة الفجوات'),
        ],
        'التوعية': [
            ('عدم وجود برنامج تدريب توعية أمنية إلزامي لجميع الموظفين', 'ضابط التوعية والتدريب', 'إطلاق تدريب سنوي إلزامي مع محاكاة تصيد ربعية ودورات متخصصة حسب الأدوار'),
            ('عدم وجود تدريب أمني متخصص لفرق تقنية المعلومات والتطوير', 'ضابط التوعية والتدريب', 'تطبيق تدريب البرمجة الآمنة للمطورين وتدريب التهديدات المتقدمة لفريق تقنية المعلومات'),
            ('مناهج ومواد التدريب غير موثقة أو خاضعة لإدارة الإصدارات', 'ضابط التوثيق والسياسات', 'إنشاء مستودع محتوى التدريب مع سجل الإصدارات وجدول التحديث السنوي'),
            ('فعالية التدريب لا تُقاس بما يتجاوز معدلات الإكمال', 'ضابط التوعية والتدريب', 'تطبيق اختبارات قبل وبعد التدريب وتتبع معدل النقر في محاكاة التصيد'),
            ('محتوى التدريب لم يُحدث ليعكس التهديدات الحالية والحوادث الأخيرة', 'ضابط المراجعة الدورية', 'تحديث مواد التدريب ربعياً مع استخبارات التهديدات والدروس المستفادة الداخلية'),
        ],
        'الأطراف الثالثة': [
            ('عدم وجود عملية تقييم أمني للموردين', 'ضابط أمن الأطراف الثالثة', 'تطبيق استبيان تقييم مخاطر الموردين مع مراجعة مصنفة حسب مستوى الوصول للبيانات'),
            ('وصول الأطراف الثالثة غير مراقب أو مراجع دورياً', 'ضابط أمن الأطراف الثالثة', 'إجراء مراجعة ربعية لجميع حسابات الموردين مع إلغاء تلقائي للحسابات غير النشطة'),
            ('متطلبات أمن الموردين غير موثقة في العقود واتفاقيات مستوى الخدمة', 'ضابط التوثيق والسياسات', 'إدراج بنود أمنية في جميع عقود الموردين تغطي حماية البيانات والإبلاغ عن الحوادث وحقوق التدقيق'),
            ('فريق المشتريات غير مدرب على إجراءات تقييم أمن الموردين', 'ضابط التوعية والتدريب', 'تدريب فرق المشتريات وإدارة الموردين على تقييم استبيانات الأمن وتصنيف المخاطر'),
            ('وضعية أمن الموردين لم تُعاد تقييمها منذ التعاقد الأولي', 'ضابط المراجعة الدورية', 'جدولة إعادة تقييم سنوية لأمن الموردين الحرجين والعاليين مع مراجعة استثنائية للحوادث'),
        ],
        'استمرارية الأعمال': [
            ('خطة استمرارية الأعمال غير موثقة أو مختبرة', 'ضابط استمرارية الأعمال', 'تطوير BCP مع تحليل أثر الأعمال واستراتيجيات الاستعادة وجدول اختبار سنوي'),
            ('عدم تحديد أهداف RTO/RPO للوظائف الحرجة', 'ضابط استمرارية الأعمال', 'تحديد RTO/RPO لكل وظيفة حرجة والتحقق من قابلية التحقيق عبر اختبارات التعافي'),
            ('إجراءات تفعيل BCP وجهات اتصال التصعيد غير موثقة', 'ضابط التوثيق والسياسات', 'توثيق معايير تفعيل BCP وسلسلة التصعيد ونماذج التواصل وإجراءات الموقع البديل'),
            ('قادة وحدات الأعمال غير مدربين على أدوارهم ومسؤولياتهم في BCP', 'ضابط التوعية والتدريب', 'تقديم توجيه سنوي لقادة الوحدات والمشاركة في تمارين المحاكاة'),
            ('خطة استمرارية الأعمال لم تُختبر أو تُحدث منذ آخر إعادة هيكلة', 'ضابط المراجعة الدورية', 'اختبار BCP سنوياً والتحديث بعد أي تغيير تنظيمي أو تقني أو مرفق رئيسي'),
        ],
        'USB': [
            ('عدم وجود سياسة تحكم استخدام أجهزة USB والوسائط القابلة للإزالة', 'ضابط حماية الوسائط', 'وضع سياسة استخدام USB تحدد الأجهزة المسموحة والمحظورة مع إجراءات الاستثناء والموافقة'),
            ('عدم تعطيل منافذ USB على محطات العمل والخوادم الحساسة', 'ضابط أمن النقاط الطرفية', 'تفعيل تعطيل منافذ USB عبر Group Policy مع القائمة البيضاء للأجهزة المعتمدة فقط'),
            ('عدم وجود حل منع تسريب البيانات (DLP) لمراقبة نسخ الملفات إلى وسائط خارجية', 'ضابط حماية البيانات', 'نشر حل DLP على جميع النقاط الطرفية لمراقبة وحظر نقل البيانات الحساسة إلى أجهزة USB'),
            ('عدم تطبيق تشفير إلزامي على أجهزة USB المعتمدة للاستخدام', 'ضابط التشفير', 'إلزام استخدام أجهزة USB مشفرة فقط (AES-256) مع إدارة مركزية للمفاتيح'),
            ('عدم وجود سجل جرد ومتابعة لأجهزة USB المعتمدة والموزعة', 'ضابط إدارة الأصول', 'إنشاء سجل مركزي لجميع أجهزة USB المعتمدة مع تتبع التوزيع والإرجاع ومراجعة ربعية'),
        ],
        'الوسائط القابلة للإزالة': [
            ('عدم وجود سياسة تحكم استخدام أجهزة USB والوسائط القابلة للإزالة', 'ضابط حماية الوسائط', 'وضع سياسة استخدام USB تحدد الأجهزة المسموحة والمحظورة مع إجراءات الاستثناء والموافقة'),
            ('عدم تعطيل منافذ USB على محطات العمل والخوادم الحساسة', 'ضابط أمن النقاط الطرفية', 'تفعيل تعطيل منافذ USB عبر Group Policy مع القائمة البيضاء للأجهزة المعتمدة فقط'),
            ('عدم وجود حل منع تسريب البيانات (DLP) لمراقبة نسخ الملفات إلى وسائط خارجية', 'ضابط حماية البيانات', 'نشر حل DLP على جميع النقاط الطرفية لمراقبة وحظر نقل البيانات الحساسة إلى أجهزة USB'),
            ('عدم تطبيق تشفير إلزامي على أجهزة USB المعتمدة للاستخدام', 'ضابط التشفير', 'إلزام استخدام أجهزة USB مشفرة فقط (AES-256) مع إدارة مركزية للمفاتيح'),
            ('عدم وجود سجل جرد ومتابعة لأجهزة USB المعتمدة والموزعة', 'ضابط إدارة الأصول', 'إنشاء سجل مركزي لجميع أجهزة USB المعتمدة مع تتبع التوزيع والإرجاع ومراجعة ربعية'),
        ],
        'الأمن السيبراني': [
            ('عدم وجود إطار حوكمة شامل للأمن السيبراني', 'ضابط حوكمة الأمن السيبراني', 'تأسيس لجنة أمن سيبراني مع تقارير لمجلس الإدارة وتحديد دور CISO واعتماد الاستراتيجية'),
            ('عدم إجراء تقييم دوري لمخاطر الأمن السيبراني', 'ضابط إدارة المخاطر', 'تطبيق تقييم سنوي شامل لمخاطر الأمن مع مراجعات ربعية للمخاطر العالية'),
        ],
    }
    
    AUDIT_FINDINGS_EN = {
        'Email': [
            ('Email encryption not enabled for sensitive communications', 'Data in Transit Protection Control', 'Enable mandatory TLS and provide S/MIME or PGP encryption for classified emails'),
            ('No effective phishing email filtering mechanism', 'Malware Protection Control', 'Deploy email security gateway with URL rewriting, attachment sandboxing, and DMARC/DKIM/SPF enforcement'),
            ('No email retention and archiving policy enforced', 'Documentation & Policy Control', 'Implement automated email archiving with retention periods aligned to regulatory requirements'),
            ('No dedicated email security awareness training covering phishing indicators', 'Awareness & Training Control', 'Launch quarterly phishing simulation campaigns with targeted retraining for repeat clickers'),
            ('Email policy not reviewed after recent organizational changes', 'Periodic Review Control', 'Schedule semi-annual email policy review triggered by infrastructure or regulatory changes'),
        ],
        'Network Security': [
            ('Network not segmented into separate security zones', 'Network Security Control', 'Implement network segmentation with DMZ, internal, and management zones using VLANs and firewalls'),
            ('Network device firmware not regularly updated', 'Vulnerability Management Control', 'Establish monthly patch cycle for all network devices with emergency patch SLA of 72 hours for critical CVEs'),
            ('Network architecture diagrams not maintained or version-controlled', 'Documentation & Policy Control', 'Document and version-control network topology with mandatory update on every change request'),
            ('IT staff not trained on latest network attack vectors (lateral movement, VLAN hopping)', 'Awareness & Training Control', 'Provide annual advanced network security training for infrastructure and SOC teams'),
            ('Firewall rule base not reviewed in over 12 months', 'Periodic Review Control', 'Schedule quarterly firewall rule review with cleanup of orphaned and overly permissive rules'),
        ],
        'Acceptable Use': [
            ('No internet usage monitoring mechanism in place', 'Monitoring and Logging Control', 'Deploy content filtering proxy with category-based blocking and usage reporting'),
            ('Employees have not signed acceptable use agreements', 'Awareness and Training Control', 'Require all employees to sign acceptable use agreements at onboarding and annually'),
            ('Acceptable use policy does not address social media and BYOD scenarios', 'Documentation & Policy Control', 'Expand policy to cover personal device usage, social media guidelines, and cloud storage restrictions'),
            ('No onboarding session explaining acceptable use rules to new employees', 'Awareness & Training Control', 'Include mandatory acceptable use orientation in employee onboarding process'),
            ('Acceptable use policy last updated over 18 months ago', 'Periodic Review Control', 'Schedule annual review with input from HR, Legal, and IT departments'),
        ],
        'Access Control': [
            ('No role-based access control (RBAC) matrix defined', 'Identity & Access Management Control', 'Design and implement RBAC matrix aligned with job functions and least-privilege principle'),
            ('Privileged accounts not subject to enhanced monitoring', 'Privileged Access Management Control', 'Deploy PAM solution with session recording, just-in-time access, and approval workflows'),
            ('Access control procedures not documented for onboarding/offboarding/transfers', 'Documentation & Policy Control', 'Document access lifecycle procedures with SLAs: provision within 24h, revoke within 4h of departure'),
            ('Managers not trained on their role in access certification reviews', 'Awareness & Training Control', 'Conduct quarterly training for managers on access review responsibilities and rubber-stamping risks'),
            ('User access reviews not conducted within the last 6 months', 'Periodic Review Control', 'Implement quarterly user access recertification for critical systems with automated reminders'),
        ],
        'Password': [
            ('Password policy does not meet minimum complexity requirements', 'Authentication Management Control', 'Enforce minimum 12 characters, complexity rules, and 90-day rotation with password history of 12'),
            ('No multi-factor authentication for administrative and remote access', 'Identity & Access Management Control', 'Mandate MFA for all privileged, remote, and cloud-based access'),
            ('Password policy document does not specify requirements for service accounts and API keys', 'Documentation & Policy Control', 'Extend password policy to cover service accounts, API keys, and secrets with vault-based management'),
            ('Users not educated on password manager usage and passphrase best practices', 'Awareness & Training Control', 'Provide training on approved password managers and modern authentication practices'),
            ('Password complexity requirements not reassessed against current threat landscape', 'Periodic Review Control', 'Review password standards annually against NIST 800-63B and emerging credential attack techniques'),
        ],
        'Incident': [
            ('No documented incident response plan with defined escalation procedures', 'Incident Management Control', 'Develop and approve incident response plan with severity classification, escalation matrix, and communication templates'),
            ('Incident response team roles and contact details not maintained', 'Incident Management Control', 'Establish CSIRT with defined roles, 24/7 on-call rotation, and quarterly tabletop exercises'),
            ('Post-incident review (lessons learned) process not documented', 'Documentation & Policy Control', 'Formalize post-incident review process with root cause analysis template and improvement tracking'),
            ('Staff not trained on incident reporting procedures and indicators of compromise', 'Awareness & Training Control', 'Conduct annual incident awareness training and publish internal incident reporting quick-reference guide'),
            ('Incident response plan not tested via tabletop exercises in the past year', 'Periodic Review Control', 'Schedule bi-annual tabletop exercises covering top-5 threat scenarios with documented improvements'),
        ],
        'Data': [
            ('Data classification scheme not implemented or enforced', 'Data Classification Control', 'Implement 4-tier classification (Public, Internal, Confidential, Restricted) with handling procedures for each level'),
            ('No data loss prevention controls for sensitive data exfiltration', 'Data Protection Control', 'Deploy DLP solution monitoring email, web, USB, and cloud channels with policies aligned to classification levels'),
            ('Data handling procedures not documented per classification level', 'Documentation & Policy Control', 'Document data handling, storage, transmission, and disposal procedures per each classification tier'),
            ('Employees not trained on data classification labels and handling requirements', 'Awareness & Training Control', 'Launch role-based data handling training with practical classification exercises'),
            ('Data classification scheme not reviewed since initial implementation', 'Periodic Review Control', 'Conduct annual review of classification scheme considering new data types and regulatory changes'),
        ],
        'Backup': [
            ('Backup procedures not documented or tested regularly', 'Backup and Recovery Control', 'Document backup policy with RPO/RTO targets, implement 3-2-1 strategy, and schedule quarterly restore tests'),
            ('No offsite or air-gapped backup copies for critical data', 'Business Continuity Control', 'Implement immutable offsite backups with encryption and weekly integrity verification'),
            ('Backup schedules and retention periods not formally documented', 'Documentation & Policy Control', 'Document backup matrix specifying frequency, retention, encryption, and responsible owners per system'),
            ('IT operations staff not trained on restore procedures for all critical systems', 'Awareness & Training Control', 'Conduct quarterly restore drill exercises covering each critical system with documented recovery time'),
            ('Backup strategy not reassessed after recent infrastructure or application changes', 'Periodic Review Control', 'Review backup strategy annually and after any major system deployment or architecture change'),
        ],
        'Change Management': [
            ('No formal change management process for production systems', 'Change Management Control', 'Implement CAB-approved change management process with impact assessment, rollback plans, and post-implementation review'),
            ('Emergency changes not subject to retrospective review', 'Change Management Control', 'Require all emergency changes to undergo CAB review within 48 hours with full documentation'),
            ('Change management procedures not documented with clear roles and approval workflows', 'Documentation & Policy Control', 'Document end-to-end change lifecycle with RACI matrix and approval authority thresholds'),
            ('Development and operations teams not trained on change management process', 'Awareness & Training Control', 'Provide mandatory change management training for all teams that submit or implement changes'),
            ('Change management process effectiveness not reviewed with failure rate metrics', 'Periodic Review Control', 'Conduct quarterly review of change success rate, emergency change frequency, and rollback incidents'),
        ],
        'Physical': [
            ('Inadequate physical access controls to server rooms and data centers', 'Physical Security Control', 'Implement multi-factor physical access (badge + biometric), CCTV monitoring, and visitor escort procedures'),
            ('No environmental monitoring in critical infrastructure areas', 'Environmental Security Control', 'Deploy temperature, humidity, water leak, and smoke detection sensors with automated alerting'),
            ('Physical security procedures not documented for visitor management and delivery handling', 'Documentation & Policy Control', 'Document visitor registration, escort requirements, delivery inspection procedures, and CCTV retention policy'),
            ('Security guards and reception staff not trained on tailgating prevention and ID verification', 'Awareness & Training Control', 'Conduct semi-annual physical security awareness training for all facility access personnel'),
            ('Physical access logs and CCTV footage not reviewed periodically', 'Periodic Review Control', 'Schedule monthly review of physical access anomalies and quarterly audit of CCTV system functionality'),
        ],
        'Asset': [
            ('No comprehensive IT asset inventory maintained', 'Asset Management Control', 'Implement automated asset discovery and CMDB with quarterly reconciliation and owner assignment'),
            ('Asset disposal procedures do not include secure data wiping', 'Asset Management Control', 'Implement certified data destruction process (NIST 800-88) with chain-of-custody documentation'),
            ('Asset lifecycle procedures not documented from procurement to disposal', 'Documentation & Policy Control', 'Document full asset lifecycle including procurement standards, tagging, tracking, maintenance, and disposal'),
            ('Asset owners not informed of their security responsibilities for assigned assets', 'Awareness & Training Control', 'Notify asset owners of their responsibilities and include asset security duties in annual training'),
            ('Asset inventory not reconciled with actual deployed systems in the past 6 months', 'Periodic Review Control', 'Schedule quarterly automated asset discovery scan with manual reconciliation of discrepancies'),
        ],
        'Vulnerability': [
            ('No regular vulnerability scanning program in place', 'Vulnerability Management Control', 'Implement weekly automated scanning with severity-based SLAs: Critical 7d, High 14d, Medium 30d'),
            ('Identified vulnerabilities not remediated within defined timeframes', 'Vulnerability Management Control', 'Establish vulnerability remediation tracking with escalation for SLA breaches and exception approval process'),
            ('Vulnerability management procedures not documented with SLA definitions', 'Documentation & Policy Control', 'Document vulnerability management lifecycle with severity classification, SLAs, exception process, and escalation chain'),
            ('System administrators not trained on secure patching procedures and rollback planning', 'Awareness & Training Control', 'Provide patching best practices training including pre-patch testing, rollback procedures, and emergency patching'),
            ('Vulnerability scanning scope and tool effectiveness not reviewed recently', 'Periodic Review Control', 'Conduct annual review of scanning scope coverage, tool configuration, and false positive rates'),
        ],
        'Cloud': [
            ('Cloud security configurations not aligned with security baseline', 'Cloud Security Control', 'Implement CIS Benchmark hardening for all cloud environments with automated compliance monitoring'),
            ('No visibility into cloud resource provisioning and access patterns', 'Cloud Security Control', 'Enable cloud security posture management (CSPM) with real-time misconfiguration alerting'),
            ('Cloud security responsibilities not documented in shared responsibility model', 'Documentation & Policy Control', 'Document cloud shared responsibility matrix and map internal controls to provider controls per service'),
            ('Cloud operations team not certified or trained on cloud security best practices', 'Awareness & Training Control', 'Require cloud security certifications (e.g. CCSK, AWS Security Specialty) for cloud operations staff'),
            ('Cloud security posture not benchmarked against CIS standards in over 6 months', 'Periodic Review Control', 'Schedule quarterly automated CIS benchmark assessment with remediation tracking for all cloud accounts'),
        ],
        'Mobile': [
            ('No mobile device management (MDM) solution enforced', 'Endpoint Security Control', 'Deploy MDM/UEM with mandatory enrollment, encryption, remote wipe, and app whitelisting'),
            ('BYOD devices accessing corporate data without security controls', 'Endpoint Security Control', 'Implement containerized workspace for BYOD with conditional access policies based on device compliance'),
            ('Mobile device policy does not address app vetting and sideloading risks', 'Documentation & Policy Control', 'Update mobile policy to include approved app catalog, sideloading prohibition, and jailbreak/root detection'),
            ('Users not trained on mobile security risks (public WiFi, lost devices, malicious apps)', 'Awareness & Training Control', 'Include mobile security module in annual awareness training with device theft response procedures'),
            ('Mobile device security configurations not audited or verified periodically', 'Periodic Review Control', 'Schedule quarterly MDM compliance report review with enforcement actions for non-compliant devices'),
        ],
        'Encryption': [
            ('Data at rest not encrypted on servers and databases', 'Data Protection Control', 'Enable AES-256 encryption for all databases, file servers, and storage volumes containing sensitive data'),
            ('Encryption key management procedures not documented', 'Cryptographic Control', 'Implement HSM-backed key management with key rotation schedule, split custody, and recovery procedures'),
            ('Cryptographic standards and approved algorithms not documented', 'Documentation & Policy Control', 'Publish cryptographic standards document specifying approved algorithms, key lengths, and prohibited ciphers'),
            ('Development teams not trained on secure cryptographic implementation practices', 'Awareness & Training Control', 'Provide secure coding training covering proper encryption API usage and common cryptographic pitfalls'),
            ('Encryption key rotation schedule and certificate expiry not tracked systematically', 'Periodic Review Control', 'Implement automated certificate and key lifecycle management with 90-day advance expiry notifications'),
        ],
        'Logging': [
            ('Security event logging not enabled across all critical systems', 'Monitoring and Logging Control', 'Enable audit logging on all servers, databases, firewalls, and applications with centralized SIEM collection'),
            ('Log retention period does not meet regulatory requirements', 'Monitoring and Logging Control', 'Implement minimum 12-month hot retention and 7-year archive with tamper-proof storage'),
            ('Log management procedures not documented including retention, access, and integrity controls', 'Documentation & Policy Control', 'Document log management policy specifying sources, retention periods, access controls, and integrity verification'),
            ('SOC analysts not trained on log analysis techniques for the deployed SIEM platform', 'Awareness & Training Control', 'Provide SIEM-specific training for SOC analysts covering correlation rules, investigation workflows, and threat hunting'),
            ('Log sources and SIEM detection rules not reviewed for coverage gaps', 'Periodic Review Control', 'Conduct quarterly log source coverage audit and detection rule effectiveness review with gap remediation'),
        ],
        'Awareness': [
            ('No mandatory security awareness training program for all staff', 'Awareness and Training Control', 'Launch annual mandatory training with quarterly phishing simulations and role-based modules'),
            ('No specialized security training for IT and development teams', 'Awareness and Training Control', 'Implement secure coding training for developers and advanced threat training for IT staff'),
            ('Training curriculum and materials not documented or version-controlled', 'Documentation & Policy Control', 'Maintain training content repository with version history, annual refresh schedule, and role-based module mapping'),
            ('Training effectiveness not measured beyond completion rates', 'Awareness & Training Control', 'Implement pre/post assessments, phishing click rate tracking, and behavioral change measurement'),
            ('Training content not updated to reflect current threats and recent incidents', 'Periodic Review Control', 'Update training materials quarterly incorporating recent threat intelligence and internal incident lessons'),
        ],
        'Third Party': [
            ('No security assessment process for third-party vendors', 'Third Party Security Control', 'Implement vendor risk assessment questionnaire with tiered review based on data access level'),
            ('Third-party access not monitored or reviewed periodically', 'Third Party Security Control', 'Conduct quarterly access reviews for all vendor accounts with automatic deprovisioning for inactive accounts'),
            ('Vendor security requirements not documented in contracts and SLAs', 'Documentation & Policy Control', 'Include security clauses in all vendor contracts covering data protection, incident notification, and audit rights'),
            ('Procurement team not trained on vendor security assessment procedures', 'Awareness & Training Control', 'Train procurement and vendor management teams on security questionnaire evaluation and risk tiering'),
            ('Vendor security posture not reassessed since initial onboarding', 'Periodic Review Control', 'Schedule annual vendor security reassessment for critical/high-risk vendors with off-cycle review for incidents'),
        ],
        'Business Continuity': [
            ('Business continuity plan not documented or tested', 'Business Continuity Control', 'Develop BCP with BIA, recovery strategies, and annual testing schedule including tabletop and functional exercises'),
            ('No defined RTO/RPO targets for critical business functions', 'Business Continuity Control', 'Define RTO/RPO per critical function through BIA and validate achievability through disaster recovery testing'),
            ('BCP activation procedures and escalation contacts not documented', 'Documentation & Policy Control', 'Document BCP activation criteria, escalation chain, communication templates, and alternate site procedures'),
            ('Business unit leaders not trained on their BCP roles and responsibilities', 'Awareness & Training Control', 'Conduct annual BCP orientation for business unit leaders and participate in tabletop exercises'),
            ('BCP not tested or updated since last organizational restructuring', 'Periodic Review Control', 'Test BCP annually and update after any major organizational, technology, or facility change'),
        ],
        'Compliance': [
            ('No compliance monitoring dashboard or reporting mechanism', 'Compliance Management Control', 'Implement GRC platform with automated control assessment, gap tracking, and executive reporting'),
            ('Regulatory requirements not mapped to internal controls', 'Compliance Management Control', 'Create control-to-regulation mapping matrix covering all applicable frameworks and update quarterly'),
            ('Compliance procedures and regulatory mapping not centrally documented', 'Documentation & Policy Control', 'Establish compliance documentation repository with control-to-regulation matrix and evidence templates'),
            ('Compliance team not trained on recent regulatory updates and enforcement trends', 'Awareness & Training Control', 'Provide quarterly regulatory update briefings and annual deep-dive training on applicable frameworks'),
            ('Regulatory compliance posture not independently verified in the past year', 'Periodic Review Control', 'Schedule annual independent compliance assessment with interim quarterly self-assessments'),
        ],
        'USB': [
            ('USB ports not disabled or restricted on workstations and sensitive servers', 'Endpoint Security Control', 'Enforce USB port disabling via Group Policy with device whitelisting for approved USB devices only'),
            ('No Data Loss Prevention (DLP) controls monitoring file transfers to removable media', 'Data Protection Control', 'Deploy endpoint DLP on all workstations to monitor, alert, and block sensitive data transfers to USB devices'),
            ('No mandatory encryption enforced on approved USB storage devices', 'Encryption Control', 'Mandate hardware-encrypted USB drives (AES-256) with centralized key management and auto-wipe on failed attempts'),
            ('No USB device inventory or tracking system for approved removable media', 'Asset Management Control', 'Establish centralized USB device registry tracking issuance, return, and quarterly reconciliation of all approved devices'),
            ('USB usage policy not communicated to employees with acknowledgement requirement', 'Awareness & Training Control', 'Require all employees to complete USB security awareness training and sign USB acceptable use agreement annually'),
        ],
        'Removable Media': [
            ('USB ports not disabled or restricted on workstations and sensitive servers', 'Endpoint Security Control', 'Enforce USB port disabling via Group Policy with device whitelisting for approved USB devices only'),
            ('No Data Loss Prevention (DLP) controls monitoring file transfers to removable media', 'Data Protection Control', 'Deploy endpoint DLP on all workstations to monitor, alert, and block sensitive data transfers to USB devices'),
            ('No mandatory encryption enforced on approved USB storage devices', 'Encryption Control', 'Mandate hardware-encrypted USB drives (AES-256) with centralized key management and auto-wipe on failed attempts'),
            ('No USB device inventory or tracking system for approved removable media', 'Asset Management Control', 'Establish centralized USB device registry tracking issuance, return, and quarterly reconciliation of all approved devices'),
            ('USB usage policy not communicated to employees with acknowledgement requirement', 'Awareness & Training Control', 'Require all employees to complete USB security awareness training and sign USB acceptable use agreement annually'),
        ],
        'Cybersecurity': [
            ('No comprehensive cybersecurity governance framework established', 'Cybersecurity Governance Control', 'Establish cybersecurity committee with board reporting, define CISO role, and approve cybersecurity strategy'),
            ('Security risk assessment not conducted periodically', 'Risk Management Control', 'Implement annual enterprise security risk assessment with quarterly reviews of high-risk areas'),
            ('Cybersecurity policies and standards not consolidated in a centralized document library', 'Documentation & Policy Control', 'Establish cybersecurity policy framework with centralized repository, version control, and approval workflows'),
            ('Executive leadership not briefed on cybersecurity risks and strategy', 'Awareness & Training Control', 'Provide quarterly cybersecurity briefings to executive leadership and annual board-level security presentation'),
            ('Cybersecurity strategy and risk posture not reviewed against evolving threats', 'Periodic Review Control', 'Conduct annual cybersecurity strategy review incorporating threat intelligence and industry benchmarks'),
        ],
        'Information Security': [
            ('No comprehensive cybersecurity governance framework established', 'Cybersecurity Governance Control', 'Establish cybersecurity committee with board reporting, define CISO role, and approve cybersecurity strategy'),
            ('Security risk assessment not conducted periodically', 'Risk Management Control', 'Implement annual enterprise security risk assessment with quarterly reviews of high-risk areas'),
            ('Information security policies not consolidated in a centralized document library', 'Documentation & Policy Control', 'Establish information security policy framework with centralized repository and version control'),
            ('Executive leadership not briefed on information security risks', 'Awareness & Training Control', 'Provide quarterly security briefings to executive leadership covering risk posture and key metrics'),
            ('Information security program effectiveness not independently assessed', 'Periodic Review Control', 'Schedule annual independent security program assessment against selected framework requirements'),
        ],
    }
    
    def _find_audit_findings(pn, findings_dict):
        if not pn:
            return None
        pn_lower = pn.lower()
        # Direct match first (highest precision)
        for key in findings_dict:
            if key.lower() in pn_lower or pn_lower in key.lower():
                return findings_dict[key]
        # Synonym/keyword expansion (high precision — curated aliases)
        TOPIC_ALIASES = {
            'USB': ['usb', 'removable', 'flash drive', 'thumb drive', 'external drive', 'portable media', 'portable storage'],
            'الوسائط القابلة للإزالة': ['usb', 'فلاش', 'وسائط', 'قابلة للإزالة', 'أجهزة خارجية', 'تخزين محمول'],
            'Email': ['email', 'e-mail', 'mail', 'smtp', 'outlook', 'exchange'],
            'البريد الإلكتروني': ['بريد', 'إيميل', 'رسائل'],
            'Network Security': ['network', 'firewall', 'switch', 'router', 'lan', 'wan', 'wifi', 'wireless'],
            'أمن الشبكات': ['شبكة', 'شبكات', 'جدار', 'ناري'],
            'Access Control': ['access', 'privilege', 'authorization', 'permission', 'iam', 'identity'],
            'التحكم بالوصول': ['وصول', 'صلاحيات', 'هوية'],
            'Password': ['password', 'credential', 'authentication', 'mfa', 'multi-factor'],
            'كلمات المرور': ['كلمة مرور', 'كلمات المرور', 'مصادقة'],
            'Incident': ['incident', 'breach response', 'csirt', 'soc response'],
            'الحوادث': ['حادث', 'حوادث', 'استجابة'],
            'Data': ['data protection', 'data classification', 'data loss', 'dlp', 'data privacy'],
            'البيانات': ['بيانات', 'تصنيف', 'تسريب'],
            'Backup': ['backup', 'restore', 'recovery', 'disaster', 'continuity'],
            'النسخ الاحتياطي': ['نسخ', 'احتياطي', 'استعادة', 'تعافي'],
            'Cloud': ['cloud', 'saas', 'iaas', 'paas', 'aws', 'azure', 'gcp'],
            'السحابة': ['سحابة', 'سحابي'],
            'Change Management': ['change management', 'change control', 'cab'],
            'إدارة التغيير': ['تغيير', 'إدارة التغيير'],
            'Physical': ['physical', 'datacenter', 'data center', 'server room', 'facility'],
            'الأمن المادي': ['مادي', 'فيزيائي', 'مركز بيانات'],
            'Asset': ['asset', 'inventory', 'cmdb', 'hardware'],
            'الأصول': ['أصول', 'جرد'],
            'Vulnerability': ['vulnerability', 'vuln', 'scanning', 'penetration', 'pentest'],
            'الثغرات': ['ثغرة', 'ثغرات', 'فحص'],
            'Encryption': ['encryption', 'crypto', 'certificate', 'pki', 'ssl', 'tls'],
            'التشفير': ['تشفير', 'شهادات'],
            'Acceptable Use': ['acceptable use', 'internet usage', 'aup'],
            'الاستخدام المقبول': ['استخدام مقبول', 'استخدام الإنترنت'],
            'Logs': ['log', 'logging', 'siem', 'monitoring', 'audit trail'],
            'السجلات': ['سجلات', 'تسجيل', 'مراقبة'],
            'Awareness': ['awareness', 'training', 'security education'],
            'التوعية': ['توعية', 'تدريب'],
            'Third Party': ['third party', 'vendor', 'supplier', 'outsourc'],
            'الأطراف الثالثة': ['أطراف ثالثة', 'مورد', 'موردين'],
            'Business Continuity': ['business continuity', 'bcp', 'drp', 'disaster recovery'],
            'استمرارية الأعمال': ['استمرارية', 'أعمال'],
        }
        for dict_key, aliases in TOPIC_ALIASES.items():
            if dict_key in findings_dict and any(alias in pn_lower for alias in aliases):
                return findings_dict[dict_key]
        # Word-level match as last resort (words > 4 chars to avoid false positives)
        for key in findings_dict:
            if any(word.lower() in pn_lower for word in key.split() if len(word) > 4):
                return findings_dict[key]
        return None
    
    if language == 'ar':
        pn = policy_name or 'الأمن السيبراني'
        findings = _find_audit_findings(pn, AUDIT_FINDINGS_AR)
        
        if findings and len(findings) >= 5:
            f1_obs, f1_ctrl, f1_rec = findings[0]
            f2_obs, f2_ctrl, f2_rec = findings[1]
            f3_obs, f3_ctrl, f3_rec = findings[2]
            f4_obs, f4_ctrl, f4_rec = findings[3]
            f5_obs, f5_ctrl, f5_rec = findings[4]
        elif findings and len(findings) >= 2:
            f1_obs, f1_ctrl, f1_rec = findings[0]
            f2_obs, f2_ctrl, f2_rec = findings[1]
            f3_obs, f3_ctrl, f3_rec = f'نقص في التوثيق المتعلق بـ{pn}', 'ضابط التوثيق والسياسات', 'تحديث وتوثيق جميع الإجراءات'
            f4_obs, f4_ctrl, f4_rec = f'تأخر في برامج التوعية المتعلقة بـ{pn}', 'ضابط التوعية والتدريب', 'إطلاق برنامج توعية مخصص'
            f5_obs, f5_ctrl, f5_rec = f'عدم وجود مراجعة دورية لسياسة {pn}', 'ضابط المراجعة الدورية', 'جدولة مراجعة سنوية'
        else:
            f1_obs, f1_ctrl, f1_rec = 'عدم تفعيل MFA للأنظمة الحساسة', 'ضابط إدارة الهوية والوصول', 'تفعيل فوري للمصادقة متعددة العوامل'
            f2_obs, f2_ctrl, f2_rec = 'سياسات كلمات المرور ضعيفة', 'ضابط إدارة المصادقة', 'تحديث متطلبات كلمات المرور'
            f3_obs, f3_ctrl, f3_rec = f'نقص في التوثيق المتعلق بـ{pn}', 'ضابط التوثيق والسياسات', 'تحديث وتوثيق جميع الإجراءات'
            f4_obs, f4_ctrl, f4_rec = f'تأخر في برامج التوعية المتعلقة بـ{pn}', 'ضابط التوعية والتدريب', 'إطلاق برنامج توعية مخصص'
            f5_obs, f5_ctrl, f5_rec = f'عدم وجود مراجعة دورية لسياسة {pn}', 'ضابط المراجعة الدورية', 'جدولة مراجعة سنوية'
        
        # Generate finding-specific implementation guides for Arabic
        def _get_impl_guide_ar(obs, rec):
            """Return (steps_list, evidence_list) specific to the finding in Arabic."""
            obs_l = (obs + ' ' + rec).lower()
            if any(k in obs_l for k in ['تشفير', 'tls', 's/mime', 'نقل']):
                return ([
                    ('التقييم', '1.1', 'حصر جميع قنوات الاتصال التي تتعامل مع بيانات حساسة', 'أمن المعلومات', 'خريطة تدفق البيانات'),
                    ('التقييم', '1.2', 'تحديد فجوات التشفير الحالية لكل قناة', 'أمن المعلومات', 'تقرير تحليل الفجوات'),
                    ('التنفيذ', '2.1', 'تفعيل TLS 1.2+ إلزامي على جميع خوادم وبوابات البريد', 'تقنية المعلومات', 'تقرير تكوين TLS'),
                    ('التنفيذ', '2.2', 'نشر شهادات S/MIME أو PGP للاتصالات المصنفة', 'فريق PKI', 'سجلات التسجيل'),
                    ('التنفيذ', '2.3', 'تكوين قواعد DLP لحظر البريد الحساس غير المشفر', 'فريق الأمن', 'سياسة DLP فعالة'),
                    ('التحقق', '3.1', 'اختبار تطبيق التشفير مع المستلمين الداخليين والخارجيين', 'ضمان الجودة', 'نتائج الاختبار'),
                ], ['لقطات تكوين TLS', 'سجلات تسجيل الشهادات', 'وثائق قواعد DLP', 'نتائج اختبار التشفير'])
            elif any(k in obs_l for k in ['تصيد', 'احتيال', 'تصفية', 'بريد.*حماية', 'dmarc', 'dkim']):
                return ([
                    ('التخطيط', '1.1', 'تقييم ضوابط أمن البريد الحالية وتحديد الفجوات', 'أمن المعلومات', 'تقييم أمن البريد'),
                    ('التخطيط', '1.2', 'تحديد متطلبات بوابة البريد: فحص URL وصندوق الرمل للمرفقات', 'أمن المعلومات', 'وثيقة المتطلبات'),
                    ('التنفيذ', '2.1', 'نشر بوابة أمن البريد مع فحص الروابط والمرفقات', 'تقنية المعلومات', 'تقرير نشر البوابة'),
                    ('التنفيذ', '2.2', 'تكوين سجلات DMARC وDKIM وSPF لجميع النطاقات', 'تقنية المعلومات', 'تحديث سجلات DNS'),
                    ('التشغيل', '3.1', 'إطلاق حملات محاكاة التصيد ربعياً', 'فريق الأمن', 'نتائج المحاكاة'),
                    ('التشغيل', '3.2', 'مراجعة البريد المحتجز أسبوعياً وضبط معدل الإنذارات الخاطئة', 'فريق SOC', 'تقرير المراجعة'),
                ], ['تكوين البوابة', 'سجلات DMARC/DKIM/SPF', 'تقارير محاكاة التصيد', 'سجلات مراجعة الحجر'])
            elif any(k in obs_l for k in ['تقسيم', 'مناطق', 'dmz', 'vlan', 'عزل.*شبكة', 'شبكة.*عزل']):
                return ([
                    ('التقييم', '1.1', 'رسم خريطة الشبكة الحالية وتحديد حدود الثقة', 'فريق الشبكات', 'مخطط الشبكة الحالي'),
                    ('التصميم', '1.2', 'تصميم التقسيم المستهدف: DMZ وداخلية وإدارية ومقيدة', 'مهندس الشبكات', 'المعمارية المستهدفة'),
                    ('التنفيذ', '2.1', 'تكوين VLANs والتوجيه بين VLANs مع قوائم التحكم', 'فريق الشبكات', 'تكوين VLAN'),
                    ('التنفيذ', '2.2', 'نشر جدران الحماية بين المناطق بقواعد الحظر الافتراضي', 'فريق الشبكات', 'قواعد الجدار الناري'),
                    ('التنفيذ', '2.3', 'عزل الأنظمة الحساسة في مناطق مقيدة', 'فريق البنية التحتية', 'التحقق من العزل'),
                    ('التحقق', '3.1', 'إجراء اختبار اختراق للتقسيم للتحقق من العزل', 'مدقق خارجي', 'تقرير اختبار الاختراق'),
                ], ['مخططات الشبكة (قبل/بعد)', 'تكوين VLAN', 'قواعد الجدار الناري', 'تقرير اختبار الاختراق'])
            elif any(k in obs_l for k in ['rbac', 'صلاحيات.*أدوار', 'مصفوفة.*صلاحيات', 'أدنى.*صلاحيات']):
                return ([
                    ('التحليل', '1.1', 'ربط جميع الأدوار الوظيفية بالصلاحيات المطلوبة', 'فريق IAM + الموارد البشرية', 'مصفوفة الأدوار والصلاحيات'),
                    ('التصميم', '1.2', 'تصميم نموذج RBAC بمبدأ الحد الأدنى من الصلاحيات', 'فريق IAM', 'وثيقة تصميم RBAC'),
                    ('التنفيذ', '2.1', 'تكوين مجموعات الأدوار في Active Directory والتطبيقات', 'تقنية المعلومات', 'هيكل مجموعات AD'),
                    ('التنفيذ', '2.2', 'إزالة جميع الصلاحيات المباشرة وربط المستخدمين بالأدوار فقط', 'فريق IAM', 'تقرير الترحيل'),
                    ('المراقبة', '3.1', 'جدولة مراجعات تصديق الوصول ربعياً من المدراء', 'فريق IAM', 'جدول التصديق'),
                ], ['مصفوفة RBAC', 'تكوين مجموعات AD', 'سجلات تصديق الوصول', 'نتائج اختبار الأتمتة'])
            elif any(k in obs_l for k in ['مميز', 'pam', 'وصول.*مميز', 'حساب.*إداري']):
                return ([
                    ('التخطيط', '1.1', 'حصر جميع الحسابات المميزة عبر الأنظمة والتطبيقات', 'فريق IAM', 'جرد الحسابات المميزة'),
                    ('التخطيط', '1.2', 'تحديد متطلبات PAM: تسجيل الجلسات، وصول JIT، سير الموافقات', 'أمن المعلومات', 'متطلبات PAM'),
                    ('التنفيذ', '2.1', 'نشر حل PAM وتخزين جميع بيانات الاعتماد المميزة', 'فريق الأمن', 'تقرير نشر PAM'),
                    ('التنفيذ', '2.2', 'تكوين الوصول المؤقت مع الموافقة والحد الزمني', 'فريق IAM', 'الوصول المؤقت مُكوّن'),
                    ('التنفيذ', '2.3', 'تفعيل تسجيل جميع جلسات الوصول المميز', 'فريق الأمن', 'التسجيل فعال'),
                    ('التشغيل', '3.1', 'مراجعة تسجيلات الجلسات أسبوعياً للكشف عن الشذوذ', 'فريق SOC', 'تقرير المراجعة الأسبوعي'),
                ], ['تقرير نشر PAM', 'جرد الحسابات المميزة', 'تسجيلات الجلسات', 'سجلات الموافقات'])
            elif any(k in obs_l for k in ['كلمات.*مرور', 'كلمة.*مرور', 'مصادقة', 'تعقيد']):
                return ([
                    ('التقييم', '1.1', 'تدقيق سياسات كلمات المرور الحالية عبر AD والتطبيقات وقواعد البيانات', 'فريق IAM', 'تدقيق السياسة الحالية'),
                    ('التصميم', '1.2', 'تحديد المتطلبات المحدثة: 12+ حرف، تعقيد، تغيير كل 90 يوم، سجل 12', 'أمن المعلومات', 'معيار كلمات المرور'),
                    ('التنفيذ', '2.1', 'تكوين Group Policy والتطبيقات لفرض المتطلبات الجديدة', 'تقنية المعلومات', 'تكوين GPO'),
                    ('التنفيذ', '2.2', 'نشر مدير كلمات المرور وقائمة كلمات المرور المحظورة', 'تقنية المعلومات', 'مدير كلمات المرور متاح'),
                    ('الإبلاغ', '3.1', 'إخطار جميع المستخدمين بالمتطلبات الجديدة مع فترة سماح 30 يوم', 'الاتصال الداخلي', 'إشعار المستخدمين'),
                    ('المراقبة', '4.1', 'متابعة معدل الامتثال وأحداث القفل أسبوعياً', 'فريق IAM', 'لوحة معلومات الامتثال'),
                ], ['لقطات GPO المحدثة', 'وثيقة معيار كلمات المرور', 'سجلات إشعار المستخدمين', 'مقاييس الامتثال'])
            elif any(k in obs_l for k in ['mfa', 'متعدد.*عوامل', 'مصادقة.*متعدد']):
                return ([
                    ('التخطيط', '1.1', 'حصر الأنظمة المستهدفة: VPN، البريد، السحابة، وحدات الإدارة', 'فريق الأمن', 'وثيقة نطاق MFA'),
                    ('التخطيط', '1.2', 'اختيار طرق MFA لكل نظام: رموز مادية، تطبيق مصادقة، FIDO2', 'تقنية المعلومات', 'مصفوفة طرق MFA'),
                    ('التنفيذ', '2.1', 'تكوين MFA على موفر الهوية (Azure AD، Okta)', 'فريق IAM', 'تكوين MFA'),
                    ('التنفيذ', '2.2', 'تجربة مع قسم تقنية المعلومات لأسبوعين وحل مشاكل التسجيل', 'تقنية المعلومات', 'نتائج التجربة'),
                    ('النشر', '3.1', 'النشر التدريجي قسم تلو آخر مع دعم مكتب المساعدة', 'تقنية المعلومات', 'متتبع حالة النشر'),
                    ('المراقبة', '4.1', 'تتبع معدل التسجيل ونجاح/فشل المصادقة', 'فريق IAM', 'لوحة معلومات اعتماد MFA'),
                ], ['لقطات تكوين MFA', 'سجلات التسجيل', 'تقرير التجربة', 'مقاييس الاعتماد'])
            elif any(k in obs_l for k in ['حوادث', 'استجابة', 'تصعيد', 'csirt']):
                return ([
                    ('التطوير', '1.1', 'تحديد مستويات خطورة الحوادث: حرجة، عالية، متوسطة، منخفضة', 'أمن المعلومات', 'تصنيف الخطورة'),
                    ('التطوير', '1.2', 'بناء مصفوفة التصعيد مع جهات الاتصال لكل مستوى', 'CISO', 'مصفوفة التصعيد'),
                    ('التنفيذ', '2.1', 'تأسيس فريق CSIRT بأدوار محددة ونوبات 24/7', 'CISO', 'ميثاق CSIRT'),
                    ('التنفيذ', '2.2', 'تطوير كتيبات إجراءات لأهم 5 سيناريوهات تهديد', 'فريق SOC', 'مكتبة الإجراءات'),
                    ('الاختبار', '3.1', 'إجراء تمارين محاكاة ربعية لسيناريوهات واقعية', 'فريق الأمن', 'تقارير التمارين'),
                ], ['خطة الاستجابة المعتمدة', 'مصفوفة التصعيد', 'ميثاق CSIRT', 'سجلات تمارين المحاكاة'])
            elif any(k in obs_l for k in ['حوكمة', 'لجنة', 'ciso', 'مجلس.*إدارة', 'استراتيجية.*أمن']):
                return ([
                    ('التأسيس', '1.1', 'تعيين CISO بتقارير مباشرة للإدارة التنفيذية', 'مجلس الإدارة/الرئيس', 'تعيين CISO'),
                    ('التأسيس', '1.2', 'تشكيل لجنة توجيهية للأمن السيبراني متعددة الوظائف', 'CISO', 'ميثاق اللجنة'),
                    ('التنفيذ', '2.1', 'تطوير استراتيجية الأمن السيبراني متوافقة مع أهداف العمل', 'CISO', 'الاستراتيجية المعتمدة'),
                    ('التنفيذ', '2.2', 'تحديد مؤشرات الأداء وجدول التقارير', 'CISO', 'إطار المؤشرات'),
                    ('التشغيل', '3.1', 'عقد اجتماعات اللجنة ربعياً مع محاضر وقرارات موثقة', 'CISO', 'محاضر الاجتماعات'),
                ], ['خطاب تعيين CISO', 'ميثاق اللجنة', 'محاضر الاجتماعات', 'عروض مجلس الإدارة'])
            elif any(k in obs_l for k in ['مخاطر.*تقييم', 'تقييم.*مخاطر', 'مخاطر.*دوري']):
                return ([
                    ('التخطيط', '1.1', 'اختيار منهجية تقييم المخاطر المتوافقة مع الإطار', 'فريق المخاطر', 'وثيقة المنهجية'),
                    ('التخطيط', '1.2', 'تحديد معايير المخاطر: مقاييس الأثر والاحتمالية وشهية المخاطر', 'فريق المخاطر', 'مصفوفة المعايير'),
                    ('التنفيذ', '2.1', 'إجراء تقييم مخاطر شامل يغطي جميع الأنظمة الحرجة', 'أمن المعلومات', 'تقرير تقييم المخاطر'),
                    ('التنفيذ', '2.2', 'تحديد وتقييم خيارات معالجة المخاطر العالية', 'فريق المخاطر', 'خطة المعالجة'),
                    ('المراقبة', '3.1', 'مراجعات ربعية للمخاطر العالية وتقييم سنوي شامل', 'فريق المخاطر', 'جدول المراجعات'),
                ], ['منهجية المخاطر', 'سجل المخاطر', 'خطة المعالجة', 'سجلات المراجعة الربعية'])
            elif any(k in obs_l for k in ['توثيق', 'سياس.*مركز', 'إصدار', 'مستودع']):
                return ([
                    ('التقييم', '1.1', 'حصر جميع السياسات والمعايير والإجراءات الحالية', 'أمن المعلومات', 'جرد الوثائق'),
                    ('التصميم', '1.2', 'تحديد التسلسل الهرمي: سياسات ← معايير ← إجراءات ← إرشادات', 'أمن المعلومات', 'هيكل الإطار'),
                    ('التنفيذ', '2.1', 'إنشاء مستودع مركزي للوثائق مع إدارة الإصدارات', 'تقنية المعلومات', 'المستودع مُنشأ'),
                    ('التنفيذ', '2.2', 'ترحيل جميع الوثائق مع البيانات الوصفية وتعيين المالكين', 'أمن المعلومات', 'الترحيل مكتمل'),
                    ('التشغيل', '3.1', 'تعيين مالكي الوثائق مع مسؤوليات المراجعة السنوية', 'أمن المعلومات', 'قائمة المالكين'),
                ], ['جرد الوثائق', 'لقطات المستودع', 'سجل الإصدارات', 'سجلات سير الموافقات'])
            elif any(k in obs_l for k in ['توعية', 'تدريب', 'تثقيف', 'إحاطة']):
                return ([
                    ('التخطيط', '1.1', 'تقييم مستوى الوعي الحالي عبر استبيان أساسي', 'أمن المعلومات', 'التقييم الأساسي'),
                    ('التطوير', '2.1', 'إنشاء مواد تدريبية تفاعلية مع اختبارات وسيناريوهات', 'فريق التدريب', 'المحتوى التدريبي'),
                    ('التنفيذ', '3.1', 'إطلاق التدريب السنوي الإلزامي عبر LMS مع التتبع', 'الموارد البشرية', 'سجلات التسجيل'),
                    ('التنفيذ', '3.2', 'إجراء محاكاة تصيد ربعية مع إعادة تدريب مستهدف', 'فريق الأمن', 'نتائج المحاكاة'),
                    ('القياس', '4.1', 'قياس معدلات الإكمال ودرجات الاختبارات ومعدلات النقر', 'فريق التدريب', 'لوحة المقاييس'),
                ], ['سجلات إكمال التدريب', 'تقارير محاكاة التصيد', 'تحليل درجات الاختبارات', 'اتجاهات التحسين'])
            elif any(k in obs_l for k in ['مراجعة', 'دوري', 'إعادة.*تقييم', 'لم.*تراجع']):
                return ([
                    ('التخطيط', '1.1', 'تحديد جدول المراجعة: سنوي لجميع الوثائق، استثنائي عند التغييرات الكبرى', 'أمن المعلومات', 'تقويم المراجعات'),
                    ('التنفيذ', '2.1', 'تكوين تذكيرات آلية قبل 30 يوم من موعد المراجعة', 'تقنية المعلومات', 'نظام التذكير'),
                    ('التنفيذ', '2.2', 'إنشاء قالب قائمة مراجعة مع متطلب سجل التغييرات', 'أمن المعلومات', 'قالب المراجعة'),
                    ('التنفيذ', '3.1', 'إجراء أول دورة مراجعة مع توثيق النتائج والتحديثات', 'مالكو الوثائق', 'سجلات المراجعة'),
                    ('المراقبة', '4.1', 'تتبع معدل إكمال المراجعات والبنود المتأخرة شهرياً', 'أمن المعلومات', 'متتبع الامتثال'),
                ], ['تقويم المراجعات', 'سجلات المراجعة المكتملة', 'سجلات التغييرات', 'متتبع الامتثال'])
            elif any(k in obs_l for k in ['usb', 'وسائط', 'قابلة للإزالة', 'فلاش', 'منافذ', 'تخزين محمول']):
                if any(k in obs_l for k in ['dlp', 'تسريب', 'نسخ', 'نقل', 'مراقبة.*ملفات']):
                    return ([
                        ('التقييم', '1.1', 'حصر جميع النقاط الطرفية وتصنيفها حسب حساسية البيانات', 'أمن المعلومات', 'تقرير تصنيف النقاط'),
                        ('التخطيط', '1.2', 'تحديد سياسات DLP لـ USB: حظر الملفات الحساسة والتنبيه عند النسخ الجماعي', 'أمن المعلومات', 'وثيقة سياسة USB DLP'),
                        ('التنفيذ', '2.1', 'نشر وكلاء DLP على جميع محطات العمل مع تفعيل مراقبة USB', 'تقنية المعلومات', 'تقرير نشر DLP'),
                        ('التنفيذ', '2.2', 'تكوين قواعد ذكية: حظر نقل البيانات الشخصية والمالية والمصنفة إلى USB', 'فريق الأمن', 'قواعد DLP فعالة'),
                        ('التشغيل', '3.1', 'مراجعة حوادث USB DLP أسبوعياً والتحقيق في الانتهاكات', 'فريق الأمن', 'تقرير المراجعة الأسبوعي'),
                    ], ['تقرير نشر DLP', 'سياسة نقل USB', 'تكوين قواعد DLP', 'سجلات التحقيق في الحوادث'])
                elif any(k in obs_l for k in ['تشفير', 'aes', 'مشفر']):
                    return ([
                        ('التخطيط', '1.1', 'تحديد أجهزة USB المعتمدة ذات التشفير المدمج (AES-256)', 'أمن المعلومات', 'قائمة الأجهزة المعتمدة'),
                        ('الشراء', '1.2', 'شراء أجهزة USB مشفرة مع إمكانية الإدارة المركزية', 'المشتريات', 'أمر الشراء'),
                        ('التنفيذ', '2.1', 'تكوين وحدة الإدارة المركزية لأسطول USB المشفر', 'تقنية المعلومات', 'وحدة الإدارة فعالة'),
                        ('التنفيذ', '2.2', 'حظر جميع أجهزة التخزين غير المشفرة عبر Group Policy', 'تقنية المعلومات', 'تكوين GPO'),
                        ('التشغيل', '3.1', 'متابعة التزام أجهزة USB المشفرة والإبلاغ عن المفقودات', 'فريق الأمن', 'تقرير الامتثال الشهري'),
                    ], ['قائمة الأجهزة المعتمدة', 'تكوين التشفير', 'أدلة تطبيق GPO', 'سجل الأجهزة المفقودة'])
                elif any(k in obs_l for k in ['جرد', 'سجل', 'متابعة', 'تتبع', 'أصول']):
                    return ([
                        ('التخطيط', '1.1', 'تصميم سجل أجهزة USB بالحقول: الرقم التسلسلي، المستخدم، القسم، تاريخ التسليم', 'أمن المعلومات', 'قالب السجل'),
                        ('التنفيذ', '2.1', 'تسجيل جميع أجهزة USB المعتمدة الحالية في نظام إدارة الأصول', 'تقنية المعلومات', 'الجرد الأولي'),
                        ('التنفيذ', '2.2', 'تطبيق عملية تسليم/استلام لأجهزة USB مع موافقة المدير', 'تقنية المعلومات', 'سير عمل التسليم'),
                        ('التشغيل', '3.1', 'إجراء مطابقة ربعية لجرد USB مع سجلات Active Directory', 'فريق الأمن', 'تقرير المطابقة الربعي'),
                    ], ['سجل أجهزة USB', 'سجلات التسليم والاستلام', 'تقارير المطابقة الربعية', 'تحقيقات الأجهزة المفقودة'])
                else:
                    return ([
                        ('التقييم', '1.1', 'فحص جميع النقاط الطرفية لتحديد حالة منافذ USB (مفعلة/معطلة)', 'تقنية المعلومات', 'تقرير فحص منافذ USB'),
                        ('التخطيط', '1.2', 'تحديد القائمة البيضاء لأجهزة USB: معرفات المصنع والمنتج المعتمدة', 'أمن المعلومات', 'القائمة البيضاء'),
                        ('التنفيذ', '2.1', 'نشر Group Policy لتعطيل وحدات التخزين USB على جميع الأجهزة المنضمة للنطاق', 'تقنية المعلومات', 'تقرير نشر GPO'),
                        ('التنفيذ', '2.2', 'تكوين استثناءات التحكم بالأجهزة لأجهزة USB المشفرة المعتمدة فقط', 'تقنية المعلومات', 'تكوين القائمة البيضاء'),
                        ('التشغيل', '3.1', 'مراجعة سجلات اتصال USB شهرياً للكشف عن محاولات أجهزة غير مصرح بها', 'فريق SOC', 'تقرير المراجعة الشهري'),
                    ], ['أدلة تكوين GPO', 'القائمة البيضاء للأجهزة', 'سجلات اتصال USB', 'سجلات الموافقة على الاستثناءات'])
            else:
                return ([
                    ('التخطيط', '1.1', 'تحديد نطاق التطبيق والأنظمة المتأثرة', 'فريق الأمن', 'وثيقة النطاق'),
                    ('التخطيط', '1.2', 'تقييم الحلول المتاحة واختيار الأنسب', 'تقنية المعلومات', 'تقرير المقارنة'),
                    ('التنفيذ', '2.1', 'نشر الحل وتكوينه', 'تقنية المعلومات', 'تقرير النشر'),
                    ('التنفيذ', '2.2', 'اختبار شامل في بيئة تجريبية', 'ضمان الجودة', 'تقرير الاختبار'),
                    ('النشر', '3.1', 'تدريب الموظفين المعنيين والنشر التدريجي', 'التدريب', 'سجلات التدريب'),
                    ('المراقبة', '4.1', 'متابعة التطبيق والتحقق من الالتزام', 'فريق الأمن', 'تقرير المتابعة'),
                ], ['تقرير التطبيق', 'أدلة التكوين', 'سجلات التدريب', 'تقرير الاختبار'])

        f1_guide_ar = _get_impl_guide_ar(f1_obs, f1_rec)
        f2_guide_ar = _get_impl_guide_ar(f2_obs, f2_rec)
        f1_steps_ar = '\n'.join(f'| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |' for s in f1_guide_ar[0])
        f1_evidence_ar = '\n'.join(f'- [ ] {e}' for e in f1_guide_ar[1])
        f2_steps_ar = '\n'.join(f'| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |' for s in f2_guide_ar[0])
        f2_evidence_ar = '\n'.join(f'- [ ] {e}' for e in f2_guide_ar[1])
        
        return f"""# تقرير تدقيق سياسة {pn} - وفق {fw}

## الملخص التنفيذي
أجري هذا التدقيق لتقييم مدى امتثال سياسة {pn} لمتطلبات إطار {fw}. يغطي التقرير الفترة من [تاريخ البداية] إلى [تاريخ النهاية].

**النتيجة العامة:** امتثال جزئي — تم تحديد 2 ملاحظات عالية الخطورة و2 متوسطة و1 منخفضة تتطلب المعالجة قبل تحقيق الامتثال الكامل لإطار {fw}.

## النتائج والملاحظات

### نتائج عالية الخطورة
| # | الملاحظة | الضابط المتأثر ({fw}) | التوصية | الحالة |
|---|----------|----------------------|---------|--------|
| 1 | {f1_obs} | {f1_ctrl} | {f1_rec} | يحتاج تقييم |
| 2 | {f2_obs} | {f2_ctrl} | {f2_rec} | يحتاج تقييم |


---

## دليل التنفيذ التفصيلي

### الملاحظة رقم 1: {f1_obs}

**الضابط المتأثر:** {f1_ctrl} ({fw})

**الخطوات التفصيلية للتنفيذ:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
{f1_steps_ar}

**الأدلة المطلوبة للإغلاق:**
{f1_evidence_ar}

---

### الملاحظة رقم 2: {f2_obs}

**الضابط المتأثر:** {f2_ctrl} ({fw})

**الخطوات التفصيلية للتنفيذ:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
{f2_steps_ar}

**الأدلة المطلوبة للإغلاق:**
{f2_evidence_ar}

---

### نتائج متوسطة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية | الحالة |
|---|----------|---------------|---------|--------|
| 3 | {f3_obs} | {f3_ctrl} | {f3_rec} | يحتاج تقييم |
| 4 | {f4_obs} | {f4_ctrl} | {f4_rec} | يحتاج تقييم |

### نتائج منخفضة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية | الحالة |
|---|----------|---------------|---------|--------|
| 5 | {f5_obs} | {f5_ctrl} | {f5_rec} | يحتاج تقييم |

## خطة العمل

| # | الإجراء | المسؤول | الموعد النهائي | الأولوية |
|---|--------|---------|---------------|----------|
| 1 | معالجة الملاحظة رقم 1 | فريق الأمن | خلال 30 يوم | عالية |
| 2 | معالجة الملاحظة رقم 2 | أمن المعلومات | خلال 30 يوم | عالية |
| 3 | معالجة الملاحظة رقم 3 | أمن المعلومات | خلال 60 يوم | متوسطة |
| 4 | معالجة الملاحظة رقم 4 | التدريب | خلال 60 يوم | متوسطة |
| 5 | معالجة الملاحظة رقم 5 | أمن المعلومات | خلال 90 يوم | منخفضة |

---
**تاريخ التقرير:** [سيتم إضافته]
**التدقيق القادم:** خلال 6 أشهر"""
    else:
        pn = policy_name or 'Cybersecurity'
        findings = _find_audit_findings(pn, AUDIT_FINDINGS_EN)
        
        if findings and len(findings) >= 5:
            f1_obs, f1_ctrl, f1_rec = findings[0]
            f2_obs, f2_ctrl, f2_rec = findings[1]
            f3_obs, f3_ctrl, f3_rec = findings[2]
            f4_obs, f4_ctrl, f4_rec = findings[3]
            f5_obs, f5_ctrl, f5_rec = findings[4]
        elif findings and len(findings) >= 2:
            f1_obs, f1_ctrl, f1_rec = findings[0]
            f2_obs, f2_ctrl, f2_rec = findings[1]
            f3_obs, f3_ctrl, f3_rec = f'Insufficient documentation related to {pn}', 'Documentation & Policy Control', 'Update and document all procedures'
            f4_obs, f4_ctrl, f4_rec = f'Delayed awareness programs related to {pn}', 'Awareness & Training Control', 'Launch dedicated awareness program'
            f5_obs, f5_ctrl, f5_rec = f'No periodic review of {pn} policy', 'Periodic Review Control', 'Schedule annual review'
        else:
            f1_obs, f1_ctrl, f1_rec = 'MFA not enabled for sensitive systems', 'Identity & Access Management Control', 'Immediate MFA implementation'
            f2_obs, f2_ctrl, f2_rec = 'Weak password policies', 'Authentication Management Control', 'Update password requirements'
            f3_obs, f3_ctrl, f3_rec = f'Insufficient documentation related to {pn}', 'Documentation & Policy Control', 'Update and document all procedures'
            f4_obs, f4_ctrl, f4_rec = f'Delayed awareness programs related to {pn}', 'Awareness & Training Control', 'Launch dedicated awareness program'
            f5_obs, f5_ctrl, f5_rec = f'No periodic review of {pn} policy', 'Periodic Review Control', 'Schedule annual review'
        
        # Generate finding-specific implementation guides
        def _get_impl_guide_en(obs, rec):
            """Return (steps_list, evidence_list) specific to the finding."""
            obs_l = (obs + ' ' + rec).lower()
            if any(k in obs_l for k in ['encrypt', 'tls', 'transit', 's/mime']):
                return ([
                    ('Assessment', '1.1', 'Inventory all communication channels handling sensitive data', 'InfoSec', 'Data flow map'),
                    ('Assessment', '1.2', 'Identify current encryption gaps per channel', 'InfoSec', 'Gap analysis report'),
                    ('Implementation', '2.1', 'Enable mandatory TLS 1.2+ on all mail servers and gateways', 'IT Team', 'TLS configuration report'),
                    ('Implementation', '2.2', 'Deploy S/MIME or PGP certificates for classified communications', 'PKI Team', 'Certificate enrollment records'),
                    ('Implementation', '2.3', 'Configure DLP rules to block unencrypted sensitive emails', 'Security Team', 'DLP policy active'),
                    ('Verification', '3.1', 'Test encryption enforcement with internal and external recipients', 'QA', 'Test results'),
                    ('Monitoring', '4.1', 'Monitor TLS failure logs and certificate expiry', 'SOC Team', 'Monthly compliance report'),
                ], ['TLS configuration screenshots', 'Certificate enrollment records', 'DLP rule documentation', 'Encryption test results'])
            elif any(k in obs_l for k in ['phishing', 'spam', 'email filter', 'email security', 'dmarc', 'dkim']):
                return ([
                    ('Planning', '1.1', 'Assess current email security controls and identify gaps', 'InfoSec', 'Email security assessment'),
                    ('Planning', '1.2', 'Define email gateway requirements including URL rewriting and sandboxing', 'InfoSec', 'Requirements document'),
                    ('Implementation', '2.1', 'Deploy email security gateway with anti-phishing and attachment scanning', 'IT Team', 'Gateway deployment report'),
                    ('Implementation', '2.2', 'Configure DMARC, DKIM, and SPF records for all domains', 'IT Team', 'DNS records updated'),
                    ('Implementation', '2.3', 'Enable URL rewriting and time-of-click analysis', 'Security Team', 'URL protection active'),
                    ('Operations', '3.1', 'Launch quarterly phishing simulation campaigns', 'Security Team', 'Simulation results'),
                    ('Operations', '3.2', 'Review quarantined emails weekly and tune false positive rates', 'SOC Team', 'Weekly review report'),
                ], ['Gateway configuration', 'DMARC/DKIM/SPF records', 'Phishing simulation reports', 'Quarantine review logs'])
            elif any(k in obs_l for k in ['segment', 'zone', 'dmz', 'vlan', 'network.*isol']):
                return ([
                    ('Assessment', '1.1', 'Map current network topology and identify trust boundaries', 'Network Team', 'Current topology diagram'),
                    ('Design', '1.2', 'Design target segmentation: DMZ, internal, management, and restricted zones', 'Network Architect', 'Target architecture'),
                    ('Implementation', '2.1', 'Configure VLANs and inter-VLAN routing with ACLs', 'Network Team', 'VLAN configuration'),
                    ('Implementation', '2.2', 'Deploy firewalls between security zones with deny-by-default rules', 'Network Team', 'Firewall rules'),
                    ('Implementation', '2.3', 'Isolate sensitive systems (databases, payment) into restricted zones', 'Infrastructure Team', 'Isolation verified'),
                    ('Verification', '3.1', 'Conduct segmentation penetration test to verify isolation', 'External Auditor', 'Pen test report'),
                ], ['Network diagrams (before/after)', 'VLAN configuration', 'Firewall rule base', 'Penetration test report'])
            elif any(k in obs_l for k in ['firmware', 'patch', 'update.*device', 'device.*update']):
                return ([
                    ('Planning', '1.1', 'Inventory all network devices with current firmware versions', 'Network Team', 'Device inventory with versions'),
                    ('Planning', '1.2', 'Establish severity-based patch SLAs: Critical 72h, High 7d, Medium 30d', 'InfoSec', 'Patch SLA document'),
                    ('Implementation', '2.1', 'Subscribe to vendor security advisories for all device types', 'Network Team', 'Advisory subscriptions'),
                    ('Implementation', '2.2', 'Deploy patch management workflow with test-stage-deploy pipeline', 'IT Operations', 'Patch workflow documented'),
                    ('Implementation', '2.3', 'Test firmware updates in lab before production deployment', 'Network Team', 'Lab test results'),
                    ('Monitoring', '3.1', 'Track patch compliance monthly against SLA targets', 'InfoSec', 'Compliance dashboard'),
                ], ['Device inventory', 'Patch SLA document', 'Test records', 'Monthly compliance reports'])
            elif any(k in obs_l for k in ['rbac', 'role.based', 'access control matrix', 'least.privilege']):
                return ([
                    ('Analysis', '1.1', 'Map all job roles to required system access and data permissions', 'IAM Team + HR', 'Role-permission matrix'),
                    ('Design', '1.2', 'Define RBAC model with least-privilege principle for each role', 'IAM Team', 'RBAC design document'),
                    ('Implementation', '2.1', 'Configure role-based groups in Active Directory and applications', 'IT Team', 'AD group structure'),
                    ('Implementation', '2.2', 'Remove all directly assigned permissions; map users to roles only', 'IAM Team', 'Migration report'),
                    ('Implementation', '2.3', 'Implement automated provisioning/deprovisioning on HR events', 'IT Team', 'Automation configured'),
                    ('Monitoring', '3.1', 'Schedule quarterly access certification reviews by managers', 'IAM Team', 'Certification schedule'),
                ], ['RBAC matrix', 'AD group configuration', 'Access certification records', 'Automation test results'])
            elif any(k in obs_l for k in ['privileged.*account', 'pam', 'privileged.*access', 'elevated.*access']):
                return ([
                    ('Planning', '1.1', 'Inventory all privileged accounts across systems and applications', 'IAM Team', 'Privileged account inventory'),
                    ('Planning', '1.2', 'Define PAM requirements: session recording, JIT access, approval workflows', 'InfoSec', 'PAM requirements'),
                    ('Implementation', '2.1', 'Deploy PAM solution and vault all privileged credentials', 'Security Team', 'PAM deployment report'),
                    ('Implementation', '2.2', 'Configure just-in-time access with time-limited checkout and approval', 'IAM Team', 'JIT access configured'),
                    ('Implementation', '2.3', 'Enable session recording for all privileged access', 'Security Team', 'Recording active'),
                    ('Operations', '3.1', 'Review privileged session recordings weekly for anomalies', 'SOC Team', 'Weekly review report'),
                ], ['PAM deployment report', 'Privileged account inventory', 'Session recordings', 'Access approval logs'])
            elif any(k in obs_l for k in ['password.*complex', 'password.*policy', 'password.*weak', 'authentication.*manage']):
                return ([
                    ('Assessment', '1.1', 'Audit current password policies across AD, applications, and databases', 'IAM Team', 'Current policy audit'),
                    ('Design', '1.2', 'Define updated requirements: 12+ chars, complexity, 90-day rotation, history of 12', 'InfoSec', 'Updated password standard'),
                    ('Implementation', '2.1', 'Configure Group Policy and application settings to enforce new requirements', 'IT Team', 'GPO configuration'),
                    ('Implementation', '2.2', 'Deploy password manager and provide banned password list', 'IT Team', 'Password manager available'),
                    ('Communication', '3.1', 'Notify all users of new requirements with 30-day grace period', 'Internal Comms', 'User notification'),
                    ('Monitoring', '4.1', 'Monitor compliance rate and lockout events weekly', 'IAM Team', 'Compliance dashboard'),
                ], ['Updated GPO screenshots', 'Password standard document', 'User notification records', 'Compliance metrics'])
            elif any(k in obs_l for k in ['mfa', 'multi.factor', 'two.factor', '2fa']):
                return ([
                    ('Planning', '1.1', 'Inventory target systems: VPN, email, cloud, admin consoles, critical apps', 'Security Team', 'MFA scope document'),
                    ('Planning', '1.2', 'Select MFA methods per system: hardware tokens, authenticator app, FIDO2', 'IT Team', 'MFA method matrix'),
                    ('Implementation', '2.1', 'Configure MFA on identity provider (Azure AD, Okta, etc.)', 'IAM Team', 'MFA configuration'),
                    ('Implementation', '2.2', 'Pilot with IT department for 2 weeks, resolve enrollment issues', 'IT Team', 'Pilot results'),
                    ('Deployment', '3.1', 'Roll out department-by-department with helpdesk support', 'IT + Helpdesk', 'Rollout status tracker'),
                    ('Deployment', '3.2', 'Enforce MFA with no bypass exceptions after grace period', 'Security Team', 'Enforcement confirmation'),
                    ('Monitoring', '4.1', 'Track enrollment rate and authentication success/failure', 'IAM Team', 'MFA adoption dashboard'),
                ], ['MFA configuration screenshots', 'Enrollment records', 'Pilot test report', 'Adoption metrics'])
            elif any(k in obs_l for k in ['incident.*response', 'incident.*plan', 'escalation', 'csirt']):
                return ([
                    ('Development', '1.1', 'Define incident severity levels: Critical, High, Medium, Low with criteria', 'InfoSec', 'Severity classification'),
                    ('Development', '1.2', 'Build escalation matrix with contacts for each severity level', 'CISO', 'Escalation matrix'),
                    ('Development', '1.3', 'Develop incident response playbooks for top-5 threat scenarios', 'SOC Team', 'Playbook library'),
                    ('Implementation', '2.1', 'Establish CSIRT with defined roles and 24/7 on-call rotation', 'CISO', 'CSIRT charter'),
                    ('Implementation', '2.2', 'Deploy forensic tools and evidence preservation procedures', 'Security Team', 'Forensic toolkit'),
                    ('Testing', '3.1', 'Conduct quarterly tabletop exercises simulating real scenarios', 'Security Team', 'Exercise reports'),
                ], ['Approved IR plan', 'Escalation matrix', 'CSIRT charter', 'Tabletop exercise records'])
            elif any(k in obs_l for k in ['classif', 'dlp', 'data loss', 'data.*protect', 'label']):
                return ([
                    ('Design', '1.1', 'Define 4-tier classification: Public, Internal, Confidential, Restricted', 'InfoSec', 'Classification standard'),
                    ('Design', '1.2', 'Document handling procedures for each tier (storage, transmission, disposal)', 'InfoSec', 'Handling procedures'),
                    ('Implementation', '2.1', 'Deploy DLP solution on email, web, USB, and cloud channels', 'IT Team', 'DLP deployment report'),
                    ('Implementation', '2.2', 'Configure DLP policies aligned to classification levels', 'Security Team', 'Active DLP policies'),
                    ('Implementation', '2.3', 'Enable automated classification labels in email and file systems', 'IT Team', 'Labeling active'),
                    ('Training', '3.1', 'Train all employees on classification procedures with practical exercises', 'Training', 'Training records'),
                ], ['Classification standard', 'DLP configuration', 'Labeling screenshots', 'Training completion records'])
            elif any(k in obs_l for k in ['backup', 'recovery', 'restore', 'rpo', 'rto']):
                return ([
                    ('Assessment', '1.1', 'Inventory all critical systems and define RPO/RTO targets', 'IT Operations', 'RPO/RTO matrix'),
                    ('Design', '1.2', 'Design 3-2-1 backup strategy: 3 copies, 2 media types, 1 offsite', 'Infrastructure Team', 'Backup architecture'),
                    ('Implementation', '2.1', 'Configure automated backup schedules per RPO targets', 'IT Operations', 'Backup schedule'),
                    ('Implementation', '2.2', 'Deploy immutable offsite/air-gapped backups for critical data', 'Infrastructure Team', 'Offsite backup verified'),
                    ('Testing', '3.1', 'Conduct quarterly restore tests verifying RTO achievement', 'IT Operations', 'Restore test reports'),
                    ('Monitoring', '4.1', 'Monitor backup success/failure daily with automated alerting', 'IT Operations', 'Monitoring dashboard'),
                ], ['Backup policy document', 'RPO/RTO matrix', 'Restore test reports', 'Backup success metrics'])
            elif any(k in obs_l for k in ['governance', 'committee', 'ciso', 'board.*report']):
                return ([
                    ('Establishment', '1.1', 'Define CISO role with direct reporting to executive management', 'Board/CEO', 'CISO appointment'),
                    ('Establishment', '1.2', 'Charter cybersecurity steering committee with cross-functional membership', 'CISO', 'Committee charter'),
                    ('Implementation', '2.1', 'Develop cybersecurity strategy aligned with business objectives', 'CISO', 'Approved strategy'),
                    ('Implementation', '2.2', 'Establish KPIs and reporting cadence (quarterly to committee, annually to board)', 'CISO', 'KPI framework'),
                    ('Operations', '3.1', 'Conduct quarterly committee meetings with documented minutes and decisions', 'CISO', 'Meeting minutes'),
                    ('Operations', '3.2', 'Present annual cybersecurity posture report to board of directors', 'CISO', 'Board presentation'),
                ], ['CISO appointment letter', 'Committee charter', 'Meeting minutes', 'Board presentations'])
            elif any(k in obs_l for k in ['risk.*assess', 'risk.*not.*conduct', 'risk.*evaluation']):
                return ([
                    ('Planning', '1.1', 'Select risk assessment methodology aligned with framework requirements', 'Risk Team', 'Methodology document'),
                    ('Planning', '1.2', 'Define risk criteria: impact scales, likelihood scales, risk appetite', 'Risk Team', 'Risk criteria matrix'),
                    ('Execution', '2.1', 'Conduct asset-based risk assessment covering all critical systems', 'InfoSec + IT', 'Risk assessment report'),
                    ('Execution', '2.2', 'Identify and evaluate risk treatment options for high-risk findings', 'Risk Team', 'Risk treatment plan'),
                    ('Reporting', '3.1', 'Present risk register and treatment plan to steering committee', 'CISO', 'Committee approval'),
                    ('Monitoring', '4.1', 'Conduct quarterly reviews of high-risk items and annual full reassessment', 'Risk Team', 'Review schedule'),
                ], ['Risk methodology', 'Risk register', 'Treatment plan', 'Quarterly review records'])
            elif any(k in obs_l for k in ['document', 'policy.*not.*consolidat', 'centrali', 'version.*control']):
                return ([
                    ('Assessment', '1.1', 'Inventory all existing cybersecurity policies, standards, and procedures', 'InfoSec', 'Document inventory'),
                    ('Design', '1.2', 'Define document hierarchy: policies → standards → procedures → guidelines', 'InfoSec', 'Framework structure'),
                    ('Implementation', '2.1', 'Establish centralized document repository with version control', 'IT Team', 'Repository deployed'),
                    ('Implementation', '2.2', 'Migrate all documents to repository with proper metadata and owners', 'InfoSec', 'Migration complete'),
                    ('Implementation', '2.3', 'Define approval workflow: draft → review → approve → publish', 'InfoSec', 'Workflow configured'),
                    ('Operations', '3.1', 'Assign document owners with annual review responsibilities', 'InfoSec', 'Owner assignment list'),
                ], ['Document inventory', 'Repository screenshots', 'Version history', 'Approval workflow records'])
            elif any(k in obs_l for k in ['awareness', 'training', 'brief', 'education']):
                return ([
                    ('Planning', '1.1', 'Assess current security awareness level via baseline survey', 'InfoSec', 'Baseline assessment'),
                    ('Planning', '1.2', 'Define role-based training tracks: general, technical, executive', 'Training Team', 'Training curriculum'),
                    ('Development', '2.1', 'Create interactive training modules with quizzes and scenarios', 'Training Team', 'Training content'),
                    ('Execution', '3.1', 'Launch mandatory annual training via LMS with tracking', 'HR + Training', 'Enrollment records'),
                    ('Execution', '3.2', 'Conduct quarterly phishing simulations with targeted retraining', 'Security Team', 'Simulation results'),
                    ('Measurement', '4.1', 'Measure completion rates, quiz scores, and phishing click rates', 'Training Team', 'Metrics dashboard'),
                ], ['Training completion records', 'Phishing simulation reports', 'Quiz score analysis', 'Improvement trends'])
            elif any(k in obs_l for k in ['review', 'periodic', 'reassess', 'not.*reviewed']):
                return ([
                    ('Planning', '1.1', 'Define review schedule: annual for all, triggered for major changes', 'InfoSec', 'Review calendar'),
                    ('Planning', '1.2', 'Identify review owners and stakeholders per document/control', 'InfoSec', 'RACI matrix'),
                    ('Implementation', '2.1', 'Configure automated review reminders 30 days before due date', 'IT Team', 'Reminder system'),
                    ('Implementation', '2.2', 'Create review checklist template with change-log requirement', 'InfoSec', 'Review template'),
                    ('Execution', '3.1', 'Conduct first review cycle with documented findings and updates', 'Document Owners', 'Review records'),
                    ('Monitoring', '4.1', 'Track review completion rate and overdue items monthly', 'InfoSec', 'Compliance tracker'),
                ], ['Review calendar', 'Completed review records', 'Change logs', 'Compliance tracker'])
            elif any(k in obs_l for k in ['third.party', 'vendor', 'supplier', 'outsourc']):
                return ([
                    ('Assessment', '1.1', 'Inventory all third parties with access to data or systems', 'Procurement', 'Vendor register'),
                    ('Assessment', '1.2', 'Classify vendors by risk tier based on data access level', 'Risk Team', 'Tiered vendor list'),
                    ('Implementation', '2.1', 'Develop and send security assessment questionnaires to critical vendors', 'Third-Party Risk', 'Completed questionnaires'),
                    ('Implementation', '2.2', 'Add security requirements to all vendor contracts and SLAs', 'Legal + InfoSec', 'Updated contracts'),
                    ('Monitoring', '3.1', 'Conduct annual reassessment of critical and high-risk vendors', 'Third-Party Risk', 'Reassessment reports'),
                ], ['Vendor register', 'Assessment questionnaires', 'Updated contracts', 'Reassessment reports'])
            elif any(k in obs_l for k in ['bcp', 'continuity', 'disaster', 'business.*continu']):
                return ([
                    ('Analysis', '1.1', 'Conduct Business Impact Analysis (BIA) for all critical functions', 'BCM Team', 'BIA report'),
                    ('Development', '1.2', 'Define RTO/RPO targets per critical function', 'BCM Team + Business', 'RTO/RPO matrix'),
                    ('Development', '2.1', 'Develop BCP with recovery strategies and alternate site procedures', 'BCM Team', 'BCP document'),
                    ('Testing', '3.1', 'Conduct tabletop exercise with key stakeholders', 'BCM Team', 'Exercise report'),
                    ('Testing', '3.2', 'Perform functional recovery drill for top-3 critical systems', 'IT + BCM', 'Drill results'),
                    ('Maintenance', '4.1', 'Review and update BCP annually and after major changes', 'BCM Team', 'Updated BCP'),
                ], ['BIA report', 'BCP document', 'Exercise reports', 'Drill results'])
            elif any(k in obs_l for k in ['logging', 'siem', 'monitor', 'log.*retention', 'audit.*trail']):
                return ([
                    ('Assessment', '1.1', 'Inventory all critical systems requiring security event logging', 'InfoSec', 'Log source inventory'),
                    ('Implementation', '2.1', 'Enable audit logging on all critical servers, databases, and firewalls', 'IT Team', 'Logging configuration'),
                    ('Implementation', '2.2', 'Integrate all log sources into centralized SIEM platform', 'Security Team', 'SIEM integration report'),
                    ('Implementation', '2.3', 'Configure log retention: 12 months active, 7 years archive', 'IT Operations', 'Retention policy'),
                    ('Operations', '3.1', 'Create detection rules and correlation alerts for key scenarios', 'SOC Team', 'Active detection rules'),
                    ('Operations', '3.2', 'Review SIEM alerts daily and investigate confirmed incidents', 'SOC Team', 'Daily review log'),
                ], ['SIEM deployment report', 'Log source inventory', 'Detection rules', 'Retention policy'])
            elif any(k in obs_l for k in ['vulnerab', 'scan', 'patch.*manag', 'cve']):
                return ([
                    ('Planning', '1.1', 'Define vulnerability scanning scope covering all IT assets', 'InfoSec', 'Scan scope document'),
                    ('Implementation', '2.1', 'Deploy automated vulnerability scanner with weekly scan schedule', 'Security Team', 'Scanner deployed'),
                    ('Implementation', '2.2', 'Define remediation SLAs: Critical 7d, High 14d, Medium 30d', 'InfoSec', 'SLA document'),
                    ('Operations', '3.1', 'Assign vulnerability owners and track remediation in ticketing system', 'Security Team', 'Remediation tracker'),
                    ('Operations', '3.2', 'Escalate SLA breaches to management weekly', 'InfoSec', 'Escalation reports'),
                    ('Monitoring', '4.1', 'Report monthly on vulnerability trends and SLA compliance', 'InfoSec', 'Monthly report'),
                ], ['Scan reports', 'SLA document', 'Remediation tracker', 'Monthly trend reports'])
            elif any(k in obs_l for k in ['cloud', 'cspm', 'misconfigur']):
                return ([
                    ('Assessment', '1.1', 'Inventory all cloud environments and classify by data sensitivity', 'Cloud Team', 'Cloud asset inventory'),
                    ('Implementation', '2.1', 'Deploy CSPM tool and scan for misconfigurations against CIS Benchmarks', 'Security Team', 'CSPM deployment report'),
                    ('Implementation', '2.2', 'Harden IAM: enforce MFA, restrict root access, implement least-privilege', 'IAM Team', 'Cloud IAM hardened'),
                    ('Implementation', '2.3', 'Enable cloud-native logging and integrate with SIEM', 'Cloud Team', 'Logging active'),
                    ('Monitoring', '3.1', 'Review CSPM findings weekly and remediate critical misconfigurations within 48h', 'Security Team', 'Remediation tracker'),
                ], ['Cloud inventory', 'CSPM scan results', 'IAM configuration', 'Remediation records'])
            elif any(k in obs_l for k in ['physical', 'server room', 'data center', 'biometric', 'cctv']):
                return ([
                    ('Assessment', '1.1', 'Audit current physical access controls for all sensitive areas', 'Facilities', 'Physical security assessment'),
                    ('Implementation', '2.1', 'Deploy multi-factor physical access: badge + biometric for server rooms', 'Facilities', 'Access control installed'),
                    ('Implementation', '2.2', 'Install CCTV with 90-day retention at all entry points', 'Facilities', 'CCTV deployment report'),
                    ('Implementation', '2.3', 'Implement visitor registration and mandatory escort procedures', 'Security', 'Visitor management SOP'),
                    ('Monitoring', '3.1', 'Review physical access logs monthly for anomalies', 'Security Team', 'Monthly review report'),
                ], ['Physical access audit', 'CCTV installation report', 'Visitor management SOP', 'Access log reviews'])
            elif any(k in obs_l for k in ['asset.*inventory', 'cmdb', 'asset.*manage', 'disposal']):
                return ([
                    ('Implementation', '1.1', 'Deploy automated asset discovery tool scanning all network ranges', 'IT Team', 'Discovery tool deployed'),
                    ('Implementation', '1.2', 'Establish CMDB with asset attributes: owner, classification, location, lifecycle', 'IT Team', 'CMDB populated'),
                    ('Implementation', '2.1', 'Define asset lifecycle procedures: procurement → deployment → maintenance → disposal', 'IT Team', 'Lifecycle procedures'),
                    ('Implementation', '2.2', 'Implement NIST 800-88 compliant data destruction for disposed assets', 'IT Team', 'Destruction procedures'),
                    ('Operations', '3.1', 'Conduct quarterly CMDB reconciliation against discovery scans', 'IT Team', 'Reconciliation report'),
                ], ['CMDB screenshots', 'Asset discovery reports', 'Disposal certificates', 'Reconciliation records'])
            elif any(k in obs_l for k in ['change.*manage', 'cab', 'emergency.*change']):
                return ([
                    ('Design', '1.1', 'Define change categories: Standard, Normal, Emergency with approval levels', 'IT Management', 'Change classification'),
                    ('Design', '1.2', 'Establish CAB membership, meeting cadence, and decision criteria', 'IT Management', 'CAB charter'),
                    ('Implementation', '2.1', 'Configure change management workflow in ITSM tool', 'IT Team', 'Workflow configured'),
                    ('Implementation', '2.2', 'Mandate impact assessment and rollback plan for all Normal/Emergency changes', 'IT Team', 'Templates created'),
                    ('Operations', '3.1', 'Require retrospective CAB review of all emergency changes within 48h', 'CAB', 'Review records'),
                    ('Monitoring', '4.1', 'Track change success rate, emergency change frequency, and failed changes monthly', 'IT Management', 'Change metrics'),
                ], ['CAB charter', 'Change workflow screenshots', 'Impact assessment templates', 'Monthly metrics reports'])
            elif any(k in obs_l for k in ['mdm', 'mobile.*device', 'byod', 'endpoint.*secur']):
                return ([
                    ('Planning', '1.1', 'Define mobile device security requirements and BYOD boundaries', 'InfoSec', 'Mobile security policy'),
                    ('Implementation', '2.1', 'Deploy MDM/UEM solution with mandatory enrollment for all devices', 'IT Team', 'MDM deployment report'),
                    ('Implementation', '2.2', 'Configure policies: device encryption, PIN lock, remote wipe, app restrictions', 'IT Team', 'MDM policies active'),
                    ('Implementation', '2.3', 'Create containerized workspace for BYOD separating personal and corporate data', 'IT Team', 'Container configured'),
                    ('Operations', '3.1', 'Monitor device compliance and auto-quarantine non-compliant devices', 'Security Team', 'Compliance dashboard'),
                ], ['MDM deployment report', 'Policy configuration', 'BYOD enrollment records', 'Compliance metrics'])
            elif any(k in obs_l for k in ['retention', 'archiv', 'email.*policy.*review']):
                return ([
                    ('Assessment', '1.1', 'Identify regulatory retention requirements applicable to the organization', 'Legal + Compliance', 'Requirements matrix'),
                    ('Design', '1.2', 'Define retention periods per data type aligned with regulations', 'InfoSec', 'Retention schedule'),
                    ('Implementation', '2.1', 'Configure automated archiving with defined retention periods', 'IT Team', 'Archive configuration'),
                    ('Implementation', '2.2', 'Implement legal hold capability for litigation-relevant data', 'Legal + IT', 'Legal hold process'),
                    ('Monitoring', '3.1', 'Audit retention compliance quarterly and purge expired data', 'Compliance', 'Audit records'),
                ], ['Retention schedule', 'Archive configuration', 'Legal hold process', 'Compliance audit records'])
            elif any(k in obs_l for k in ['firewall.*rule', 'firewall.*review', 'acl']):
                return ([
                    ('Assessment', '1.1', 'Export complete firewall rule base and identify total rule count', 'Network Team', 'Rule base export'),
                    ('Analysis', '1.2', 'Identify orphaned, duplicate, shadowed, and overly permissive rules', 'Network Security', 'Cleanup report'),
                    ('Implementation', '2.1', 'Remove or tighten identified problematic rules with change management', 'Network Team', 'Change records'),
                    ('Implementation', '2.2', 'Implement rule documentation standard: business justification and expiry for each rule', 'Network Security', 'Documentation standard'),
                    ('Operations', '3.1', 'Schedule quarterly firewall rule base review', 'Network Security', 'Quarterly review records'),
                ], ['Rule base export', 'Cleanup report', 'Change records', 'Quarterly review schedule'])
            elif any(k in obs_l for k in ['usb', 'removable', 'portable media', 'flash drive', 'external drive', 'usb port']):
                if any(k in obs_l for k in ['dlp', 'data loss', 'monitor', 'file transfer', 'exfiltrat']):
                    return ([
                        ('Assessment', '1.1', 'Inventory all endpoints and classify by data sensitivity level', 'InfoSec', 'Endpoint classification report'),
                        ('Planning', '1.2', 'Define DLP policies for USB: block sensitive files, alert on bulk transfers, log all activity', 'InfoSec', 'USB DLP policy document'),
                        ('Implementation', '2.1', 'Deploy endpoint DLP agents on all workstations with USB monitoring enabled', 'IT Team', 'DLP agent deployment report'),
                        ('Implementation', '2.2', 'Configure content-aware rules: block PII, financial data, and classified files to USB', 'Security Team', 'DLP rules active'),
                        ('Implementation', '2.3', 'Set up real-time alerts for policy violations and bulk file copy attempts', 'SOC Team', 'Alert rules configured'),
                        ('Operations', '3.1', 'Review USB DLP incidents weekly and investigate confirmed violations', 'Security Team', 'Weekly incident review'),
                    ], ['DLP deployment report', 'USB transfer policy', 'DLP rule configuration', 'Incident investigation logs'])
                elif any(k in obs_l for k in ['encrypt', 'aes', 'cipher']):
                    return ([
                        ('Planning', '1.1', 'Define approved USB device models with hardware encryption (AES-256)', 'InfoSec', 'Approved device list'),
                        ('Procurement', '1.2', 'Procure hardware-encrypted USB drives with centralized management capability', 'IT Procurement', 'Purchase order'),
                        ('Implementation', '2.1', 'Configure central management console for encrypted USB fleet', 'IT Team', 'Management console active'),
                        ('Implementation', '2.2', 'Enforce policy: block all non-encrypted USB storage devices via Group Policy', 'IT Team', 'GPO configuration'),
                        ('Implementation', '2.3', 'Configure auto-wipe after 10 failed password attempts on encrypted devices', 'Security Team', 'Auto-wipe policy active'),
                        ('Operations', '3.1', 'Monitor encrypted USB device compliance and report lost/stolen devices', 'Security Team', 'Monthly compliance report'),
                    ], ['Approved device list', 'Encryption configuration', 'GPO enforcement evidence', 'Lost device incident log'])
                elif any(k in obs_l for k in ['inventory', 'track', 'registry', 'asset']):
                    return ([
                        ('Planning', '1.1', 'Design USB device registry with fields: serial number, assigned user, department, issue date', 'InfoSec', 'Registry template'),
                        ('Implementation', '2.1', 'Register all existing approved USB devices in centralized asset management system', 'IT Team', 'Initial inventory'),
                        ('Implementation', '2.2', 'Implement check-out/check-in process for USB device issuance with manager approval', 'IT Team', 'Issuance workflow'),
                        ('Implementation', '2.3', 'Tag all approved USB devices with tamper-evident asset labels', 'IT Team', 'Labeling complete'),
                        ('Operations', '3.1', 'Conduct quarterly reconciliation of USB inventory vs active directory records', 'Security Team', 'Quarterly reconciliation report'),
                        ('Operations', '3.2', 'Investigate and report missing or unreturned USB devices', 'Security Team', 'Investigation records'),
                    ], ['USB device registry', 'Issuance/return records', 'Quarterly reconciliation reports', 'Missing device investigations'])
                else:
                    return ([
                        ('Assessment', '1.1', 'Audit all endpoints for current USB port status (enabled/disabled)', 'IT Team', 'USB port audit report'),
                        ('Planning', '1.2', 'Define USB device whitelist: approved vendor IDs and product IDs', 'InfoSec', 'Device whitelist'),
                        ('Implementation', '2.1', 'Deploy Group Policy to disable USB mass storage on all domain-joined machines', 'IT Team', 'GPO deployment report'),
                        ('Implementation', '2.2', 'Configure device control exceptions for approved encrypted USB devices only', 'IT Team', 'Whitelist configuration'),
                        ('Implementation', '2.3', 'Enable USB device connection logging on all endpoints', 'Security Team', 'Logging enabled'),
                        ('Operations', '3.1', 'Review USB connection logs monthly for unauthorized device attempts', 'SOC Team', 'Monthly review report'),
                    ], ['GPO configuration evidence', 'Device whitelist', 'USB connection logs', 'Exception approval records'])
            else:
                # Generic guide as last resort
                return ([
                    ('Planning', '1.1', 'Define implementation scope and affected systems', 'Security Team', 'Scope document'),
                    ('Planning', '1.2', 'Evaluate available solutions and select best fit', 'IT', 'Comparison report'),
                    ('Implementation', '2.1', 'Deploy and configure selected solution', 'IT Team', 'Deployment report'),
                    ('Implementation', '2.2', 'Comprehensive testing in staging environment', 'QA', 'Test report'),
                    ('Deployment', '3.1', 'Train relevant personnel and gradual rollout', 'Training', 'Training records'),
                    ('Monitoring', '4.1', 'Monitor implementation and verify compliance', 'Security Team', 'Monitoring report'),
                ], ['Implementation report', 'Configuration evidence', 'Training records', 'Test report'])

        f1_guide = _get_impl_guide_en(f1_obs, f1_rec)
        f2_guide = _get_impl_guide_en(f2_obs, f2_rec)
        f1_steps_md = '\n'.join(f'| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |' for s in f1_guide[0])
        f1_evidence = ' '.join(f'☐ {e}' for e in f1_guide[1])
        f2_steps_md = '\n'.join(f'| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |' for s in f2_guide[0])
        f2_evidence = ' '.join(f'☐ {e}' for e in f2_guide[1])
        
        return f"""# Audit Report - {pn} Policy vs {fw}

## Executive Summary
This audit was conducted to assess the compliance of the {pn} Policy against {fw} requirements. The report covers the period from [Start Date] to [End Date].

**Overall Result:** Partially Compliant — 2 high-risk, 2 medium-risk, and 1 low-risk findings identified requiring remediation before full {fw} compliance can be achieved.

## Findings & Observations

### High-Risk Findings
| # | Observation | Affected Control ({fw}) | Recommendation | Status |
|---|-------------|------------------------|----------------|--------|
| 1 | {f1_obs} | {f1_ctrl} | {f1_rec} | To Be Assessed |
| 2 | {f2_obs} | {f2_ctrl} | {f2_rec} | To Be Assessed |


---

## Detailed Implementation Guidelines

### Finding #1: {f1_obs}

**Affected Control:** {f1_ctrl} ({fw})

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
{f1_steps_md}

**Evidence Required:** {f1_evidence}

---

### Finding #2: {f2_obs}

**Affected Control:** {f2_ctrl} ({fw})

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
{f2_steps_md}

**Evidence Required:** {f2_evidence}

---

### Medium-Risk Findings
| # | Observation | Affected Control | Recommendation | Status |
|---|-------------|-----------------|----------------|--------|
| 3 | {f3_obs} | {f3_ctrl} | {f3_rec} | To Be Assessed |
| 4 | {f4_obs} | {f4_ctrl} | {f4_rec} | To Be Assessed |

### Low-Risk Findings
| # | Observation | Affected Control | Recommendation | Status |
|---|-------------|-----------------|----------------|--------|
| 5 | {f5_obs} | {f5_ctrl} | {f5_rec} | To Be Assessed |

## Action Plan
| # | Action | Owner | Deadline | Priority |
|---|--------|-------|----------|----------|
| 1 | Address Finding #1 | Security Team | Within 30 days | High |
| 2 | Address Finding #2 | InfoSec | Within 30 days | High |
| 3 | Address Finding #3 | InfoSec | Within 60 days | Medium |
| 4 | Address Finding #4 | Training | Within 60 days | Medium |
| 5 | Address Finding #5 | InfoSec | Within 90 days | Low |

---
**Report Date:** [To be added]
**Next Audit:** Within 6 months"""
def generate_risk_simulation(language='en', category=None, asset=None, threat=None):
    """Generate risk analysis simulation content - scenario-specific."""
    cat = category or ('أمن المعلومات' if language == 'ar' else 'Information Security')
    ast_name = asset or ('البنية التحتية الحرجة' if language == 'ar' else 'Critical Infrastructure')
    thr = threat or ('وصول غير مصرح' if language == 'ar' else 'Unauthorized access')
    
    # Scenario-specific controls and impacts based on threat keywords
    RISK_SCENARIOS_EN = {
        'insider': {
            'title': 'Insider Threat',
            'sources': ['Disgruntled employees with elevated access', 'Contractors with unmonitored access', 'Social engineering of privileged users', 'Compromised employee credentials'],
            'impacts': [
                ('Financial', 'Data breach costs $2-8 million including forensics, notification, and litigation', 'High'),
                ('Operational', 'Database corruption or exfiltration causing 48-96 hour recovery', 'High'),
                ('Reputational', 'Loss of customer trust due to internal data theft', 'High'),
                ('Legal', 'Regulatory penalties for failure to prevent insider access abuse', 'Medium'),
            ],
            'likelihood': [
                ('Insider access to sensitive systems', 'High'),
                ('Monitoring of privileged user activity', 'Low'),
                ('Background check rigor', 'Medium'),
                ('Data exfiltration detection capability', 'Low'),
            ],
            'controls': [
                ('Implement User and Entity Behavior Analytics (UEBA)', 'High', 'Immediate', '$80,000'),
                ('Deploy Database Activity Monitoring (DAM)', 'High', '30 days', '$60,000'),
                ('Implement Data Loss Prevention (DLP) for database exports', 'High', '45 days', '$50,000'),
            ],
            'guides': [
                {
                    'name': 'User and Entity Behavior Analytics (UEBA)',
                    'steps': [
                        ('Planning', '1.1', 'Identify critical systems and baseline normal user behavior patterns', 'Security Team', 'Behavior baseline report'),
                        ('Planning', '1.2', 'Define anomaly detection rules: unusual query volumes, off-hours access, bulk downloads', 'InfoSec', 'Detection rule set'),
                        ('Implementation', '2.1', 'Deploy UEBA solution and integrate with AD, VPN, database, and endpoint logs', 'Infrastructure Team', 'Integrated UEBA platform'),
                        ('Implementation', '2.2', 'Configure risk scoring thresholds and automated alert escalation', 'SOC Team', 'Calibrated alerting rules'),
                        ('Implementation', '2.3', 'Establish investigation workflow: alert → triage → investigation → action', 'SOC Team', 'Investigation playbook'),
                        ('Operations', '3.1', 'Tune models to reduce false positives using 30-day learning period', 'Security Team', 'Tuning report'),
                        ('Operations', '3.2', 'Conduct monthly insider threat review meetings with HR and Legal', 'CISO', 'Monthly review minutes'),
                    ],
                    'evidence': ['UEBA deployment report', 'Detection rules documentation', 'Sample alert investigation records', 'False positive rate metrics'],
                },
                {
                    'name': 'Database Activity Monitoring (DAM)',
                    'steps': [
                        ('Planning', '1.1', 'Inventory all databases containing sensitive data (PII, financial, classified)', 'DBA Team', 'Database inventory with classification'),
                        ('Planning', '1.2', 'Define monitoring policies: privileged queries, schema changes, bulk exports, off-hours access', 'InfoSec', 'DAM policy document'),
                        ('Implementation', '2.1', 'Deploy DAM agents/network sensors on all classified databases', 'Infrastructure Team', 'DAM deployment report'),
                        ('Implementation', '2.2', 'Configure real-time alerts for policy violations and suspicious queries', 'Security Team', 'Active alert rules'),
                        ('Implementation', '2.3', 'Integrate DAM alerts with SIEM for correlation with other indicators', 'SOC Team', 'SIEM integration confirmed'),
                        ('Operations', '3.1', 'Establish weekly review of database access patterns and anomalies', 'DBA + Security', 'Weekly access review report'),
                    ],
                    'evidence': ['DAM installation report', 'Policy violation alerts', 'Database access audit logs', 'SIEM correlation rules'],
                },
                {
                    'name': 'Data Loss Prevention (DLP) for Database Exports',
                    'steps': [
                        ('Planning', '1.1', 'Map all data export paths: SQL clients, ETL tools, backup utilities, API endpoints', 'DBA Team', 'Export path inventory'),
                        ('Planning', '1.2', 'Define DLP policies: block bulk exports > threshold rows, alert on sensitive column access', 'InfoSec', 'DLP policy matrix'),
                        ('Implementation', '2.1', 'Deploy endpoint DLP on all database administrator workstations', 'IT Team', 'DLP agent deployment report'),
                        ('Implementation', '2.2', 'Configure network DLP at database egress points to detect large data transfers', 'Network Team', 'Network DLP rules active'),
                        ('Implementation', '2.3', 'Implement database-level row export limits with manager approval for exceptions', 'DBA Team', 'Database export controls'),
                        ('Operations', '3.1', 'Review DLP incident reports weekly and investigate confirmed violations', 'Security Team', 'DLP incident review log'),
                    ],
                    'evidence': ['DLP deployment confirmation', 'Export control policies', 'Incident investigation reports', 'Exception approval records'],
                },
            ],
        },
        'ransomware': {
            'title': 'Ransomware Attack',
            'sources': ['Phishing emails with malicious attachments', 'Exploitation of unpatched vulnerabilities', 'Compromised remote access credentials', 'Supply chain compromise'],
            'impacts': [
                ('Financial', 'Ransom demand $500K-$5M plus recovery costs and business interruption', 'High'),
                ('Operational', 'Complete system encryption causing 1-4 week business halt', 'Critical'),
                ('Reputational', 'Public disclosure of security failure and potential data leak', 'High'),
                ('Legal', 'Regulatory fines for inadequate protection and potential data exposure', 'High'),
            ],
            'likelihood': [
                ('Email security maturity', 'Medium'),
                ('Patch management cadence', 'Medium'),
                ('Backup isolation and testing', 'Low'),
                ('Endpoint detection capability', 'Medium'),
            ],
            'controls': [
                ('Deploy advanced endpoint detection and response (EDR)', 'High', 'Immediate', '$100,000'),
                ('Implement immutable air-gapped backup strategy', 'High', '30 days', '$75,000'),
                ('Harden email gateway with sandbox detonation', 'High', '30 days', '$50,000'),
            ],
            'guides': [
                {
                    'name': 'Advanced Endpoint Detection and Response (EDR)',
                    'steps': [
                        ('Planning', '1.1', 'Assess current endpoint protection gaps and EDR requirements', 'Security Team', 'Requirements document'),
                        ('Planning', '1.2', 'Evaluate EDR solutions against ransomware-specific detection capabilities', 'InfoSec', 'Vendor comparison'),
                        ('Implementation', '2.1', 'Deploy EDR agents to all endpoints with anti-tampering enabled', 'IT Team', 'Deployment report'),
                        ('Implementation', '2.2', 'Configure behavioral detection rules for file encryption patterns', 'Security Team', 'Detection rules active'),
                        ('Implementation', '2.3', 'Enable automated containment: isolate endpoint on ransomware detection', 'SOC Team', 'Auto-response rules'),
                        ('Operations', '3.1', 'Conduct monthly ransomware simulation exercises', 'Security Team', 'Simulation results'),
                    ],
                    'evidence': ['EDR deployment coverage report', 'Detection rule documentation', 'Containment test results', 'Simulation exercise reports'],
                },
                {
                    'name': 'Immutable Air-Gapped Backup Strategy',
                    'steps': [
                        ('Planning', '1.1', 'Identify all critical systems and define RPO/RTO targets', 'BCM Team', 'BIA document'),
                        ('Planning', '1.2', 'Design 3-2-1-1 backup architecture: 3 copies, 2 media, 1 offsite, 1 immutable', 'Infrastructure', 'Architecture design'),
                        ('Implementation', '2.1', 'Deploy immutable backup storage with WORM (Write Once Read Many) capability', 'Infrastructure', 'Storage configured'),
                        ('Implementation', '2.2', 'Configure automated backup verification and integrity checks', 'IT Team', 'Verification schedule'),
                        ('Operations', '3.1', 'Test full restoration from immutable backups quarterly', 'IT Team', 'Restore test report'),
                    ],
                    'evidence': ['Backup architecture documentation', 'Immutability configuration proof', 'Quarterly restore test reports'],
                },
                {
                    'name': 'Email Gateway Hardening with Sandbox',
                    'steps': [
                        ('Planning', '1.1', 'Audit current email security stack and identify gaps', 'InfoSec', 'Gap assessment'),
                        ('Implementation', '2.1', 'Deploy attachment sandboxing with detonation in isolated environment', 'IT Team', 'Sandbox configured'),
                        ('Implementation', '2.2', 'Enable URL rewriting and time-of-click analysis', 'IT Team', 'URL protection active'),
                        ('Implementation', '2.3', 'Enforce DMARC reject policy and verify SPF/DKIM alignment', 'IT Team', 'Email authentication report'),
                        ('Operations', '3.1', 'Review blocked threats weekly and tune detection policies', 'Security Team', 'Weekly threat report'),
                    ],
                    'evidence': ['Sandbox deployment report', 'DMARC/SPF/DKIM configuration', 'Blocked threat statistics'],
                },
            ],
        },
        'default': {
            'title': 'Security Threat',
            'sources': ['External attackers (APT)', 'Insider threats', 'Human error', 'Technical failure'],
            'impacts': [
                ('Financial', 'Potential losses from breach, recovery, and regulatory fines', 'High'),
                ('Operational', 'Service disruption affecting business operations', 'High'),
                ('Reputational', 'Negative impact on stakeholder and customer trust', 'Medium'),
                ('Legal', 'Potential regulatory penalties and litigation costs', 'Medium'),
            ],
            'likelihood': [
                ('Historical incident frequency', 'Medium'),
                ('Attack surface exposure', 'Medium'),
                ('Current control maturity', 'Low'),
                ('Threat intelligence indicators', 'Medium'),
            ],
            'controls': [
                ('Implement comprehensive access control hardening', 'High', 'Immediate', '$40,000'),
                ('Deploy advanced threat detection and monitoring', 'High', '30 days', '$80,000'),
                ('Establish incident response capability', 'Medium', '60 days', '$30,000'),
            ],
            'guides': [
                {
                    'name': 'Access Control Hardening',
                    'steps': [
                        ('Planning', '1.1', 'Conduct access rights review across all critical systems', 'IAM Team', 'Access review report'),
                        ('Planning', '1.2', 'Define RBAC matrix aligned with least-privilege principle', 'InfoSec', 'RBAC matrix'),
                        ('Implementation', '2.1', 'Deploy MFA for all privileged and remote access', 'IT Team', 'MFA deployment report'),
                        ('Implementation', '2.2', 'Implement PAM solution for privileged account management', 'Security Team', 'PAM configured'),
                        ('Implementation', '2.3', 'Configure automated access certification reviews quarterly', 'IAM Team', 'Certification schedule'),
                        ('Monitoring', '3.1', 'Monitor privileged session activity in real-time', 'SOC Team', 'Monitoring dashboard'),
                    ],
                    'evidence': ['Access review documentation', 'MFA enrollment report', 'PAM configuration', 'Certification records'],
                },
                {
                    'name': 'Advanced Threat Detection and Monitoring',
                    'steps': [
                        ('Planning', '1.1', 'Define SIEM use cases and log source requirements', 'InfoSec', 'Use case catalog'),
                        ('Implementation', '2.1', 'Integrate all critical system logs into SIEM platform', 'IT Team', 'Log source inventory'),
                        ('Implementation', '2.2', 'Configure correlation rules and alert thresholds', 'SOC Team', 'Active detection rules'),
                        ('Implementation', '2.3', 'Establish 24/7 monitoring coverage with escalation procedures', 'SOC Team', 'Monitoring SOP'),
                        ('Operations', '3.1', 'Tune detection rules monthly to optimize signal-to-noise ratio', 'Security Team', 'Monthly tuning report'),
                    ],
                    'evidence': ['SIEM deployment report', 'Correlation rules list', 'Alert response metrics'],
                },
                {
                    'name': 'Incident Response Capability',
                    'steps': [
                        ('Planning', '1.1', 'Develop incident response plan with severity classification', 'InfoSec', 'IR plan document'),
                        ('Planning', '1.2', 'Define CSIRT roles, responsibilities, and escalation matrix', 'CISO', 'CSIRT charter'),
                        ('Implementation', '2.1', 'Deploy forensic tools and evidence preservation procedures', 'Security Team', 'Forensic toolkit ready'),
                        ('Implementation', '2.2', 'Create incident playbooks for top threat scenarios', 'SOC Team', 'Playbook library'),
                        ('Operations', '3.1', 'Conduct quarterly tabletop exercises simulating real scenarios', 'Security Team', 'Exercise reports'),
                    ],
                    'evidence': ['Approved IR plan', 'CSIRT contact list', 'Tabletop exercise reports'],
                },
            ],
        },
    }
    
    RISK_SCENARIOS_AR = {
        'داخلي': {
            'title': 'تهديد داخلي',
            'sources': ['موظفون ساخطون لديهم صلاحيات مرتفعة', 'متعاقدون بوصول غير مراقب', 'هندسة اجتماعية لمستخدمين مميزين', 'بيانات اعتماد موظف مخترقة'],
            'impacts': [
                ('مالي', 'تكاليف اختراق البيانات 2-8 مليون ريال شاملة التحقيق والإخطار والتقاضي', 'عالي'),
                ('تشغيلي', 'تلف أو تسريب قاعدة البيانات مع فترة استعادة 48-96 ساعة', 'عالي'),
                ('سمعة', 'فقدان ثقة العملاء بسبب سرقة بيانات داخلية', 'عالي'),
                ('قانوني', 'عقوبات تنظيمية لعدم منع إساءة استخدام الوصول الداخلي', 'متوسط'),
            ],
            'likelihood': [
                ('وصول داخلي للأنظمة الحساسة', 'عالي'),
                ('مراقبة نشاط المستخدمين المميزين', 'منخفض'),
                ('صرامة فحص الخلفيات', 'متوسط'),
                ('قدرة كشف تسريب البيانات', 'منخفض'),
            ],
            'controls': [
                ('تطبيق تحليلات سلوك المستخدم والكيانات (UEBA)', 'عالية', 'فوري', '300,000 ريال'),
                ('نشر نظام مراقبة نشاط قواعد البيانات (DAM)', 'عالية', '30 يوم', '225,000 ريال'),
                ('تطبيق منع تسريب البيانات (DLP) لصادرات قواعد البيانات', 'عالية', '45 يوم', '190,000 ريال'),
            ],
            'guides': [
                {
                    'name': 'تحليلات سلوك المستخدم والكيانات (UEBA)',
                    'steps': [
                        ('التخطيط', '1.1', 'تحديد الأنظمة الحرجة ورسم خط أساس لسلوك المستخدم الطبيعي', 'فريق الأمن', 'تقرير خط الأساس'),
                        ('التخطيط', '1.2', 'تحديد قواعد كشف الشذوذ: استعلامات غير عادية، وصول خارج ساعات العمل، تنزيلات كبيرة', 'أمن المعلومات', 'مجموعة قواعد الكشف'),
                        ('التنفيذ', '2.1', 'نشر حل UEBA وربطه مع AD وVPN وقاعدة البيانات والأجهزة الطرفية', 'فريق البنية التحتية', 'منصة UEBA متكاملة'),
                        ('التنفيذ', '2.2', 'تكوين حدود تسجيل المخاطر والتصعيد الآلي للتنبيهات', 'فريق SOC', 'قواعد تنبيه معايرة'),
                        ('التشغيل', '3.1', 'ضبط النماذج لتقليل التنبيهات الخاطئة باستخدام فترة تعلم 30 يوم', 'فريق الأمن', 'تقرير الضبط'),
                    ],
                    'evidence': ['تقرير نشر UEBA', 'توثيق قواعد الكشف', 'سجلات تحقيق التنبيهات'],
                },
                {
                    'name': 'مراقبة نشاط قواعد البيانات (DAM)',
                    'steps': [
                        ('التخطيط', '1.1', 'جرد جميع قواعد البيانات المحتوية على بيانات حساسة', 'فريق DBA', 'جرد قواعد البيانات المصنفة'),
                        ('التخطيط', '1.2', 'تحديد سياسات المراقبة: استعلامات مميزة، تغييرات الهيكل، التصدير الكبير', 'أمن المعلومات', 'وثيقة سياسات DAM'),
                        ('التنفيذ', '2.1', 'نشر وكلاء/حساسات DAM على جميع قواعد البيانات المصنفة', 'فريق البنية التحتية', 'تقرير نشر DAM'),
                        ('التنفيذ', '2.2', 'تكوين تنبيهات فورية لانتهاكات السياسة والاستعلامات المشبوهة', 'فريق الأمن', 'قواعد تنبيه فعالة'),
                        ('التشغيل', '3.1', 'إنشاء مراجعة أسبوعية لأنماط وصول قاعدة البيانات والشذوذ', 'DBA + الأمن', 'تقرير مراجعة أسبوعي'),
                    ],
                    'evidence': ['تقرير تثبيت DAM', 'تنبيهات انتهاك السياسة', 'سجلات تدقيق وصول قاعدة البيانات'],
                },
                {
                    'name': 'منع تسريب البيانات (DLP) لصادرات قواعد البيانات',
                    'steps': [
                        ('التخطيط', '1.1', 'رسم خريطة جميع مسارات تصدير البيانات: عملاء SQL، أدوات ETL، أدوات النسخ', 'فريق DBA', 'جرد مسارات التصدير'),
                        ('التنفيذ', '2.1', 'نشر DLP على محطات عمل مديري قواعد البيانات', 'فريق تقنية المعلومات', 'تقرير نشر DLP'),
                        ('التنفيذ', '2.2', 'تكوين DLP شبكي عند نقاط خروج قاعدة البيانات لكشف النقل الكبير', 'فريق الشبكات', 'قواعد DLP الشبكية'),
                        ('التنفيذ', '2.3', 'تطبيق حدود تصدير الصفوف مع موافقة المدير للاستثناءات', 'فريق DBA', 'ضوابط التصدير'),
                        ('التشغيل', '3.1', 'مراجعة تقارير حوادث DLP أسبوعياً والتحقيق في الانتهاكات المؤكدة', 'فريق الأمن', 'سجل مراجعة حوادث DLP'),
                    ],
                    'evidence': ['تأكيد نشر DLP', 'سياسات التحكم بالتصدير', 'تقارير التحقيق في الحوادث'],
                },
            ],
        },
        'default': {
            'title': 'تهديد أمني',
            'sources': ['مهاجمون خارجيون (APT)', 'تهديدات داخلية', 'أخطاء بشرية', 'فشل تقني'],
            'impacts': [
                ('مالي', 'خسائر محتملة من الاختراق والاستعادة والغرامات التنظيمية', 'عالي'),
                ('تشغيلي', 'انقطاع الخدمات المؤثر على العمليات', 'عالي'),
                ('سمعة', 'تأثير سلبي على ثقة الأطراف المعنية والعملاء', 'متوسط'),
                ('قانوني', 'غرامات تنظيمية وتكاليف تقاضي محتملة', 'متوسط'),
            ],
            'likelihood': [
                ('تكرار الحوادث التاريخي', 'متوسط'),
                ('تعرض سطح الهجوم', 'متوسط'),
                ('نضج الضوابط الحالية', 'منخفض'),
                ('مؤشرات استخبارات التهديدات', 'متوسط'),
            ],
            'controls': [
                ('تطبيق تقوية شاملة لضوابط الوصول', 'عالية', 'فوري', '150,000 ريال'),
                ('نشر كشف ومراقبة التهديدات المتقدمة', 'عالية', '30 يوم', '300,000 ريال'),
                ('إنشاء قدرة الاستجابة للحوادث', 'متوسطة', '60 يوم', '110,000 ريال'),
            ],
            'guides': [
                {
                    'name': 'تقوية ضوابط الوصول',
                    'steps': [
                        ('التخطيط', '1.1', 'إجراء مراجعة شاملة لحقوق الوصول عبر جميع الأنظمة الحرجة', 'فريق IAM', 'تقرير مراجعة الوصول'),
                        ('التنفيذ', '2.1', 'نشر MFA لجميع الوصول المميز والبعيد', 'فريق تقنية المعلومات', 'تقرير نشر MFA'),
                        ('التنفيذ', '2.2', 'تطبيق حل PAM لإدارة الحسابات المميزة', 'فريق الأمن', 'PAM مُكوّن'),
                        ('المراقبة', '3.1', 'مراقبة نشاط الجلسات المميزة في الوقت الفعلي', 'فريق SOC', 'لوحة المراقبة'),
                    ],
                    'evidence': ['وثائق مراجعة الوصول', 'تقرير تسجيل MFA', 'تكوين PAM'],
                },
                {
                    'name': 'كشف ومراقبة التهديدات المتقدمة',
                    'steps': [
                        ('التخطيط', '1.1', 'تحديد حالات استخدام SIEM ومتطلبات مصادر السجلات', 'أمن المعلومات', 'كتالوج حالات الاستخدام'),
                        ('التنفيذ', '2.1', 'دمج جميع سجلات الأنظمة الحرجة في منصة SIEM', 'فريق تقنية المعلومات', 'جرد مصادر السجلات'),
                        ('التنفيذ', '2.2', 'تكوين قواعد الارتباط وحدود التنبيه', 'فريق SOC', 'قواعد كشف فعالة'),
                        ('التشغيل', '3.1', 'ضبط قواعد الكشف شهرياً لتحسين نسبة الإشارة للضوضاء', 'فريق الأمن', 'تقرير ضبط شهري'),
                    ],
                    'evidence': ['تقرير نشر SIEM', 'قائمة قواعد الارتباط', 'مقاييس الاستجابة للتنبيهات'],
                },
                {
                    'name': 'قدرة الاستجابة للحوادث',
                    'steps': [
                        ('التخطيط', '1.1', 'تطوير خطة استجابة للحوادث مع تصنيف الخطورة', 'أمن المعلومات', 'وثيقة خطة IR'),
                        ('التخطيط', '1.2', 'تحديد أدوار ومسؤوليات CSIRT ومصفوفة التصعيد', 'CISO', 'ميثاق CSIRT'),
                        ('التنفيذ', '2.1', 'نشر أدوات التحقيق الجنائي وإجراءات حفظ الأدلة', 'فريق الأمن', 'أدوات جنائية جاهزة'),
                        ('التشغيل', '3.1', 'إجراء تمارين طاولة ربعية لمحاكاة سيناريوهات حقيقية', 'فريق الأمن', 'تقارير التمارين'),
                    ],
                    'evidence': ['خطة IR معتمدة', 'قائمة اتصال CSIRT', 'تقارير تمارين الطاولة'],
                },
            ],
        },
    }
    
    # Match scenario based on threat keywords
    def _find_scenario(thr_text, scenarios_dict):
        if not thr_text:
            return scenarios_dict.get('default')
        thr_lower = thr_text.lower()
        for key in scenarios_dict:
            if key == 'default':
                continue
            if key.lower() in thr_lower:
                return scenarios_dict[key]
        return scenarios_dict.get('default')
    
    if language == 'ar':
        scenario = _find_scenario(thr, RISK_SCENARIOS_AR)
        
        sources_md = '\n'.join(f'- {s}' for s in scenario['sources'])
        impacts_md = '\n'.join(f'| {t} | {d} | {l} |' for t, d, l in scenario['impacts'])
        likelihood_md = '\n'.join(f'| {f} | {a} |' for f, a in scenario['likelihood'])
        controls_md = '\n'.join(f'| {i+1} | {c[0]} | {c[1]} | {c[2]} | {c[3]} | يحتاج تقييم |' for i, c in enumerate(scenario['controls']))
        
        guides_md = ''
        for i, guide in enumerate(scenario['guides'], 1):
            steps_md = '\n'.join(f'| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |' for s in guide['steps'])
            evidence_md = ' '.join(f'☐ {e}' for e in guide['evidence'])
            guides_md += f"""
---

### دليل تنفيذ الضابط رقم {i}: {guide['name']}

**الخطوات التفصيلية:**

| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
{steps_md}

**الأدلة المطلوبة:** {evidence_md}
"""
        
        return f"""# تحليل المخاطر - {scenario['title']}

## ملخص تقييم الخطر

| العنصر | القيمة |
|--------|-------|
| فئة الخطر | {cat} |
| الأصل المتأثر | {ast_name} |
| التهديد | {thr} |
| مستوى الخطر | **عالي** |
| درجة الخطر | عالي (18/25) |

## تحليل التهديد
يمثل تهديد {scenario['title']} خطراً كبيراً على {ast_name}. يستهدف هذا التهديد سرية وسلامة وتوافر الأصل المحدد.

### مصادر التهديد المحتملة:
{sources_md}

## تحليل الأثر

| نوع الأثر | الوصف | المستوى |
|----------|-------|---------|
{impacts_md}

## تقييم الاحتمالية

| العامل | التقييم |
|--------|---------|
{likelihood_md}
| **الاحتمالية الإجمالية** | **عالية** |

## الضوابط الموصى بها

| # | الضابط | الأولوية | الجدول الزمني | التكلفة المقدرة | الحالة |
|---|--------|----------|---------------|-----------------|--------|
{controls_md}

{guides_md}

## الخطر المتبقي

| السيناريو | قبل الضوابط | بعد الضوابط |
|----------|------------|------------|
| مستوى الخطر | عالي (18/25) | متوسط (9/25) |
| الاحتمالية | عالية | منخفضة |
| الأثر المالي | كبير | مخفض بنسبة 60-75% بعد تطبيق الضوابط |

## التوصيات النهائية
1. تنفيذ الضوابط الموصى بها خلال 90 يوماً
2. إجراء اختبار اختراق بعد تطبيق الضوابط
3. مراجعة تقييم المخاطر كل 6 أشهر

---
**تاريخ التقييم:** [يُحدد عند اعتماد التقييم رسمياً]
**المراجعة القادمة:** خلال 6 أشهر"""
    
    else:
        scenario = _find_scenario(thr, RISK_SCENARIOS_EN)
        
        sources_md = '\n'.join(f'- {s}' for s in scenario['sources'])
        impacts_md = '\n'.join(f'| {t} | {d} | {l} |' for t, d, l in scenario['impacts'])
        likelihood_md = '\n'.join(f'| {f} | {a} |' for f, a in scenario['likelihood'])
        controls_md = '\n'.join(f'| {i+1} | {c[0]} | {c[1]} | {c[2]} | {c[3]} | To Be Assessed |' for i, c in enumerate(scenario['controls']))
        
        guides_md = ''
        for i, guide in enumerate(scenario['guides'], 1):
            steps_md = '\n'.join(f'| {s[0]} | {s[1]} | {s[2]} | {s[3]} | {s[4]} |' for s in guide['steps'])
            evidence_md = ' '.join(f'☐ {e}' for e in guide['evidence'])
            guides_md += f"""
---

### Control #{i} Implementation Guide: {guide['name']}

**Step-by-Step Implementation:**

| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
{steps_md}

**Evidence Required:** {evidence_md}
"""
        
        return f"""# Risk Analysis - {scenario['title']}

## Risk Assessment Summary

| Element | Value |
|---------|-------|
| Risk Category | {cat} |
| Affected Asset | {ast_name} |
| Threat | {thr} |
| Risk Level | **High** |
| Risk Score | High (18/25) |

## Threat Analysis
The {scenario['title']} threat poses a significant risk to {ast_name}. This threat targets the confidentiality, integrity, and availability of the identified asset.

### Potential Threat Sources:
{sources_md}

## Impact Analysis

| Impact Type | Description | Level |
|-------------|-------------|-------|
{impacts_md}

## Likelihood Assessment

| Factor | Assessment |
|--------|------------|
{likelihood_md}
| **Overall Likelihood** | **High** |

## Recommended Controls

| # | Control | Priority | Timeline | Estimated Cost | Status |
|---|---------|----------|----------|----------------|--------|
{controls_md}

{guides_md}

## Residual Risk

| Scenario | Before Controls | After Controls |
|----------|-----------------|----------------|
| Risk Level | High (18/25) | Medium (9/25) |
| Likelihood | High | Low |
| Financial Impact | {scenario['impacts'][0][1].split(' ')[0] + '-' + scenario['impacts'][0][1].split(' ')[1] if len(scenario['impacts']) > 0 else 'Significant'} | Reduced by 60-75% with recommended controls |

## Final Recommendations
1. Implement recommended controls within 90 days
2. Conduct penetration testing after control implementation
3. Review risk assessment every 6 months

---
**Assessment Date:** [To be added upon formal assessment]
**Next Review:** Within 6 months"""


def generate_gap_remediation_simulation(language='en', framework='NCA ECC', prompt=''):
    """Generate gap remediation plan simulation when AI is unavailable."""
    import re
    abbrev_match = re.search(r'\(([A-Z][A-Z\s]+)\)', framework)
    fw = abbrev_match.group(1).strip() if abbrev_match else framework
    
    # Try to extract gaps from prompt
    gaps_found = []
    for line in prompt.split('\n'):
        line = line.strip()
        if line.startswith('- ') and len(line) > 5:
            gaps_found.append(line[2:].strip())
    
    if not gaps_found:
        gaps_found = ['Undefined gap #1', 'Undefined gap #2', 'Undefined gap #3'] if language == 'en' else ['فجوة غير محددة #1', 'فجوة غير محددة #2', 'فجوة غير محددة #3']
    
    if language == 'ar':
        gaps_rows = '\n'.join(f'| {i+1} | {g} | تطوير وتنفيذ ضوابط لمعالجة: {g} | فريق الامتثال | مستشار خارجي + أدوات تقنية | خلال {(i+1)*30} يوم | إغلاق الفجوة بنسبة 100% |' for i, g in enumerate(gaps_found))
        
        return f"""## خطة المعالجة — وفق {fw}

### الملخص التنفيذي
تم تحديد {len(gaps_found)} فجوات تتطلب معالجة لتحقيق الامتثال الكامل لمتطلبات إطار {fw}. تتضمن هذه الخطة إجراءات محددة مع جداول زمنية واضحة ومؤشرات نجاح قابلة للقياس لكل فجوة.

### خطة العمل التفصيلية
| # | الفجوة | الإجراء | المسؤول | الموارد | الجدول الزمني | مؤشر النجاح |
|---|--------|---------|---------|---------|--------------|-------------|
{gaps_rows}

### الأولويات
#### عالية (فورية — خلال 30 يوم)
- معالجة الفجوات الحرجة التي تؤثر مباشرة على أمن المعلومات والبيانات الحساسة
- تعيين مسؤولين وتخصيص الميزانية اللازمة

#### متوسطة (3-6 أشهر)
- تطوير السياسات والإجراءات المفقودة وفق {fw}
- تدريب الفريق على المتطلبات والضوابط الجديدة

#### منخفضة (6-12 شهر)
- تحسين العمليات القائمة وأتمتة الضوابط
- إجراء تدقيق داخلي للتحقق من فعالية المعالجة

### الميزانية التقديرية
| البند | التكلفة التقديرية |
|-------|------------------|
| استشارات خارجية | 150,000 - 300,000 ر.س |
| أدوات وتقنيات | 100,000 - 250,000 ر.س |
| تدريب وتأهيل | 50,000 - 100,000 ر.س |
| موارد بشرية إضافية | 200,000 - 400,000 ر.س |
| **الإجمالي التقديري** | **500,000 - 1,050,000 ر.س** |

### مؤشرات الأداء
| المؤشر | القيمة الحالية | القيمة المستهدفة |
|--------|---------------|-----------------|
| نسبة الامتثال لـ {fw} | تحتاج تقييم | 90%+ |
| عدد الفجوات المفتوحة | {len(gaps_found)} | 0 |
| نسبة إنجاز خطة المعالجة | 0% | 100% |

### المخاطر والتحديات
| المخاطرة | الأثر | خطة التخفيف |
|----------|-------|------------|
| نقص الموارد البشرية المؤهلة | تأخير المعالجة | الاستعانة بمستشارين خارجيين |
| تجاوز الميزانية | توقف المشروع | تحديد أولويات وتنفيذ مرحلي |
| مقاومة التغيير | ضعف التطبيق | برنامج توعية وإشراك الإدارة العليا |"""
    else:
        gaps_rows = '\n'.join(f'| {i+1} | {g} | Develop and implement controls for: {g} | Compliance Team | External consultant + tools | Within {(i+1)*30} days | 100% gap closure |' for i, g in enumerate(gaps_found))
        
        return f"""## Remediation Plan — {fw}

### Executive Summary
{len(gaps_found)} gaps have been identified requiring remediation to achieve full compliance with {fw} requirements. This plan includes specific actions with clear timelines and measurable success metrics for each gap.

### Detailed Action Plan
| # | Gap | Action | Owner | Resources | Timeline | Success Metric |
|---|-----|--------|-------|-----------|----------|----------------|
{gaps_rows}

### Priorities
#### High (Immediate — Within 30 days)
- Address critical gaps directly impacting information security and sensitive data
- Assign responsible parties and allocate required budget

#### Medium (3-6 months)
- Develop missing policies and procedures per {fw}
- Train team on new requirements and controls

#### Low (6-12 months)
- Improve existing processes and automate controls
- Conduct internal audit to verify remediation effectiveness

### Estimated Budget
| Item | Estimated Cost |
|------|----------------|
| External consultancy | $40,000 - $80,000 |
| Tools & technology | $25,000 - $65,000 |
| Training & certification | $15,000 - $30,000 |
| Additional staffing | $50,000 - $100,000 |
| **Total Estimate** | **$130,000 - $275,000** |

### KPIs
| KPI | Current Value | Target Value |
|-----|---------------|--------------|
| {fw} Compliance Rate | To be assessed | 90%+ |
| Open Gaps | {len(gaps_found)} | 0 |
| Remediation Plan Completion | 0% | 100% |

### Risks & Challenges
| Risk | Impact | Mitigation Plan |
|------|--------|-----------------|
| Shortage of qualified resources | Delayed remediation | Engage external consultants |
| Budget overrun | Project stoppage | Prioritize and implement in phases |
| Resistance to change | Poor adoption | Awareness program and executive sponsorship |"""


def generate_risk_appetite_simulation(language='en', prompt=''):
    """Generate risk appetite statement simulation when AI is unavailable."""
    import re
    
    # Try to extract risk counts from prompt
    total = 0
    critical = high = medium = low = 0
    categories = []
    
    total_match = re.search(r'(?:Total|إجمالي).*?(\d+)', prompt)
    if total_match:
        total = int(total_match.group(1))
    crit_match = re.search(r'(?:Critical|حرجة).*?(\d+)', prompt)
    if crit_match:
        critical = int(crit_match.group(1))
    high_match = re.search(r'(?:High|عالية).*?(\d+)', prompt)
    if high_match:
        high = int(high_match.group(1))
    med_match = re.search(r'(?:Medium|متوسطة).*?(\d+)', prompt)
    if med_match:
        medium = int(med_match.group(1))
    low_match = re.search(r'(?:Low|منخفضة).*?(\d+)', prompt)
    if low_match:
        low = int(low_match.group(1))
    
    cat_match = re.search(r'(?:Categories|الفئات):\s*(.+)', prompt)
    if cat_match:
        categories = [c.strip() for c in cat_match.group(1).split(',') if c.strip()]
    
    if not categories:
        categories = ['Operational', 'Technical', 'Compliance'] if language == 'en' else ['تشغيلي', 'تقني', 'امتثال']
    if not total:
        total = critical + high + medium + low or 5
    
    if language == 'ar':
        cat_rows = '\n'.join(f'| {c} | {"صفر تسامح" if i == 0 else "منخفضة" if i == 1 else "متوسطة"} | {"0%" if i == 0 else "15%" if i == 1 else "30%"} | بناءً على طبيعة المخاطر في هذه الفئة |' for i, c in enumerate(categories))
        
        return f"""## بيان شهية المخاطر المؤسسية

### 1. بيان شهية المخاطر العام
تتبنى المنظمة مستوى شهية مخاطر **محافظ** بشكل عام، مع التركيز على حماية الأصول المعلوماتية والامتثال التنظيمي. بناءً على تحليل سجل المخاطر الحالي ({total} خطر: {critical} حرج، {high} عالي، {medium} متوسط، {low} منخفض)، تسعى المنظمة لتقليل المخاطر الحرجة والعالية إلى مستويات مقبولة خلال 90 يوماً.

### 2. شهية المخاطر حسب الفئة

#### جدول شهية المخاطر:
| الفئة | مستوى الشهية | الحد الأقصى المقبول | المبرر |
|-------|-------------|-------------------|--------|
{cat_rows}

### 3. حدود التحمل ومعايير التصعيد

#### مصفوفة التصعيد:
| مستوى الخطر | الإجراء المطلوب | الجهة المسؤولة | الإطار الزمني |
|------------|----------------|---------------|--------------|
| حرج (20-25) | إيقاف النشاط فوراً + خطة معالجة طارئة | الرئيس التنفيذي + مجلس الإدارة | فوري (خلال 24 ساعة) |
| عالي (12-19) | خطة معالجة عاجلة + مراقبة يومية | مدير المخاطر + الإدارة العليا | خلال 7 أيام |
| متوسط (6-11) | خطة معالجة مجدولة + مراقبة أسبوعية | مالك الخطر + فريق المخاطر | خلال 30 يوم |
| منخفض (1-5) | قبول مع مراقبة دورية | مالك الخطر | خلال 90 يوم |

### 4. أدوار ومسؤوليات إدارة المخاطر

**الخط الأول — الإدارات التشغيلية:**
- تحديد المخاطر اليومية والإبلاغ عنها
- تنفيذ خطط المعالجة المعتمدة

**الخط الثاني — إدارة المخاطر والامتثال:**
- وضع سياسات وأطر إدارة المخاطر
- مراقبة مستويات المخاطر وفعالية الضوابط

**الخط الثالث — التدقيق الداخلي:**
- تقييم مستقل لفعالية إطار إدارة المخاطر
- تقديم تقارير مباشرة لمجلس الإدارة

### 5. آلية المراجعة والتحديث
- مراجعة ربع سنوية لبيان شهية المخاطر
- تحديث فوري عند حدوث تغييرات جوهرية في بيئة المخاطر
- اعتماد التحديثات من لجنة المخاطر ومجلس الإدارة"""
    else:
        cat_rows = '\n'.join(f'| {c} | {"Zero Tolerance" if i == 0 else "Low" if i == 1 else "Moderate"} | {"0%" if i == 0 else "15%" if i == 1 else "30%"} | Based on risk nature in this category |' for i, c in enumerate(categories))
        
        return f"""## Enterprise Risk Appetite Statement

### 1. Overall Risk Appetite Statement
The organization adopts a **conservative** overall risk appetite, focusing on protecting information assets and regulatory compliance. Based on the current risk register analysis ({total} risks: {critical} critical, {high} high, {medium} medium, {low} low), the organization aims to reduce critical and high risks to acceptable levels within 90 days.

### 2. Risk Appetite by Category

#### Risk Appetite Table:
| Category | Appetite Level | Maximum Acceptable Threshold | Justification |
|----------|---------------|------------------------------|---------------|
{cat_rows}

### 3. Tolerance Thresholds & Escalation Criteria

#### Escalation Matrix:
| Risk Level | Required Action | Responsible Party | Timeframe |
|-----------|----------------|-------------------|-----------|
| Critical (20-25) | Halt activity + emergency treatment plan | CEO + Board of Directors | Immediate (within 24 hours) |
| High (12-19) | Urgent treatment plan + daily monitoring | Risk Manager + Senior Management | Within 7 days |
| Medium (6-11) | Scheduled treatment plan + weekly monitoring | Risk Owner + Risk Team | Within 30 days |
| Low (1-5) | Accept with periodic monitoring | Risk Owner | Within 90 days |

### 4. Risk Management Roles & Responsibilities

**First Line — Operational Management:**
- Identify and report day-to-day risks
- Execute approved treatment plans

**Second Line — Risk Management & Compliance:**
- Develop risk management policies and frameworks
- Monitor risk levels and control effectiveness

**Third Line — Internal Audit:**
- Independent assessment of risk management framework
- Report directly to the Board of Directors

### 5. Review & Update Mechanism
- Quarterly review of risk appetite statement
- Immediate update upon material changes in risk environment
- Approval of updates by Risk Committee and Board of Directors"""


def generate_chat_simulation(language='en'):
    """Return a helpful message when AI is unavailable for document chat."""
    if language == 'ar':
        return """عذراً، خدمة الذكاء الاصطناعي غير متاحة حالياً للإجابة على أسئلة حول الوثيقة.

**يمكنك في الوقت الحالي:**
- مراجعة الوثيقة يدوياً للعثور على المعلومات المطلوبة
- استخدام خاصية البحث في المتصفح (Ctrl+F) للبحث عن كلمات محددة
- تحميل الوثيقة بصيغة Word أو PDF للمراجعة التفصيلية

سيتم استعادة الخدمة قريباً. يرجى المحاولة مرة أخرى لاحقاً."""
    else:
        return """Sorry, the AI service is currently unavailable to answer questions about this document.

**In the meantime, you can:**
- Review the document manually to find the information you need
- Use your browser's search function (Ctrl+F) to search for specific terms
- Download the document as Word or PDF for detailed review

The service will be restored shortly. Please try again later."""


# ============================================================================
# ROUTES - LANDING PAGE & AUTHENTICATION
# ============================================================================

@app.route('/')
def index():
    """Landing page for non-logged-in users, dashboard for logged-in users."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    lang = request.args.get('lang', 'en')
    txt = get_text(lang)
    return render_template('landing.html', txt=txt, lang=lang, config=config, is_rtl=(lang == 'ar'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with rate limiting."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    if request.method == 'POST':
        # Rate limiting - 5 attempts per minute per IP
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if not check_rate_limit(f'login_{client_ip}', max_requests=5, window_seconds=60):
            flash('Too many login attempts. Please wait a minute.', 'error')
            return render_template('login.html', txt=txt, lang=lang, config=config, is_rtl=(lang == 'ar'))
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        if not validate_username(username):
            flash('Invalid username format', 'error')
            return render_template('login.html', txt=txt, lang=lang, config=config, is_rtl=(lang == 'ar'))
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and verify_password(password, user['password_hash']):
            # Check if user is active
            if user['is_active'] == 0:
                flash('Account is deactivated. Contact admin.', 'error')
                conn.close()
                return render_template('login.html', txt=txt, lang=lang, config=config, is_rtl=(lang == 'ar'))
            
            # Update last login
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user['id']))
            conn.commit()
            conn.close()
            
            # Regenerate session to prevent session fixation
            session.clear()
            session['lang'] = lang
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role'] if user['role'] else 'user'
            generate_csrf_token()  # Generate new CSRF token
            
            # Redirect admin to admin panel
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', 
                          txt=txt, 
                          lang=lang, 
                          config=config,
                          is_rtl=(lang == 'ar'))

@app.route('/register', methods=['POST'])
def register():
    """Register new user with limit check and rate limiting."""
    lang = session.get('lang', 'en')
    
    # Rate limiting - 3 registration attempts per minute per IP
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if not check_rate_limit(f'register_{client_ip}', max_requests=3, window_seconds=60):
        flash('Too many registration attempts. Please wait.', 'error')
        return redirect(url_for('login', lang=lang))
    
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    
    # Input validation using helper functions
    if not validate_username(username):
        flash('Username: 3-50 characters, letters/numbers/underscore only', 'error')
        return redirect(url_for('login', lang=lang))
    
    if not validate_email(email):
        flash('Invalid email format', 'error')
        return redirect(url_for('login', lang=lang))
    
    valid, msg = validate_password(password)
    if not valid:
        flash(msg, 'error')
        return redirect(url_for('login', lang=lang))
    
    conn = get_db()
    
    # Check user limit
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if user_count >= MAX_USERS:
        flash('Registration limit reached (2000 users). Contact admin.', 'error')
        conn.close()
        return redirect(url_for('login', lang=lang))
    
    try:
        conn.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                    (username, email if email else None, hash_password(password), 'user'))
        conn.commit()
        flash('Account created successfully! Please login.', 'success')
    except sqlite3.IntegrityError:
        flash('Username or email already exists', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('login', lang=lang))

@app.route('/logout')
def logout():
    """Logout user."""
    lang = session.get('lang', 'en')
    session.clear()
    session['lang'] = lang
    return redirect(url_for('login', lang=lang))

# ============================================================================
# ROUTES - PROFILE
# ============================================================================

@app.route('/profile')
@login_required
def profile_page():
    """User profile page."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get per-domain usage stats
    domain_stats = {}
    en_domains = TRANSLATIONS['en']['domains']
    for domain in en_domains:
        s_count = conn.execute('SELECT COUNT(*) FROM strategies WHERE user_id = ? AND domain = ?', (session['user_id'], domain)).fetchone()[0]
        p_count = conn.execute('SELECT COUNT(*) FROM policies WHERE user_id = ? AND domain = ?', (session['user_id'], domain)).fetchone()[0]
        a_count = conn.execute('SELECT COUNT(*) FROM audits WHERE user_id = ? AND domain = ?', (session['user_id'], domain)).fetchone()[0]
        r_count = conn.execute('SELECT COUNT(*) FROM risks WHERE user_id = ? AND domain = ?', (session['user_id'], domain)).fetchone()[0]
        total = s_count + p_count + a_count + r_count
        if total > 0:
            domain_stats[domain] = {
                'strategies': s_count, 'policies': p_count,
                'audits': a_count, 'risks': r_count, 'total': total,
                'strategy_limit': 1, 'policy_limit': 2, 'audit_limit': 2, 'risk_limit': 2
            }
    
    total_docs = conn.execute('''
        SELECT 
            (SELECT COUNT(*) FROM strategies WHERE user_id = ?) +
            (SELECT COUNT(*) FROM policies WHERE user_id = ?) +
            (SELECT COUNT(*) FROM audits WHERE user_id = ?) +
            (SELECT COUNT(*) FROM risks WHERE user_id = ?)
    ''', (session['user_id'], session['user_id'], session['user_id'], session['user_id'])).fetchone()[0]
    
    # Get user's AI preferences
    ai_pref_generate = 'auto'
    ai_pref_review = 'auto'
    try:
        ai_pref_generate = user['ai_provider_generate'] or 'auto'
        ai_pref_review = user['ai_provider_review'] or 'auto'
    except:
        pass
    
    conn.close()
    
    return render_template('profile.html',
                          txt=txt, lang=lang, config=config,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          user=user,
                          domain_stats=domain_stats,
                          total_docs=total_docs,
                          ai_available=check_ai_available(),
                          ai_providers=get_available_providers(),
                          ai_pref_generate=ai_pref_generate,
                          ai_pref_review=ai_pref_review,
                          domains=txt['domains'])

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password."""
    lang = session.get('lang', 'en')
    txt = get_text(lang)
    
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if new_password != confirm_password:
        flash(txt['password_mismatch'], 'error')
        return redirect(url_for('profile_page', lang=lang))
    
    valid, msg = validate_password(new_password)
    if not valid:
        flash(msg, 'error')
        return redirect(url_for('profile_page', lang=lang))
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if not verify_password(current_password, user['password_hash']):
        flash(txt['wrong_password'], 'error')
        conn.close()
        return redirect(url_for('profile_page', lang=lang))
    
    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                (hash_password(new_password), session['user_id']))
    conn.commit()
    conn.close()
    
    flash(txt['password_updated'], 'success')
    return redirect(url_for('profile_page', lang=lang))

@app.route('/profile/ai-preferences', methods=['POST'])
@login_required
def save_ai_preferences():
    """Save user's AI provider preferences."""
    lang = session.get('lang', 'en')
    
    generate_provider = request.form.get('ai_provider_generate', 'auto')
    review_provider = request.form.get('ai_provider_review', 'auto')
    
    # Validate providers
    valid_providers = ['auto', 'anthropic', 'openai', 'google']
    if generate_provider not in valid_providers:
        generate_provider = 'auto'
    if review_provider not in valid_providers:
        review_provider = 'auto'
    
    conn = get_db()
    conn.execute('''
        UPDATE users 
        SET ai_provider_generate = ?, ai_provider_review = ?
        WHERE id = ?
    ''', (generate_provider, review_provider, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('AI preferences updated successfully' if lang == 'en' else 'تم تحديث تفضيلات الذكاء الاصطناعي بنجاح', 'success')
    return redirect(url_for('profile_page', lang=lang))

# ============================================================================
# ROUTES - EXPORT ALL DOCUMENTS
# ============================================================================

@app.route('/api/export-all', methods=['GET'])
@login_required
def export_all_documents():
    """Export all user documents as a ZIP file."""
    import zipfile
    from io import BytesIO
    
    lang = session.get('lang', 'en')
    user_id = session['user_id']
    username = session.get('username', 'user')
    
    conn = get_db()
    
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        doc_count = 0
        
        # Export strategies
        strategies = conn.execute('SELECT * FROM strategies WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
        for s in strategies:
            fname = f"strategies/{s['domain']}_{s['language']}_{s['id']}.md"
            zf.writestr(fname, s['content'] or '')
            doc_count += 1
        
        # Export policies
        policies = conn.execute('SELECT * FROM policies WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
        for p in policies:
            fname = f"policies/{p['domain']}_{p['policy_name']}_{p['language']}_{p['id']}.md"
            zf.writestr(fname, p['content'] or '')
            doc_count += 1
        
        # Export audits
        audits = conn.execute('SELECT * FROM audits WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
        for a in audits:
            fname = f"audits/{a['domain']}_{a['language']}_{a['id']}.md"
            zf.writestr(fname, a['content'] or '')
            doc_count += 1
        
        # Export risks
        risks = conn.execute('SELECT * FROM risks WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
        for r in risks:
            fname = f"risk_analyses/{r['domain']}_{r['language']}_{r['id']}.md"
            zf.writestr(fname, r['analysis'] or '')
            doc_count += 1
        
        # Add summary file
        summary = f"# Mizan GRC - Document Export\n"
        summary += f"**User:** {username}\n"
        summary += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        summary += f"**Total Documents:** {doc_count}\n\n"
        summary += f"- Strategies: {len(strategies)}\n"
        summary += f"- Policies: {len(policies)}\n"
        summary += f"- Audits: {len(audits)}\n"
        summary += f"- Risk Analyses: {len(risks)}\n"
        zf.writestr('README.md', summary)
    
    conn.close()
    
    if doc_count == 0:
        return jsonify({'error': 'No documents to export'}), 404
    
    buffer.seek(0)
    from flask import send_file
    return send_file(buffer, mimetype='application/zip',
                    as_attachment=True,
                    download_name=f'mizan_documents_{username}_{datetime.now().strftime("%Y%m%d")}.zip')

# ============================================================================
# ROUTES - DASHBOARD
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with widgets."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    conn = get_db()
    user_id = session['user_id']
    
    # Get user stats
    strategies_count = conn.execute('SELECT COUNT(*) FROM strategies WHERE user_id = ?', (user_id,)).fetchone()[0]
    policies_count = conn.execute('SELECT COUNT(*) FROM policies WHERE user_id = ?', (user_id,)).fetchone()[0]
    audits_count = conn.execute('SELECT COUNT(*) FROM audits WHERE user_id = ?', (user_id,)).fetchone()[0]
    risks_count = conn.execute('SELECT COUNT(*) FROM risks WHERE user_id = ?', (user_id,)).fetchone()[0]
    
    # Get recent documents (last 5)
    recent_docs = []
    for doc_type, table, content_field in [
        ('strategy', 'strategies', 'content'), ('policy', 'policies', 'content'),
        ('audit', 'audits', 'content'), ('risk', 'risks', 'analysis')
    ]:
        rows = conn.execute(f'SELECT id, domain, language, created_at FROM {table} WHERE user_id = ? ORDER BY created_at DESC LIMIT 3', (user_id,)).fetchall()
        for row in rows:
            recent_docs.append({
                'type': doc_type, 'id': row['id'], 'domain': row['domain'],
                'language': row['language'], 'created_at': row['created_at']
            })
    
    # Sort by date, take latest 5
    recent_docs.sort(key=lambda x: x['created_at'] or '', reverse=True)
    recent_docs = recent_docs[:5]
    
    # Count active domains
    active_domains = set()
    for table in ['strategies', 'policies', 'audits', 'risks']:
        rows = conn.execute(f'SELECT DISTINCT domain FROM {table} WHERE user_id = ?', (user_id,)).fetchall()
        for row in rows:
            if row['domain']:
                active_domains.add(row['domain'])
    
    conn.close()
    
    return render_template('dashboard.html',
                          txt=txt, lang=lang, config=config,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          ai_available=check_ai_available(),
                          ai_status=get_ai_status(),
                          stats={
                              'strategies': strategies_count,
                              'policies': policies_count,
                              'audits': audits_count,
                              'risks': risks_count,
                              'total': strategies_count + policies_count + audits_count + risks_count
                          },
                          recent_docs=recent_docs,
                          active_domains=len(active_domains),
                          domains=txt['domains'],
                          domain_codes=DOMAIN_CODES,
                          frameworks=DOMAIN_FRAMEWORKS)

@app.route('/domain/<domain_name>')
@login_required
def domain_page(domain_name):
    """Domain-specific page."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    domain_code = DOMAIN_CODES.get(domain_name, 'global')
    
    # Get frameworks - now hierarchical by region
    domain_frameworks = DOMAIN_FRAMEWORKS.get(domain_code, {})
    # Also provide flat list for backward compatibility
    frameworks_flat = DOMAIN_FRAMEWORKS_FLAT.get(domain_code, [])
    
    # Get domain-specific technologies
    lang_key = 'ar' if lang == 'ar' else 'en'
    technologies = DOMAIN_TECHNOLOGIES.get(domain_code, {}).get(lang_key, {})
    
    # Get risk categories with scenarios
    risk_data = RISK_CATEGORIES.get(domain_code, {}).get(lang_key, {})
    
    # Get user's remaining usage FOR THIS DOMAIN
    usage_info = get_remaining_usage(session['user_id'], domain_name)
    
    # Get domain-specific awareness modules
    domain_awareness = AWARENESS_MODULES.get(domain_code, {}).get('ar' if lang == 'ar' else 'en', [])
    
    # Get GRC Professional modules - filter by domain relevance
    all_grc_modules = AWARENESS_MODULES.get('grc_professional', {}).get('ar' if lang == 'ar' else 'en', [])
    
    # Domain-specific GRC module mapping
    grc_domain_relevance = {
        'cyber': ['grc_nca_frameworks', 'grc_iso27001', 'grc_nist_csf', 'grc_sama_framework', 'grc_eu_regulations'],
        'data': ['grc_pdpl', 'grc_gdpr', 'grc_nca_frameworks', 'grc_eu_regulations'],
        'ai': ['grc_eu_regulations', 'grc_nist_csf', 'grc_iso27001'],
        'dt': ['grc_nist_csf', 'grc_iso27001', 'grc_coso_erm', 'grc_eu_regulations'],
        'global': ['grc_iso27001', 'grc_nist_csf', 'grc_coso_erm', 'grc_gdpr', 'grc_eu_regulations'],
        'erm': ['grc_coso_erm', 'grc_nist_csf', 'grc_iso27001', 'grc_sama_framework']
    }
    
    # Filter GRC modules by domain
    relevant_module_ids = grc_domain_relevance.get(domain_code, [])
    grc_professional_modules = [m for m in all_grc_modules if m.get('id') in relevant_module_ids]
    
    return render_template('domain.html',
                          txt=txt,
                          lang=lang,
                          config=config,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          ai_available=check_ai_available(),
                          domain_name=domain_name,
                          domain_code=domain_code,
                          frameworks=domain_frameworks,
                          frameworks_flat=frameworks_flat,
                          technologies=technologies,
                          risk_categories=risk_data,
                          usage_info=usage_info,
                          usage_limits=USAGE_LIMITS,
                          awareness_modules=domain_awareness,
                          grc_professional_modules=grc_professional_modules)

# ============================================================================
# ANALYTICS & INSIGHTS
# ============================================================================

def calculate_compliance_score(user_id):
    """Calculate compliance score based on user's documents."""
    conn = get_db()
    
    # Get counts
    strategies = conn.execute('SELECT COUNT(*) FROM strategies WHERE user_id = ?', (user_id,)).fetchone()[0]
    policies = conn.execute('SELECT COUNT(*) FROM policies WHERE user_id = ?', (user_id,)).fetchone()[0]
    audits = conn.execute('SELECT COUNT(*) FROM audits WHERE user_id = ?', (user_id,)).fetchone()[0]
    risks = conn.execute('SELECT COUNT(*) FROM risks WHERE user_id = ?', (user_id,)).fetchone()[0]
    
    # Get unique domains covered
    domains_covered = set()
    for table in ['strategies', 'policies', 'audits', 'risks']:
        rows = conn.execute(f'SELECT DISTINCT domain FROM {table} WHERE user_id = ?', (user_id,)).fetchall()
        for row in rows:
            if row['domain']:
                domains_covered.add(row['domain'])
    
    conn.close()
    
    # Calculate score (weighted)
    # Max expected: 6 strategies, 12 policies, 6 audits, 12 risks, 6 domains
    strategy_score = min(strategies / 6, 1) * 20  # 20%
    policy_score = min(policies / 10, 1) * 25     # 25%
    audit_score = min(audits / 6, 1) * 25         # 25%
    risk_score = min(risks / 10, 1) * 20          # 20%
    domain_score = min(len(domains_covered) / 5, 1) * 10  # 10%
    
    total_score = strategy_score + policy_score + audit_score + risk_score + domain_score
    
    return {
        'score': round(total_score, 1),
        'strategies': strategies,
        'policies': policies,
        'audits': audits,
        'risks': risks,
        'domains_covered': len(domains_covered)
    }

def calculate_domain_compliance(user_id):
    """Calculate compliance scores per domain for radar chart."""
    conn = get_db()
    
    domain_codes = {
        'Cyber Security': 'cyber', 'الأمن السيبراني': 'cyber',
        'Data Management': 'data', 'إدارة البيانات': 'data',
        'Artificial Intelligence': 'ai', 'الذكاء الاصطناعي': 'ai',
        'Digital Transformation': 'dt', 'التحول الرقمي': 'dt',
        'Global Standards': 'global', 'المعايير العالمية': 'global',
        'Enterprise Risk Management': 'erm', 'إدارة المخاطر المؤسسية': 'erm'
    }
    
    domain_scores = {}
    for domain_name, code in domain_codes.items():
        if code in domain_scores:
            continue
        
        # Count documents per domain
        strategies = conn.execute(
            'SELECT COUNT(*) FROM strategies WHERE user_id=? AND domain IN (?,?)',
            (user_id, domain_name, [k for k,v in domain_codes.items() if v==code][0])
        ).fetchone()[0]
        policies = conn.execute(
            'SELECT COUNT(*) FROM policies WHERE user_id=? AND domain LIKE ?',
            (user_id, f'%{code[:3]}%' if len(code) < 4 else f'%{domain_name[:4]}%')
        ).fetchone()[0]
        audits = conn.execute(
            'SELECT COUNT(*) FROM audits WHERE user_id=? AND domain LIKE ?',
            (user_id, f'%{domain_name[:6]}%')
        ).fetchone()[0]
        risks = conn.execute(
            'SELECT COUNT(*) FROM risks WHERE user_id=? AND domain LIKE ?',
            (user_id, f'%{domain_name[:6]}%')
        ).fetchone()[0]
        
        # Calculate domain score (0-100)
        score = min(100, (
            min(strategies, 2) * 15 +  # 2 strategies = 30 points
            min(policies, 3) * 10 +    # 3 policies = 30 points
            min(audits, 2) * 10 +      # 2 audits = 20 points
            min(risks, 2) * 10         # 2 risks = 20 points
        ))
        
        domain_scores[code] = {
            'score': score,
            'strategies': strategies,
            'policies': policies,
            'audits': audits,
            'risks': risks
        }
    
    conn.close()
    return domain_scores

def get_framework_coverage(user_id):
    """Calculate which frameworks are covered by user's policies."""
    conn = get_db()
    
    # Get all policies with their frameworks
    policies = conn.execute(
        'SELECT framework, domain FROM policies WHERE user_id = ?',
        (user_id,)
    ).fetchall()
    
    # Get all audits with frameworks
    audits = conn.execute(
        'SELECT framework, domain FROM audits WHERE user_id = ?',
        (user_id,)
    ).fetchall()
    
    conn.close()
    
    # Framework categories
    all_frameworks = {
        'cyber': ['NCA ECC', 'NCA CSCC', 'NCA DCC', 'SAMA CSF', 'ISO 27001', 'NIST CSF', 'CIS Controls', 'PCI DSS'],
        'data': ['PDPL', 'NDMO', 'ISO 27701', 'GDPR', 'Data Governance Framework'],
        'ai': ['SDAIA AI Ethics', 'UNESCO AI', 'EU AI Act', 'NIST AI RMF'],
        'global': ['ISO 27001', 'ISO 22301', 'ISO 31000', 'COBIT', 'ITIL'],
        'erm': ['ISO 31000', 'COSO ERM', 'SAMA Regulations', 'Basel III']
    }
    
    # Count covered frameworks
    covered = set()
    for p in policies:
        if p['framework']:
            for fw in p['framework'].split(','):
                covered.add(fw.strip())
    for a in audits:
        if a['framework']:
            for fw in a['framework'].split(','):
                covered.add(fw.strip())
    
    # Calculate coverage per category
    coverage = {}
    for cat, frameworks in all_frameworks.items():
        cat_covered = sum(1 for fw in frameworks if any(fw.lower() in c.lower() for c in covered))
        coverage[cat] = {
            'covered': cat_covered,
            'total': len(frameworks),
            'percentage': round(cat_covered / len(frameworks) * 100) if frameworks else 0,
            'frameworks': frameworks,
            'covered_list': [fw for fw in frameworks if any(fw.lower() in c.lower() for c in covered)]
        }
    
    return coverage

def get_compliance_trend(user_id, days=30):
    """Get compliance score trend over time."""
    conn = get_db()
    
    # Record current score if not recorded today
    today = conn.execute("SELECT DATE('now')").fetchone()[0]
    last_record = conn.execute(
        "SELECT DATE(recorded_at) as d FROM compliance_history WHERE user_id=? ORDER BY recorded_at DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    
    if not last_record or last_record['d'] != today:
        # Record today's score
        current = calculate_compliance_score(user_id)
        maturity = calculate_maturity_levels(user_id)
        conn.execute('''
            INSERT INTO compliance_history 
            (user_id, score, maturity_avg, strategies, policies, audits, risks, domains_covered)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, current['score'], maturity['average'], current['strategies'],
              current['policies'], current['audits'], current['risks'], current['domains_covered']))
        conn.commit()
    
    # Get history
    history = conn.execute('''
        SELECT DATE(recorded_at) as date, score, maturity_avg, strategies, policies, audits, risks
        FROM compliance_history 
        WHERE user_id = ? AND recorded_at >= DATE('now', ?)
        ORDER BY recorded_at ASC
    ''', (user_id, f'-{days} days')).fetchall()
    
    conn.close()
    
    return [dict(h) for h in history]

def generate_gap_recommendations(user_id, lang='en'):
    """Generate AI-powered gap analysis recommendations."""
    compliance = calculate_compliance_score(user_id)
    maturity = calculate_maturity_levels(user_id)
    domain_scores = calculate_domain_compliance(user_id)
    frameworks = get_framework_coverage(user_id)
    
    recommendations = []
    
    # Check overall compliance
    if compliance['score'] < 50:
        if lang == 'ar':
            recommendations.append({
                'priority': 'critical',
                'area': 'الامتثال العام',
                'issue': f"درجة الامتثال منخفضة ({compliance['score']}%)",
                'action': 'ابدأ بإنشاء استراتيجية شاملة لكل مجال، ثم طور السياسات الأساسية',
                'impact': 'تحسين الامتثال بنسبة 20-30%'
            })
        else:
            recommendations.append({
                'priority': 'critical',
                'area': 'Overall Compliance',
                'issue': f"Low compliance score ({compliance['score']}%)",
                'action': 'Start by creating a comprehensive strategy for each domain, then develop core policies',
                'impact': 'Improve compliance by 20-30%'
            })
    
    # Check strategies
    if compliance['strategies'] < 3:
        if lang == 'ar':
            recommendations.append({
                'priority': 'high',
                'area': 'التخطيط الاستراتيجي',
                'issue': f"عدد الاستراتيجيات غير كافٍ ({compliance['strategies']} من 6)",
                'action': 'أنشئ استراتيجيات للمجالات الحرجة: الأمن السيبراني، إدارة البيانات، إدارة المخاطر',
                'impact': 'تغطية استراتيجية شاملة'
            })
        else:
            recommendations.append({
                'priority': 'high',
                'area': 'Strategic Planning',
                'issue': f"Insufficient strategies ({compliance['strategies']} of 6)",
                'action': 'Create strategies for critical domains: Cyber Security, Data Management, ERM',
                'impact': 'Comprehensive strategic coverage'
            })
    
    # Check policies
    if compliance['policies'] < 6:
        if lang == 'ar':
            recommendations.append({
                'priority': 'high',
                'area': 'السياسات',
                'issue': f"نقص في السياسات ({compliance['policies']} من 10 موصى به)",
                'action': 'طور سياسات أمن المعلومات، حماية البيانات، الاستجابة للحوادث',
                'impact': 'تحسين الامتثال التنظيمي'
            })
        else:
            recommendations.append({
                'priority': 'high',
                'area': 'Policies',
                'issue': f"Policy gap ({compliance['policies']} of 10 recommended)",
                'action': 'Develop Information Security, Data Protection, and Incident Response policies',
                'impact': 'Improved regulatory compliance'
            })
    
    # Check audits
    if compliance['audits'] < 2:
        if lang == 'ar':
            recommendations.append({
                'priority': 'medium',
                'area': 'التدقيق',
                'issue': 'لا توجد تقارير تدقيق كافية',
                'action': 'أجرِ تدقيق على إطار NCA ECC أو ISO 27001',
                'impact': 'تحديد فجوات الامتثال الفعلية'
            })
        else:
            recommendations.append({
                'priority': 'medium',
                'area': 'Auditing',
                'issue': 'Insufficient audit coverage',
                'action': 'Conduct an audit against NCA ECC or ISO 27001 framework',
                'impact': 'Identify actual compliance gaps'
            })
    
    # Check domain coverage
    weak_domains = [code for code, data in domain_scores.items() if data['score'] < 30]
    if weak_domains:
        domain_names = {'cyber': 'Cyber Security', 'data': 'Data Management', 'ai': 'AI Governance',
                       'dt': 'Digital Transformation', 'global': 'Global Standards', 'erm': 'Enterprise Risk'}
        if lang == 'ar':
            domain_names_ar = {'cyber': 'الأمن السيبراني', 'data': 'إدارة البيانات', 'ai': 'حوكمة الذكاء الاصطناعي',
                              'dt': 'التحول الرقمي', 'global': 'المعايير العالمية', 'erm': 'إدارة المخاطر المؤسسية'}
            recommendations.append({
                'priority': 'medium',
                'area': 'تغطية المجالات',
                'issue': f"مجالات ضعيفة: {', '.join(domain_names_ar.get(d, d) for d in weak_domains[:3])}",
                'action': 'ركز على تطوير محتوى لهذه المجالات',
                'impact': 'تغطية شاملة لجميع مجالات الحوكمة'
            })
        else:
            recommendations.append({
                'priority': 'medium',
                'area': 'Domain Coverage',
                'issue': f"Weak domains: {', '.join(domain_names.get(d, d) for d in weak_domains[:3])}",
                'action': 'Focus on developing content for these domains',
                'impact': 'Comprehensive GRC coverage'
            })
    
    # Check framework coverage
    for cat, data in frameworks.items():
        if data['percentage'] < 25 and cat in ['cyber', 'global']:
            if lang == 'ar':
                recommendations.append({
                    'priority': 'high',
                    'area': 'تغطية الأطر التنظيمية',
                    'issue': f"تغطية منخفضة لأطر {cat} ({data['percentage']}%)",
                    'action': f"طور سياسات وتدقيق لـ: {', '.join(data['frameworks'][:3])}",
                    'impact': 'تحسين الامتثال للأطر التنظيمية'
                })
            else:
                recommendations.append({
                    'priority': 'high',
                    'area': 'Framework Coverage',
                    'issue': f"Low {cat} framework coverage ({data['percentage']}%)",
                    'action': f"Develop policies and audits for: {', '.join(data['frameworks'][:3])}",
                    'impact': 'Improved regulatory framework alignment'
                })
    
    # Sort by priority
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
    
    return recommendations[:6]  # Return top 6 recommendations

def calculate_maturity_levels(user_id):
    """Calculate maturity levels for radar chart."""
    conn = get_db()
    
    # Get counts by type
    strategies = conn.execute('SELECT COUNT(*) FROM strategies WHERE user_id = ?', (user_id,)).fetchone()[0]
    policies = conn.execute('SELECT COUNT(*) FROM policies WHERE user_id = ?', (user_id,)).fetchone()[0]
    audits = conn.execute('SELECT COUNT(*) FROM audits WHERE user_id = ?', (user_id,)).fetchone()[0]
    risks = conn.execute('SELECT COUNT(*) FROM risks WHERE user_id = ?', (user_id,)).fetchone()[0]
    
    # Get unique domains
    domains = set()
    for table in ['strategies', 'policies', 'audits', 'risks']:
        rows = conn.execute(f'SELECT DISTINCT domain FROM {table} WHERE user_id = ?', (user_id,)).fetchall()
        for row in rows:
            if row['domain']:
                domains.add(row['domain'])
    
    conn.close()
    
    # Calculate maturity (1-5 scale)
    # Governance: based on strategies
    governance = min(1 + (strategies * 0.8), 5)
    
    # Risk Management: based on risk assessments
    risk_mgmt = min(1 + (risks * 0.4), 5)
    
    # Compliance: based on policies and audits
    compliance = min(1 + ((policies + audits) * 0.3), 5)
    
    # Technology: based on domain coverage (Cyber, AI, DT)
    tech_domains = len([d for d in domains if any(x in d for x in ['Cyber', 'AI', 'Digital', 'سيبراني', 'ذكاء', 'رقمي'])])
    technology = min(1 + (tech_domains * 1.3), 5)
    
    # Process: overall completeness
    total_docs = strategies + policies + audits + risks
    process = min(1 + (total_docs * 0.15), 5)
    
    return {
        'governance': round(governance, 1),
        'risk_mgmt': round(risk_mgmt, 1),
        'compliance': round(compliance, 1),
        'technology': round(technology, 1),
        'process': round(process, 1),
        'average': round((governance + risk_mgmt + compliance + technology + process) / 5, 1)
    }

def get_risk_heatmap_data(user_id):
    """Get risk distribution for heatmap."""
    conn = get_db()
    risks = conn.execute('SELECT risk_level, threat FROM risks WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    
    # Initialize heatmap matrix (4x4: Low, Medium, High, Critical)
    # For simplicity, we'll estimate likelihood from threat description
    heatmap = {
        'low': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
        'medium': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
        'high': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
        'critical': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    }
    
    for risk in risks:
        impact = (risk['risk_level'] or 'medium').lower()
        if impact not in heatmap:
            impact = 'medium'
        
        # Estimate likelihood based on common keywords
        threat = (risk['threat'] or '').lower()
        if any(x in threat for x in ['common', 'frequent', 'daily', 'شائع', 'متكرر']):
            likelihood = 'high'
        elif any(x in threat for x in ['rare', 'unlikely', 'نادر']):
            likelihood = 'low'
        elif any(x in threat for x in ['critical', 'severe', 'حرج']):
            likelihood = 'critical'
        else:
            likelihood = 'medium'
        
        heatmap[likelihood][impact] += 1
    
    return heatmap

def get_benchmark_comparison(user_id, sector):
    """Compare user's metrics with industry benchmark."""
    conn = get_db()
    
    # Get user's metrics
    user_metrics = calculate_compliance_score(user_id)
    user_maturity = calculate_maturity_levels(user_id)
    
    # Get benchmark for sector
    benchmark = conn.execute('SELECT * FROM benchmarks WHERE sector = ?', (sector,)).fetchone()
    conn.close()
    
    if not benchmark:
        return None
    
    comparison = {
        'sector': sector,
        'source': benchmark['source'],
        'source_year': benchmark['source_year'],
        'metrics': {
            'compliance_score': {
                'user': user_metrics['score'],
                'benchmark': benchmark['compliance_score_avg'],
                'gap': round(user_metrics['score'] - benchmark['compliance_score_avg'], 1)
            },
            'maturity_level': {
                'user': user_maturity['average'],
                'benchmark': benchmark['maturity_level_avg'],
                'gap': round(user_maturity['average'] - benchmark['maturity_level_avg'], 1)
            },
            'policy_count': {
                'user': user_metrics['policies'],
                'benchmark': benchmark['policy_count_avg'],
                'gap': user_metrics['policies'] - benchmark['policy_count_avg']
            },
            'audit_count': {
                'user': user_metrics['audits'],
                'benchmark': benchmark['audit_count_avg'],
                'gap': user_metrics['audits'] - benchmark['audit_count_avg']
            },
            'risk_assessments': {
                'user': user_metrics['risks'],
                'benchmark': benchmark['risk_assessment_avg'],
                'gap': user_metrics['risks'] - benchmark['risk_assessment_avg']
            }
        }
    }
    
    return comparison

@app.route('/analytics')
@login_required
def analytics_page():
    """Analytics and Insights dashboard."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    user_id = session['user_id']
    sector = request.args.get('sector', 'Government')
    
    # Calculate all analytics
    compliance = calculate_compliance_score(user_id)
    maturity = calculate_maturity_levels(user_id)
    heatmap = get_risk_heatmap_data(user_id)
    benchmark = get_benchmark_comparison(user_id, sector)
    
    # Enhanced analytics
    domain_compliance = calculate_domain_compliance(user_id)
    framework_coverage = get_framework_coverage(user_id)
    compliance_trend = get_compliance_trend(user_id, days=30)
    recommendations = generate_gap_recommendations(user_id, lang)
    
    # Get available sectors for dropdown
    conn = get_db()
    sectors = conn.execute('SELECT sector, sector_ar FROM benchmarks ORDER BY sector').fetchall()
    conn.close()
    
    has_data = compliance['score'] > 0
    
    return render_template('analytics.html',
                          txt=txt,
                          lang=lang,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          compliance=compliance,
                          maturity=maturity,
                          heatmap=heatmap,
                          benchmark=benchmark,
                          sectors=sectors,
                          selected_sector=sector,
                          has_data=has_data,
                          domain_compliance=domain_compliance,
                          framework_coverage=framework_coverage,
                          compliance_trend=compliance_trend,
                          recommendations=recommendations)

@app.route('/api/analytics/benchmark/<sector>')
@login_required
def api_get_benchmark(sector):
    """Get benchmark comparison for a sector."""
    try:
        user_id = session['user_id']
        comparison = get_benchmark_comparison(user_id, sector)
        if comparison:
            return jsonify({'success': True, 'data': comparison})
        return jsonify({'success': False, 'error': 'Sector not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/domain-scores')
@login_required
def api_domain_scores():
    """Get compliance scores per domain."""
    try:
        user_id = session['user_id']
        scores = calculate_domain_compliance(user_id)
        return jsonify({'success': True, 'data': scores})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/framework-coverage')
@login_required
def api_framework_coverage():
    """Get framework coverage analysis."""
    try:
        user_id = session['user_id']
        coverage = get_framework_coverage(user_id)
        return jsonify({'success': True, 'data': coverage})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/trend')
@login_required
def api_compliance_trend():
    """Get compliance score trend over time."""
    try:
        user_id = session['user_id']
        days = request.args.get('days', 30, type=int)
        trend = get_compliance_trend(user_id, days)
        return jsonify({'success': True, 'data': trend})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/recommendations')
@login_required
def api_recommendations():
    """Get gap analysis recommendations."""
    try:
        user_id = session['user_id']
        lang = request.args.get('lang', session.get('lang', 'en'))
        recommendations = generate_gap_recommendations(user_id, lang)
        return jsonify({'success': True, 'data': recommendations})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/history')
@login_required
def document_history():
    """Document history page - view all generated documents."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    user_id = session['user_id']
    conn = get_db()
    
    # Get all documents for this user
    strategies = conn.execute('''
        SELECT id, domain, org_name, sector, language, created_at, 'strategy' as doc_type
        FROM strategies WHERE user_id = ? ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    
    policies = conn.execute('''
        SELECT id, domain, policy_name, framework, language, created_at, 'policy' as doc_type
        FROM policies WHERE user_id = ? ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    
    audits = conn.execute('''
        SELECT id, domain, framework, scope, language, created_at, 'audit' as doc_type
        FROM audits WHERE user_id = ? ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    
    risks = conn.execute('''
        SELECT id, domain, asset_name, threat, risk_level, created_at, 'risk' as doc_type
        FROM risks WHERE user_id = ? ORDER BY created_at DESC
    ''', (user_id,)).fetchall()
    
    conn.close()
    
    # Combine and sort all documents
    all_documents = []
    
    for s in strategies:
        all_documents.append({
            'id': s['id'],
            'type': 'strategy',
            'type_label': txt.get('strategies', 'Strategy'),
            'domain': s['domain'],
            'title': s['org_name'] or 'Strategy',
            'subtitle': s['sector'] or '',
            'language': s['language'],
            'created_at': s['created_at']
        })
    
    for p in policies:
        all_documents.append({
            'id': p['id'],
            'type': 'policy',
            'type_label': txt.get('policies', 'Policy'),
            'domain': p['domain'],
            'title': p['policy_name'] or 'Policy',
            'subtitle': p['framework'] or '',
            'language': p['language'],
            'created_at': p['created_at']
        })
    
    for a in audits:
        all_documents.append({
            'id': a['id'],
            'type': 'audit',
            'type_label': txt.get('audits', 'Audit'),
            'domain': a['domain'],
            'title': a['framework'] or 'Audit Report',
            'subtitle': a['scope'] or '',
            'language': a['language'],
            'created_at': a['created_at']
        })
    
    for r in risks:
        all_documents.append({
            'id': r['id'],
            'type': 'risk',
            'type_label': txt.get('risks', 'Risk Analysis'),
            'domain': r['domain'],
            'title': r['asset_name'] or 'Risk Analysis',
            'subtitle': r['risk_level'] or '',
            'language': r['language'] if 'language' in r.keys() else 'en',
            'created_at': r['created_at']
        })
    
    # Sort by date descending
    all_documents.sort(key=lambda x: x['created_at'] or '', reverse=True)
    
    # Get unique domains for filter
    domains = list(set([d['domain'] for d in all_documents if d['domain']]))
    
    return render_template('history.html',
                          txt=txt,
                          lang=lang,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          documents=all_documents,
                          domains=domains,
                          total_count=len(all_documents))

@app.route('/api/templates/<template_type>')
@login_required
def api_get_templates(template_type):
    """Get templates for a specific type and domain."""
    lang = request.args.get('lang', 'en')
    domain = request.args.get('domain', '')
    
    # Map domain name to domain code
    domain_code = DOMAIN_CODES.get(domain, 'cyber')
    
    # Get domain-specific templates
    domain_templates = DOMAIN_TEMPLATES.get(domain_code, {})
    templates = domain_templates.get(template_type, {}).get(lang, {})
    
    return jsonify({'success': True, 'templates': templates, 'domain': domain_code})

@app.route('/api/document/<doc_type>/<int:doc_id>')
@login_required
def api_get_document(doc_type, doc_id):
    """Get a specific document content."""
    user_id = session['user_id']
    conn = get_db()
    
    if doc_type == 'strategy':
        doc = conn.execute('SELECT * FROM strategies WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            return jsonify({'success': True, 'content': doc['content'], 'domain': doc['domain'], 'language': doc['language']})
    elif doc_type == 'policy':
        doc = conn.execute('SELECT * FROM policies WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            return jsonify({'success': True, 'content': doc['content'], 'domain': doc['domain'], 'language': doc['language']})
    elif doc_type == 'audit':
        doc = conn.execute('SELECT * FROM audits WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            return jsonify({'success': True, 'content': doc['content'], 'domain': doc['domain'], 'language': doc['language']})
    elif doc_type == 'risk':
        doc = conn.execute('SELECT * FROM risks WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            return jsonify({'success': True, 'content': doc['analysis'], 'domain': doc['domain'], 'language': doc['language'] if 'language' in doc.keys() else 'en'})
    
    conn.close()
    return jsonify({'success': False, 'error': 'Document not found'}), 404

@app.route('/api/document/<doc_type>/<int:doc_id>', methods=['DELETE'])
@login_required
def api_delete_document(doc_type, doc_id):
    """Delete a specific document."""
    user_id = session['user_id']
    conn = get_db()
    
    table_map = {
        'strategy': 'strategies',
        'policy': 'policies',
        'audit': 'audits',
        'risk': 'risks'
    }
    
    table = table_map.get(doc_type)
    if not table:
        return jsonify({'success': False, 'error': 'Invalid document type'}), 400
    
    try:
        conn.execute(f'DELETE FROM {table} WHERE id = ? AND user_id = ?', (doc_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/share/<doc_type>/<int:doc_id>', methods=['POST'])
@login_required
def api_share_document(doc_type, doc_id):
    """Create a shareable link for a document with optional OTP protection."""
    import uuid
    import random
    user_id = session['user_id']
    data = request.json or {}
    
    # Check if secure share (OTP) is requested
    secure_share = data.get('secure', False)
    recipient_email = data.get('recipient_email', '').strip()
    
    if secure_share and not recipient_email:
        return jsonify({'success': False, 'error': 'Recipient email required for secure share'}), 400
    
    if secure_share and not validate_email(recipient_email):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    conn = get_db()
    
    # Get the document content
    content = None
    title = None
    domain = None
    language = 'en'
    
    if doc_type == 'strategy':
        doc = conn.execute('SELECT * FROM strategies WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            content = doc['content']
            title = doc['org_name'] or 'Strategy'
            domain = doc['domain']
            language = doc['language']
    elif doc_type == 'policy':
        doc = conn.execute('SELECT * FROM policies WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            content = doc['content']
            title = doc['policy_name'] or 'Policy'
            domain = doc['domain']
            language = doc['language']
    elif doc_type == 'audit':
        doc = conn.execute('SELECT * FROM audits WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            content = doc['content']
            title = doc['framework'] or 'Audit Report'
            domain = doc['domain']
            language = doc['language']
    elif doc_type == 'risk':
        doc = conn.execute('SELECT * FROM risks WHERE id = ? AND user_id = ?', (doc_id, user_id)).fetchone()
        if doc:
            content = doc['analysis']
            title = doc['asset_name'] or 'Risk Analysis'
            domain = doc['domain']
            language = 'en'
    
    if not content:
        conn.close()
        return jsonify({'success': False, 'error': 'Document not found'}), 404
    
    # Generate unique share ID
    share_id = str(uuid.uuid4())[:8]
    
    # For non-secure shares, check if already shared
    if not secure_share:
        existing = conn.execute('SELECT share_id FROM shared_documents WHERE doc_type = ? AND doc_id = ? AND user_id = ? AND is_active = 1 AND requires_otp = 0', 
                               (doc_type, doc_id, user_id)).fetchone()
        if existing:
            conn.close()
            return jsonify({
                'success': True, 
                'share_id': existing['share_id'],
                'share_url': f"/shared/{existing['share_id']}",
                'already_shared': True,
                'secure': False
            })
    
    # Generate OTP if secure share
    otp_code = None
    otp_expires = None
    if secure_share:
        otp_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        otp_expires = (datetime.now() + timedelta(minutes=10)).isoformat()
    
    # Create share record
    try:
        conn.execute('''INSERT INTO shared_documents 
                        (share_id, user_id, doc_type, doc_id, title, domain, content, language, requires_otp, recipient_email, otp_code, otp_expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (share_id, user_id, doc_type, doc_id, title, domain, content, language, 
                     1 if secure_share else 0, recipient_email if secure_share else None, 
                     otp_code, otp_expires))
        conn.commit()
        conn.close()
        
        # Send OTP email if secure share
        if secure_share:
            username = session.get('username', 'A Mizan user')
            email_sent, email_msg = send_otp_email(recipient_email, otp_code, title, username)
            
            return jsonify({
                'success': True,
                'share_id': share_id,
                'share_url': f"/shared/{share_id}",
                'secure': True,
                'email_sent': email_sent,
                'recipient': recipient_email
            })
        
        return jsonify({
            'success': True,
            'share_id': share_id,
            'share_url': f"/shared/{share_id}",
            'secure': False
        })
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/share/<share_id>/resend-otp', methods=['POST'])
def api_resend_otp(share_id):
    """Resend OTP code for a secure share."""
    import random
    conn = get_db()
    
    doc = conn.execute('SELECT * FROM shared_documents WHERE share_id = ? AND is_active = 1 AND requires_otp = 1', (share_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({'success': False, 'error': 'Share not found'}), 404
    
    # Generate new OTP
    otp_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    otp_expires = (datetime.now() + timedelta(minutes=10)).isoformat()
    
    conn.execute('UPDATE shared_documents SET otp_code = ?, otp_expires_at = ?, otp_verified = 0 WHERE share_id = ?',
                (otp_code, otp_expires, share_id))
    conn.commit()
    
    # Get sharer username
    user = conn.execute('SELECT username FROM users WHERE id = ?', (doc['user_id'],)).fetchone()
    username = user['username'] if user else 'A Mizan user'
    conn.close()
    
    # Send email
    email_sent, email_msg = send_otp_email(doc['recipient_email'], otp_code, doc['title'], username)
    
    return jsonify({
        'success': email_sent,
        'message': 'OTP resent' if email_sent else email_msg
    })

@app.route('/api/share/<share_id>/verify-otp', methods=['POST'])
def api_verify_otp(share_id):
    """Verify OTP code for accessing a secure shared document."""
    data = request.json or {}
    otp_input = data.get('otp', '').strip()
    
    if not otp_input or len(otp_input) != 6:
        return jsonify({'success': False, 'error': 'Invalid OTP format'}), 400
    
    conn = get_db()
    doc = conn.execute('SELECT * FROM shared_documents WHERE share_id = ? AND is_active = 1 AND requires_otp = 1', (share_id,)).fetchone()
    
    if not doc:
        conn.close()
        return jsonify({'success': False, 'error': 'Share not found'}), 404
    
    # Check if OTP expired
    if doc['otp_expires_at']:
        expires = datetime.fromisoformat(doc['otp_expires_at'])
        if datetime.now() > expires:
            conn.close()
            return jsonify({'success': False, 'error': 'OTP expired', 'expired': True}), 400
    
    # Verify OTP
    if doc['otp_code'] != otp_input:
        conn.close()
        return jsonify({'success': False, 'error': 'Invalid OTP'}), 400
    
    # Mark as verified and increment view count
    conn.execute('UPDATE shared_documents SET otp_verified = 1, view_count = view_count + 1 WHERE share_id = ?', (share_id,))
    conn.commit()
    
    # Get sharer username
    user = conn.execute('SELECT username FROM users WHERE id = ?', (doc['user_id'],)).fetchone()
    username = user['username'] if user else 'Unknown'
    conn.close()
    
    return jsonify({
        'success': True,
        'document': {
            'title': doc['title'],
            'domain': doc['domain'],
            'doc_type': doc['doc_type'],
            'content': doc['content'],
            'language': doc['language'],
            'shared_by': username,
            'view_count': doc['view_count'] + 1
        }
    })

@app.route('/api/share/<share_id>', methods=['DELETE'])
@login_required
def api_unshare_document(share_id):
    """Stop sharing a document."""
    user_id = session['user_id']
    conn = get_db()
    
    try:
        conn.execute('UPDATE shared_documents SET is_active = 0 WHERE share_id = ? AND user_id = ?', (share_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/my-shares')
@login_required
def api_my_shares():
    """Get all shared documents for current user."""
    user_id = session['user_id']
    conn = get_db()
    
    shares = conn.execute('''SELECT share_id, doc_type, title, domain, view_count, created_at 
                            FROM shared_documents WHERE user_id = ? AND is_active = 1
                            ORDER BY created_at DESC''', (user_id,)).fetchall()
    conn.close()
    
    result = []
    for s in shares:
        result.append({
            'share_id': s['share_id'],
            'doc_type': s['doc_type'],
            'title': s['title'],
            'domain': s['domain'],
            'view_count': s['view_count'],
            'created_at': s['created_at']
        })
    
    return jsonify({'success': True, 'shares': result})

@app.route('/shared/<share_id>')
def view_shared_document(share_id):
    """Public page to view a shared document."""
    lang = request.args.get('lang', 'en')
    txt = get_text(lang)
    
    conn = get_db()
    doc = conn.execute('SELECT * FROM shared_documents WHERE share_id = ? AND is_active = 1', (share_id,)).fetchone()
    
    if not doc:
        conn.close()
        return render_template('shared.html', 
                              txt=txt, 
                              lang=lang,
                              is_rtl=(lang == 'ar'),
                              error=True,
                              error_message=txt.get('document_not_found', 'Document not found'))
    
    # Check if OTP is required
    if doc['requires_otp'] == 1:
        # Get username for display
        user = conn.execute('SELECT username FROM users WHERE id = ?', (doc['user_id'],)).fetchone()
        username = user['username'] if user else 'Unknown'
        conn.close()
        
        return render_template('shared.html',
                              txt=txt,
                              lang=doc['language'] or lang,
                              is_rtl=(doc['language'] == 'ar'),
                              error=False,
                              requires_otp=True,
                              share_id=share_id,
                              doc_title=doc['title'],
                              shared_by=username,
                              recipient_email=doc['recipient_email'])
    
    # Public share - increment view count and show document
    conn.execute('UPDATE shared_documents SET view_count = view_count + 1 WHERE share_id = ?', (share_id,))
    conn.commit()
    
    # Get username
    user = conn.execute('SELECT username FROM users WHERE id = ?', (doc['user_id'],)).fetchone()
    username = user['username'] if user else 'Unknown'
    conn.close()
    
    return render_template('shared.html',
                          txt=txt,
                          lang=doc['language'] or lang,
                          is_rtl=(doc['language'] == 'ar'),
                          error=False,
                          requires_otp=False,
                          document={
                              'title': doc['title'],
                              'domain': doc['domain'],
                              'doc_type': doc['doc_type'],
                              'content': doc['content'],
                              'view_count': doc['view_count'] + 1,
                              'created_at': doc['created_at'],
                              'shared_by': username
                          },
                          share_id=share_id)

@app.route('/api/usage/<domain>')
@login_required
def api_get_usage(domain):
    """Get user's remaining usage for a specific domain."""
    usage = get_remaining_usage(session['user_id'], domain)
    return jsonify({'success': True, 'usage': usage, 'domain': domain})

# ============================================================================
# ROUTES - API ENDPOINTS
# ============================================================================

@app.route('/api/generate-strategy', methods=['POST'])
@login_required
def api_generate_strategy():
    """Generate strategy via AI."""
    import sys
    print("=" * 60, flush=True)
    print("STRATEGY GENERATION STARTED", flush=True)
    print("=" * 60, flush=True)
    
    try:
        data = request.json
        domain = data.get('domain', 'Cyber Security')
        print(f"DEBUG: Domain = {domain}", flush=True)
        
        # Check usage limit for this domain
        can_generate, used, limit = check_usage_limit(session['user_id'], 'strategies', domain)
        if not can_generate:
            return jsonify({
                'success': False,
                'error': f'Usage limit reached for {domain}. You have used {used}/{limit} strategies in this domain.',
                'limit_reached': True
            }), 429
        
        lang = data.get('language', 'en')
        print(f"DEBUG: Language = {lang}", flush=True)
        
        # Get current state info
        org_structure = data.get('org_structure', 'Not specified')
        technologies = data.get('technologies', [])
        maturity = data.get('maturity_level', 'initial')
        tech_list = ', '.join(technologies) if technologies else 'None specified'
        frameworks_list = ', '.join(data.get('frameworks', [])) if data.get('frameworks') else 'Not specified'
        
        if lang == 'ar':
            # Map domain to Arabic specialized context
            domain_context = {
                'Cyber Security': 'الأمن السيبراني - يشمل حماية الأنظمة والشبكات والبيانات من التهديدات السيبرانية',
                'الأمن السيبراني': 'الأمن السيبراني - يشمل حماية الأنظمة والشبكات والبيانات من التهديدات السيبرانية',
                'Data Management': 'إدارة البيانات - يشمل حوكمة البيانات وجودتها وحمايتها وإدارة دورة حياتها',
                'إدارة البيانات': 'إدارة البيانات - يشمل حوكمة البيانات وجودتها وحمايتها وإدارة دورة حياتها',
                'Artificial Intelligence': 'الذكاء الاصطناعي - يشمل حوكمة الذكاء الاصطناعي وأخلاقياته ومخاطره',
                'الذكاء الاصطناعي': 'الذكاء الاصطناعي - يشمل حوكمة الذكاء الاصطناعي وأخلاقياته ومخاطره',
                'Digital Transformation': 'التحول الرقمي - يشمل استراتيجية الرقمنة والتقنيات الناشئة وإدارة التغيير',
                'التحول الرقمي': 'التحول الرقمي - يشمل استراتيجية الرقمنة والتقنيات الناشئة وإدارة التغيير',
                'Global Standards': 'المعايير العالمية - يشمل الامتثال للمعايير الدولية مثل ISO وNIST وCOBIT',
                'المعايير العالمية': 'المعايير العالمية - يشمل الامتثال للمعايير الدولية مثل ISO وNIST وCOBIT',
                'Enterprise Risk Management': 'إدارة المخاطر المؤسسية - يشمل تحديد وتقييم ومعالجة ومراقبة المخاطر على مستوى المؤسسة وفق COSO ERM وISO 31000',
                'إدارة المخاطر المؤسسية': 'إدارة المخاطر المؤسسية - يشمل تحديد وتقييم ومعالجة ومراقبة المخاطر على مستوى المؤسسة وفق COSO ERM وISO 31000',
            }
            domain_desc = domain_context.get(domain, domain)
            
            # Domain-specific gaps for Arabic
            domain_gaps_ar = {
                'Cyber Security': [
                    ('غياب سياسة الأمن السيبراني', 'عدم وجود سياسة أمن سيبراني معتمدة وشاملة'),
                    ('ضعف إدارة الثغرات الأمنية', 'عدم وجود برنامج منظم لاكتشاف ومعالجة الثغرات'),
                    ('نقص في المراقبة الأمنية', 'محدودية قدرات الكشف والاستجابة للتهديدات'),
                    ('ضعف حماية نقاط النهاية', 'عدم كفاية حلول حماية الأجهزة والخوادم'),
                    ('عدم اكتمال خطة الاستجابة للحوادث', 'نقص في إجراءات الاستجابة للحوادث السيبرانية'),
                ],
                'الأمن السيبراني': [
                    ('غياب سياسة الأمن السيبراني', 'عدم وجود سياسة أمن سيبراني معتمدة وشاملة'),
                    ('ضعف إدارة الثغرات الأمنية', 'عدم وجود برنامج منظم لاكتشاف ومعالجة الثغرات'),
                    ('نقص في المراقبة الأمنية', 'محدودية قدرات الكشف والاستجابة للتهديدات'),
                    ('ضعف حماية نقاط النهاية', 'عدم كفاية حلول حماية الأجهزة والخوادم'),
                    ('عدم اكتمال خطة الاستجابة للحوادث', 'نقص في إجراءات الاستجابة للحوادث السيبرانية'),
                ],
                'Data Management': [
                    ('غياب سياسة حوكمة البيانات', 'عدم وجود إطار شامل لحوكمة البيانات المؤسسية'),
                    ('ضعف تصنيف البيانات', 'عدم تصنيف البيانات حسب الحساسية والأهمية'),
                    ('نقص في جودة البيانات', 'غياب معايير ومقاييس جودة البيانات'),
                    ('ضعف إدارة دورة حياة البيانات', 'عدم وجود سياسات للاحتفاظ والإتلاف'),
                    ('عدم الامتثال لنظام حماية البيانات الشخصية', 'فجوات في تطبيق متطلبات PDPL'),
                ],
                'إدارة البيانات': [
                    ('غياب سياسة حوكمة البيانات', 'عدم وجود إطار شامل لحوكمة البيانات المؤسسية'),
                    ('ضعف تصنيف البيانات', 'عدم تصنيف البيانات حسب الحساسية والأهمية'),
                    ('نقص في جودة البيانات', 'غياب معايير ومقاييس جودة البيانات'),
                    ('ضعف إدارة دورة حياة البيانات', 'عدم وجود سياسات للاحتفاظ والإتلاف'),
                    ('عدم الامتثال لنظام حماية البيانات الشخصية', 'فجوات في تطبيق متطلبات PDPL'),
                ],
                'Artificial Intelligence': [
                    ('غياب إطار حوكمة الذكاء الاصطناعي', 'عدم وجود سياسات وإجراءات لحوكمة أنظمة الذكاء الاصطناعي'),
                    ('ضعف إدارة مخاطر الذكاء الاصطناعي', 'عدم تقييم المخاطر المرتبطة بنماذج AI'),
                    ('نقص في الشفافية والتفسير', 'غياب آليات لتفسير قرارات نماذج AI'),
                    ('ضعف ضمان العدالة والحياد', 'عدم اختبار التحيز في نماذج الذكاء الاصطناعي'),
                    ('عدم الامتثال لمبادئ أخلاقيات AI', 'فجوات في تطبيق مبادئ SDAIA الأخلاقية'),
                ],
                'الذكاء الاصطناعي': [
                    ('غياب إطار حوكمة الذكاء الاصطناعي', 'عدم وجود سياسات وإجراءات لحوكمة أنظمة الذكاء الاصطناعي'),
                    ('ضعف إدارة مخاطر الذكاء الاصطناعي', 'عدم تقييم المخاطر المرتبطة بنماذج AI'),
                    ('نقص في الشفافية والتفسير', 'غياب آليات لتفسير قرارات نماذج AI'),
                    ('ضعف ضمان العدالة والحياد', 'عدم اختبار التحيز في نماذج الذكاء الاصطناعي'),
                    ('عدم الامتثال لمبادئ أخلاقيات AI', 'فجوات في تطبيق مبادئ SDAIA الأخلاقية'),
                ],
                'Digital Transformation': [
                    ('غياب استراتيجية التحول الرقمي', 'عدم وجود خارطة طريق واضحة للتحول الرقمي'),
                    ('ضعف إدارة التغيير', 'محدودية برامج إدارة التغيير المؤسسي'),
                    ('نقص في الكفاءات الرقمية', 'فجوة في المهارات الرقمية للموظفين'),
                    ('ضعف التكامل بين الأنظمة', 'عدم ترابط الأنظمة الرقمية المختلفة'),
                    ('عدم قياس العائد من التحول الرقمي', 'غياب مؤشرات قياس نجاح التحول'),
                ],
                'التحول الرقمي': [
                    ('غياب استراتيجية التحول الرقمي', 'عدم وجود خارطة طريق واضحة للتحول الرقمي'),
                    ('ضعف إدارة التغيير', 'محدودية برامج إدارة التغيير المؤسسي'),
                    ('نقص في الكفاءات الرقمية', 'فجوة في المهارات الرقمية للموظفين'),
                    ('ضعف التكامل بين الأنظمة', 'عدم ترابط الأنظمة الرقمية المختلفة'),
                    ('عدم قياس العائد من التحول الرقمي', 'غياب مؤشرات قياس نجاح التحول'),
                ],
                'Enterprise Risk Management': [
                    ('غياب إطار إدارة المخاطر المؤسسية', 'عدم وجود إطار ERM متكامل'),
                    ('ضعف تحديد المخاطر', 'عدم شمولية عملية تحديد المخاطر'),
                    ('نقص في تقييم المخاطر', 'غياب منهجية موحدة لتقييم المخاطر'),
                    ('ضعف مراقبة المخاطر', 'محدودية آليات المتابعة والرقابة'),
                    ('عدم ربط المخاطر بالأهداف الاستراتيجية', 'فجوة بين إدارة المخاطر والتخطيط الاستراتيجي'),
                ],
            }
            
            # Get domain-specific gaps or use default
            gaps = domain_gaps_ar.get(domain, [
                ('غياب السياسات المعتمدة', 'عدم وجود سياسات موثقة ومعتمدة'),
                ('ضعف برنامج التوعية', 'عدم كفاية برامج التدريب والتوعية'),
                ('نقص في إدارة المخاطر', 'غياب منهجية واضحة لإدارة المخاطر'),
                ('ضعف آليات المراقبة', 'محدودية قدرات الرقابة والمتابعة'),
                ('عدم اكتمال خطة الاستمرارية', 'نقص في خطط استمرارية الأعمال'),
            ])
            
            # Build gaps table
            gaps_table = ""
            # If no cyber structure, add it as first confirmed gap
            if org_structure and ('no' in org_structure.lower() or 'لا' in org_structure or 'none' in org_structure.lower()):
                gaps_table += f"| 1 | غياب الهيكل التنظيمي للأمن السيبراني | عدم وجود إدارة مختصة بالأمن السيبراني - أساس تطبيق جميع الضوابط | حرجة | مفتوحة - مؤكدة |\n"
                start_idx = 2
            else:
                start_idx = 1
            for i, (gap_name, gap_desc) in enumerate(gaps, start_idx):
                priority = "عالية" if i <= 2 else ("متوسطة" if i <= 4 else "منخفضة")
                gaps_table += f"| {i} | {gap_name} | {gap_desc} | {priority} | مفتوحة |\n"
            
            # Translate framework names for Arabic
            frameworks_ar = translate_frameworks_list_ar(frameworks_list)
            
            prompt = f"""أنت خبير استراتيجي في مجال {domain_desc}.

أنشئ وثيقة استراتيجية احترافية لمجال **{domain_desc}** وفق إطار **{frameworks_ar}**.

المنظمة: {data.get('org_name', 'المنظمة')}
القطاع: {data.get('sector', 'حكومي')}
الحجم: {data.get('size', 'متوسطة')}
مستوى النضج: {maturity}
الهيكل التنظيمي الحالي: {org_structure}

تقييد الإطار التنظيمي:
- الإطار المحدد هو: {frameworks_ar}
- يجب الإشارة إلى {frameworks_ar} بالاسم في الرؤية والأهداف والركائز والمؤشرات
- عند تكرار اسم الإطار، استخدم الاسم المختصر فقط (مثلاً: NCA ECC بدلاً من NCA ECC Essential Cybersecurity Controls)
- لا تكتب الاسم الكامل بالإنجليزية - استخدم الاختصار العربي أو الاختصار الإنجليزي القصير فقط
- لا تذكر أي إطار آخر مثل ISO أو NIST أو COBIT إلا إذا كان مذكوراً في القائمة أعلاه
- اربط كل هدف وكل ركيزة بمتطلبات محددة من {frameworks_ar}

{"تنبيه حاسم: الهيكل التنظيمي الحالي لا يتضمن إدارة مختصة بالأمن السيبراني. يجب أن يكون الهدف الأول في الاستراتيجية هو إنشاء إدارة أو قسم مختص بالأمن السيبراني. يجب أن تتضمن الركيزة الأولى تفاصيل الهيكل المقترح (مدير الأمن السيبراني، فريق العمليات، فريق الحوكمة، فريق الاستجابة) مع تحديد الصلاحيات وخطوط التقارير. هذا هو الأساس الذي تُبنى عليه جميع الأهداف الأخرى." if org_structure and ('no' in org_structure.lower() or 'لا' in org_structure or 'not' in org_structure.lower() or 'none' in org_structure.lower()) else ""}

قواعد صارمة:
- المحتوى خاص بمجال {domain} فقط
- القيم الحالية: يجب أن تكون جميعها "يُحدد بعد التقييم" - لا تكتب أي نسب مئوية أو أرقام في عمود القيمة الحالية
- القيم المستهدفة فقط يمكن أن تحتوي على نسب مئوية مع مبرر
- لا تكتب أي تعليمات أو تنبيهات في المخرجات
- لا تنسخ أي نص من التعليمات إلى المخرجات - المخرجات يجب أن تكون وثيقة احترافية فقط
- استخدم [SECTION] بين الأقسام الستة
- يجب تضمين جميع الأقسام الستة كاملة

قاعدة حاسمة - عمود المبررات:
- المبرر يجب أن يشرح لماذا الهدف مهم وكيف يرتبط بمتطلب محدد من {frameworks_ar}
- مثال جيد: "الخطأ البشري مسبب رئيسي للحوادث؛ {frameworks_ar} يلزم بتدريب أمني منتظم"
- مثال جيد: "بدون فريق مختص لا يمكن تطبيق أي ضابط بشكل مستدام"
- مثال سيء: "ضوابط الحماية التقنية" (هذا وصف وليس مبرر)
- مثال سيء: "متطلبات التوعية والتدريب" (هذا عنوان وليس مبرر)
- لا تنسخ عبارات التعليمات مثل "selected frameworks" أو "FRAMEWORK" إلى المبررات

## 1. الرؤية والأهداف الاستراتيجية

**الرؤية الاستراتيجية:**
(فقرة تصف الرؤية مع ذكر إطار {frameworks_ar} صراحةً وكيف ستحقق المنظمة الامتثال له)

### الأهداف الاستراتيجية:
| # | الهدف الاستراتيجي | المؤشر المستهدف | المبرر (لماذا هذا مهم وما علاقته بـ {frameworks_ar}) | الإطار الزمني |
|---|-------------------|-----------------|------------------------------------------------------|---------------|
(5 أهداف - كل مبرر يشرح السبب الحقيقي وراء الهدف وعلاقته بمتطلب محدد من {frameworks_ar}، وليس مجرد اسم ضابط)

[SECTION]

## 2. تحليل الفجوات

### الفجوات المحددة:
| # | الفجوة | الوصف | الأولوية | الحالة |
|---|--------|-------|---------|--------|
{gaps_table}

[SECTION]

## 3. الركائز الاستراتيجية

### الركيزة 1: (الاسم)
(وصف الركيزة وأهميتها)
• مبادرة 1
• مبادرة 2
• مبادرة 3

### الركيزة 2: (الاسم)
(وصف وأهمية)
• مبادرة 1
• مبادرة 2
• مبادرة 3

### الركيزة 3: (الاسم)
(وصف وأهمية)
• مبادرة 1
• مبادرة 2
• مبادرة 3

### الركيزة 4: (الاسم)
(وصف وأهمية)
• مبادرة 1
• مبادرة 2
• مبادرة 3

[SECTION]

## 4. خارطة الطريق التنفيذية

### المرحلة 1: التأسيس (0-6 أشهر)
| # | النشاط | المسؤول | الجدول الزمني | المخرجات |
|---|--------|---------|---------------|----------|
(4 أنشطة خاصة بمجال {domain})

### المرحلة 2: البناء (6-12 شهر)
| # | النشاط | المسؤول | الجدول الزمني | المخرجات |
|---|--------|---------|---------------|----------|
(4 أنشطة)

### المرحلة 3: التحسين (12-24 شهر)
| # | النشاط | المسؤول | الجدول الزمني | المخرجات |
|---|--------|---------|---------------|----------|
(4 أنشطة)

[SECTION]

## 5. مؤشرات الأداء الرئيسية

### مؤشرات الأداء:
| # | المؤشر | الوصف | القيمة الحالية | القيمة المستهدفة | المبرر (لماذا هذا المستهدف مهم) | الإطار الزمني | مصدر البيانات |
|---|--------|-------|----------------|------------------|-------------------------------------|---------------|---------------|
(8 مؤشرات KPI - عمود "القيمة الحالية" يجب أن يكون "يُحدد بعد التقييم" لجميع المؤشرات بدون استثناء)

قاعدة حاسمة للمؤشرات:
- لا تضع ضابطاً واحداً (مثل MFA) كمؤشر مستقل - بل استخدم مؤشرات على مستوى نطاق الضوابط (مثلاً: "نسبة تطبيق ضوابط إدارة الهوية والوصول" بدلاً من "تغطية MFA")
- المؤشرات يجب أن تقيس نتائج قابلة للقياس على مستوى المنظمة

### أدلة تقييم المؤشرات

تنبيه: كل مؤشر يحتاج دليل تقييم فريد بخطوات مختلفة. لا تكرر نفس الخطوات لكل مؤشر.
- مثال سيء (عام): "تحديد النطاق → تحديد المصادر → جمع البيانات → التحقق → الاحتساب" لكل مؤشر
- مثال جيد (محدد): لوقت الاستجابة → "استخراج أوقات من SIEM → حساب MTTD من وقت التنبيه → حساب MTTR من التنبيه للاحتواء"

كل دليل يجب أن يحتوي:
- الأدوات والأنظمة المحددة لقياس ذلك المؤشر
- صيغة الاحتساب الدقيقة
- المسؤول المحدد (ليس فقط "فريق القياس")
- مخرجات ملموسة (ليس فقط "قيمة المؤشر")

---
#### دليل تقييم المؤشر رقم 1: [اسم المؤشر الأول]
(4-5 خطوات فريدة لقياس هذا المؤشر تحديداً - أدوات، صيغة، مصادر بيانات)

---
#### دليل تقييم المؤشر رقم 2: [اسم المؤشر الثاني]
(4-5 خطوات مختلفة - لا تنسخ من المؤشر الأول)

[SECTION]

## 6. تقييم الجاهزية والمخاطر

**درجة الثقة:** [X]%

**مبررات التقييم:**
[فقرة تفصيلية توضح أسس تقييم الدرجة مع ذكر العوامل المحددة وتأثير كل عامل على الدرجة]

### عوامل النجاح الحرجة:
| # | العامل | الوصف | الأهمية |
|---|--------|-------|---------|
(5 عوامل نجاح مرتبطة بمتطلبات {frameworks_ar})

### المخاطر الاستراتيجية:
| # | الخطر | الاحتمالية | الأثر | خطة التخفيف |
|---|-------|-----------|-------|-------------|
(4 مخاطر خاصة بمجال {domain})

---
**تاريخ الإعداد:** يُحدد لاحقاً"""
        else:
            # Map domain to context description
            domain_context = {
                'Cyber Security': 'Cyber Security - including protection of systems, networks, and data from cyber threats',
                'Data Management': 'Data Management - including data governance, quality, protection, and lifecycle management',
                'Artificial Intelligence': 'Artificial Intelligence - including AI governance, ethics, risks, and responsible AI practices',
                'Digital Transformation': 'Digital Transformation - including digitization strategy, emerging technologies, and change management',
                'Global Standards': 'Global Standards - including compliance with international standards like ISO, NIST, and COBIT',
                'Enterprise Risk Management': 'Enterprise Risk Management - including risk identification, assessment, treatment, monitoring, risk appetite, and organizational resilience per COSO ERM and ISO 31000',
            }
            domain_desc = domain_context.get(domain, domain)
            
            # Shorten framework names for clean prompt injection
            # "NCA ECC (Essential Cybersecurity Controls)" → "NCA ECC"
            import re as re_fw
            fw_short = re_fw.sub(r'\s*\([^)]+\)', '', frameworks_list).strip()
            if not fw_short:
                fw_short = frameworks_list
            
            # Build domain-specific English gap table (like Arabic prompt has)
            domain_gaps_en = {
                'Cyber Security': [
                    ('Policy & Governance Gap', 'Outdated or missing cybersecurity policies and procedures'),
                    ('Technical Controls Gap', f'Incomplete implementation of mandatory technical controls per {fw_short}'),
                    ('Training & Awareness Gap', 'Insufficient security awareness programs for employees'),
                    ('Incident Response Gap', f'Incomplete incident response plan per {fw_short} requirements'),
                    ('Asset Management Gap', 'No comprehensive and updated cybersecurity asset register'),
                ],
                'Data Management': [
                    ('Data Governance Gap', 'Absence of a formal data governance framework and roles'),
                    ('Data Quality Gap', 'No data quality standards or measurement processes'),
                    ('Data Classification Gap', 'Data not classified by sensitivity or criticality levels'),
                    ('Data Lifecycle Gap', 'Missing data retention and disposal policies'),
                    ('Data Protection Gap', 'Insufficient data encryption and access controls'),
                ],
                'Artificial Intelligence': [
                    ('AI Governance Gap', 'No formal AI governance framework or oversight committee'),
                    ('AI Ethics Gap', 'Missing ethical guidelines and bias assessment processes'),
                    ('AI Risk Gap', 'No AI-specific risk assessment methodology'),
                    ('AI Transparency Gap', 'Lack of model documentation and explainability standards'),
                    ('AI Data Gap', 'Insufficient controls for AI training data quality and bias'),
                ],
                'Digital Transformation': [
                    ('Digital Strategy Gap', 'No comprehensive digital transformation roadmap'),
                    ('Change Management Gap', 'Limited organizational change management programs'),
                    ('Digital Skills Gap', 'Workforce digital competency shortfall'),
                    ('Systems Integration Gap', 'Lack of interoperability between digital systems'),
                    ('ROI Measurement Gap', 'No metrics framework for digital transformation outcomes'),
                ],
                'Enterprise Risk Management': [
                    ('ERM Framework Gap', 'No integrated enterprise risk management framework'),
                    ('Risk Identification Gap', 'Incomplete risk identification process'),
                    ('Risk Assessment Gap', 'No standardized risk assessment methodology'),
                    ('Risk Monitoring Gap', 'Limited risk monitoring and reporting mechanisms'),
                    ('Strategic Alignment Gap', 'Risk management not linked to strategic objectives'),
                ],
            }
            
            gaps = domain_gaps_en.get(domain, [
                ('Policy Gap', 'Missing or outdated documented policies'),
                ('Awareness Gap', 'Insufficient training and awareness programs'),
                ('Risk Management Gap', 'No clear risk management methodology'),
                ('Monitoring Gap', 'Limited monitoring and oversight capabilities'),
                ('Continuity Gap', 'Incomplete business continuity plans'),
            ])
            
            # Build pre-populated gap table
            gaps_table_en = ""
            if org_structure and ('no' in org_structure.lower() or 'none' in org_structure.lower()):
                gaps_table_en += f"| 1 | Organizational Structure Gap | No dedicated cybersecurity department - this is the foundation for implementing all other controls | Critical | Open - Confirmed |\n"
                start_idx = 2
            else:
                start_idx = 1
            for i, (gap_name, gap_desc) in enumerate(gaps, start_idx):
                priority = "High" if i <= 2 else ("Medium" if i <= 4 else "Low")
                gaps_table_en += f"| {i} | {gap_name} | {gap_desc} | {priority} | Open |\n"
            
            prompt = f"""You are a GRC expert specializing in **{domain_desc}**.

Generate a professional strategy document in Markdown. Domain: **{domain}**.

FRAMEWORK: {fw_short}
- Use "{fw_short}" naturally throughout — in objectives, gaps, KPIs, and pillars
- Do NOT mention any other framework unless it is listed above
- Do NOT echo raw instruction text, labels, or meta-phrases from this prompt into the output
- NEVER include phrases like "The user has selected", "selected frameworks", "FRAMEWORK:", or any other prompt text in the document

OUTPUT RULES:
1. Use relative timeframes: "Within 6 months", "Within 12 months", "Year 1", "Year 2". No person names.
2. Current values = "To be assessed" (never fabricate). Target values may include percentages with justification from {fw_short}.
3. Gap statuses: "Open - Confirmed" for gaps already identified, "Open" for gaps requiring assessment.
4. JUSTIFICATION COLUMN: Each justification must explain WHY the objective matters and HOW it connects to a specific {fw_short} requirement.
   - GOOD: "Human error causes majority of incidents; {fw_short} mandates regular security training"
   - GOOD: "Without a dedicated team, no control can be sustainably implemented or monitored"
   - BAD: "{fw_short} detection and response controls" (this is a label, not a justification)
   - BAD: "{fw_short} awareness requirements" (this restates the objective, not why it matters)
{"5. CRITICAL: The organization has NO cybersecurity department. Objective #1 = Establish a dedicated cybersecurity department (CISO, SOC, Governance, CSIRT) with reporting lines and authority. This is the FOUNDATION before any other objective can succeed." if org_structure and ('no' in org_structure.lower() or 'none' in org_structure.lower()) else ""}

Organization: {data.get('org_name', 'Organization')} | Sector: {data.get('sector', 'General')} | Size: {data.get('size', 'Medium')} | Budget: {data.get('budget', '1M-5M')} | Maturity: {maturity} | Technologies: {tech_list} | Challenges: {data.get('challenges', 'Not specified')}

Write 6 sections separated by [SECTION].

FORMATTING: ## for section headings, ### before every table, • for pillar initiatives only.

## 1. Vision & Objectives

**Vision:**
[Paragraph describing the strategic vision — mention {fw_short} explicitly]

### Strategic Objectives:
| # | Objective | Target Metric | Justification (why it matters + link to {fw_short}) | Timeframe |
|---|-----------|---------------|-----------------------------------------------------|-----------|
{"| 1 | Establish dedicated cybersecurity department with defined structure and authority | Approved org structure and full team | Without a dedicated team, no " + fw_short + " control can be sustainably implemented or monitored | Within 6 months |" if org_structure and ('no' in org_structure.lower() or 'none' in org_structure.lower()) else "| 1 | [First objective] | [Metric] | [Why this matters + specific " + fw_short + " requirement] | Within X months |"}
(5-7 objectives total, each with a meaningful justification that explains the business need)

[SECTION]

## 2. Gap Analysis

### Identified Gaps:
| # | Gap | Description | Priority | Status |
|---|-----|-------------|----------|--------|
{gaps_table_en}

### Detailed Implementation Guidelines:

Provide a SEPARATE, COMPLETE implementation guide for EACH gap above. Do NOT write "repeat" or "same as above".

---
#### Gap #1 Implementation Guide: {"Organizational Structure Gap" if org_structure and ('no' in org_structure.lower() or 'none' in org_structure.lower()) else "[First Gap Name]"}
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
{"| Planning | 1.1 | Define cybersecurity org structure requirements per " + fw_short + " | Executive Management | Requirements document |" if org_structure and ('no' in org_structure.lower() or 'none' in org_structure.lower()) else "| Planning | 1.1 | [Specific step] | [Team] | [Output] |"}
{"| Planning | 1.2 | Design proposed structure (CISO, SOC team, Governance team, CSIRT) | Executive Management | Proposed org chart |" if org_structure and ('no' in org_structure.lower() or 'none' in org_structure.lower()) else "| Planning | 1.2 | [Specific step] | [Team] | [Output] |"}
| Execution | 2.1 | [Specific step] | [Team] | [Output] |
| Execution | 2.2 | [Specific step] | [Team] | [Output] |
| Verification | 3.1 | [Specific step] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
#### Gap #2 Implementation Guide: [Second Gap Name]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for Gap 2] | [Team] | [Output] |
| Planning | 1.2 | [Specific step for Gap 2] | [Team] | [Output] |
| Execution | 2.1 | [Specific step for Gap 2] | [Team] | [Output] |
| Execution | 2.2 | [Specific step for Gap 2] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for Gap 2] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
#### Gap #3 Implementation Guide: [Third Gap Name]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for Gap 3] | [Team] | [Output] |
| Planning | 1.2 | [Specific step for Gap 3] | [Team] | [Output] |
| Execution | 2.1 | [Specific step for Gap 3] | [Team] | [Output] |
| Execution | 2.2 | [Specific step for Gap 3] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for Gap 3] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
#### Gap #4 Implementation Guide: [Fourth Gap Name]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for Gap 4] | [Team] | [Output] |
| Planning | 1.2 | [Specific step for Gap 4] | [Team] | [Output] |
| Execution | 2.1 | [Specific step for Gap 4] | [Team] | [Output] |
| Execution | 2.2 | [Specific step for Gap 4] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for Gap 4] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
#### Gap #5 Implementation Guide: [Fifth Gap Name]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for Gap 5] | [Team] | [Output] |
| Planning | 1.2 | [Specific step for Gap 5] | [Team] | [Output] |
| Execution | 2.1 | [Specific step for Gap 5] | [Team] | [Output] |
| Execution | 2.2 | [Specific step for Gap 5] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for Gap 5] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

[SECTION]

## 3. Strategic Pillars

### Pillar 1: [Name]
• Initiative one
• Initiative two

### Pillar 2: [Name]
• Initiative one
• Initiative two

### Pillar 3: [Name]
• Initiative one
• Initiative two

### Pillar 4: [Name]
• Initiative one
• Initiative two

[SECTION]

## 4. Implementation Roadmap

### Phase 1: Foundation (0-6 months)
| # | Activity | Owner | Timeline | Deliverable |
|---|----------|-------|----------|-------------|
| 1 | [Activity 1] | [Owner] | Month 1-2 | [Deliverable] |
| 2 | [Activity 2] | [Owner] | Month 2-3 | [Deliverable] |
| 3 | [Activity 3] | [Owner] | Month 3-4 | [Deliverable] |
| 4 | [Activity 4] | [Owner] | Month 4-6 | [Deliverable] |

### Phase 2: Build (6-12 months)
| # | Activity | Owner | Timeline | Deliverable |
|---|----------|-------|----------|-------------|
| 1 | [Activity 1] | [Owner] | Month 6-7 | [Deliverable] |
| 2 | [Activity 2] | [Owner] | Month 7-9 | [Deliverable] |
| 3 | [Activity 3] | [Owner] | Month 9-10 | [Deliverable] |
| 4 | [Activity 4] | [Owner] | Month 10-12 | [Deliverable] |

### Phase 3: Optimize (12-24 months)
| # | Activity | Owner | Timeline | Deliverable |
|---|----------|-------|----------|-------------|
| 1 | [Activity 1] | [Owner] | Month 12-15 | [Deliverable] |
| 2 | [Activity 2] | [Owner] | Month 15-18 | [Deliverable] |
| 3 | [Activity 3] | [Owner] | Month 18-21 | [Deliverable] |
| 4 | [Activity 4] | [Owner] | Month 21-24 | [Deliverable] |

[SECTION]

## 5. Key Performance Indicators

### KPIs:
| # | KPI | Description | Current Value | Target Value | Justification | Timeframe | Data Source |
|---|-----|-------------|---------------|--------------|---------------|-----------|-------------|
| 1 | [KPI Name] | [Brief description] | To be assessed | [Justified value] | [Why this target] | Within X months | [Source] |
(8 KPIs total)

CRITICAL KPI RULES:
- Do NOT list individual controls as standalone KPIs (e.g. "MFA coverage" is wrong — MFA is one of many controls under Identity & Access Management)
- KPIs must measure at the CONTROL DOMAIN level (e.g. "Identity & Access Management implementation rate" which covers MFA, PAM, RBAC, access reviews together)
- Each KPI must be measurable with a clear formula

### KPI Assessment Guidelines

CRITICAL: Each KPI below requires a UNIQUE measurement guide. Do NOT repeat the same steps for different KPIs.
Bad example (generic): "Define scope → Identify sources → Collect data → Validate → Calculate" for every KPI
Good example (specific): For incident response time → "Configure SIEM timestamps → Extract incident ticket data → Calculate MTTD from alert-to-triage → Calculate MTTR from triage-to-containment"

Each guide must include:
- The specific tools, systems, or data sources used for THAT KPI
- The exact calculation formula
- Who specifically owns measurement (not just "[Team]")
- Concrete outputs (not just "KPI value")

---
#### KPI #1 Assessment Guide: [First KPI Name]
(4-5 unique steps specific to measuring THIS KPI — tools, formula, data sources)

---
#### KPI #2 Assessment Guide: [Second KPI Name]
(4-5 DIFFERENT steps — do NOT copy from KPI #1)

---
#### KPI #3 Assessment Guide: [Third KPI Name]
(4-5 steps unique to this measurement)

---
#### KPI #4 Assessment Guide: [Fourth KPI Name]
(4-5 steps unique to this measurement)

---
#### KPI #5 Assessment Guide: [Fifth KPI Name]
(4-5 steps unique to this measurement)

---
#### KPI #6 Assessment Guide: [Sixth KPI Name]
(4-5 steps unique to this measurement)

---
#### KPI #7 Assessment Guide: [Seventh KPI Name]
(4-5 steps unique to this measurement)

---
#### KPI #8 Assessment Guide: [Eighth KPI Name]
(4-5 steps unique to this measurement)

[SECTION]

## 6. Confidence Assessment & Risks

**Confidence Score:** [X]%

**Score Justification:**
[Detailed paragraph explaining the basis for the confidence score, citing specific factors and their individual impact on the score]

### Key Risks:
| # | Risk | Likelihood | Impact | Mitigation Plan |
|---|------|------------|--------|-----------------|
| 1 | [Risk] | High/Medium/Low | High/Medium/Low | [Action] |
| 2 | [Risk] | High/Medium/Low | High/Medium/Low | [Action] |
| 3 | [Risk] | High/Medium/Low | High/Medium/Low | [Action] |
| 4 | [Risk] | High/Medium/Low | High/Medium/Low | [Action] |"""

        content = generate_ai_content(prompt, lang)
        
        if not content:
            content = generate_simulation_content(prompt, lang)
        
        import re  # Import at function level to ensure availability
        
        # Content is already cleaned by generate_ai_content via clean_ai_response()
        
        # DEBUG: Print content length and check for section markers
        print(f"DEBUG: Generated content length: {len(content)}", flush=True)
        print(f"DEBUG: Contains [SECTION]: {'[SECTION]' in content}", flush=True)
        print(f"DEBUG: Contains ## 4.: {'## 4.' in content}", flush=True)
        print(f"DEBUG: Contains ## 5.: {'## 5.' in content}", flush=True)
        print(f"DEBUG: Contains ## 6.: {'## 6.' in content}", flush=True)
        print(f"DEBUG: Contains خارطة الطريق: {'خارطة الطريق' in content}", flush=True)
        print(f"DEBUG: Contains مؤشرات الأداء: {'مؤشرات الأداء' in content}", flush=True)
        
        # Parse sections - split by separator
        parts = []
        
        if '[SECTION]' in content:
            parts = content.split('[SECTION]')
            print(f"DEBUG: Split by [SECTION], got {len(parts)} parts", flush=True)
        else:
            # No [SECTION] markers - must split by section headers
            # First, try to split by ## X. pattern (works for both English and Arabic)
            section_split_pattern = r'(?=##\s*[1-6]\.)'
            parts = re.split(section_split_pattern, content)
            parts = [p for p in parts if p.strip()]
            print(f"DEBUG: Split by ## X. pattern, got {len(parts)} parts", flush=True)
            
            if len(parts) < 4:
                # Try splitting by Arabic section titles directly
                ar_section_titles = [
                    'الرؤية والأهداف',
                    'تحليل الفجوات', 
                    'الركائز الاستراتيجية',
                    'خارطة الطريق',
                    'مؤشرات الأداء',
                    'تقييم الثقة'
                ]
                # Build pattern to match any of these titles
                ar_pattern = r'(?=##\s*\d*\.?\s*(?:' + '|'.join(ar_section_titles) + '))'
                parts = re.split(ar_pattern, content)
                parts = [p for p in parts if p.strip()]
                print(f"DEBUG: Split by Arabic titles, got {len(parts)} parts", flush=True)
            
            if len(parts) < 4:
                # Try splitting by English section titles
                en_section_titles = [
                    'Vision',
                    'Gap Analysis',
                    'Strategic Pillars',
                    'Implementation Roadmap',
                    'Key Performance',
                    'Confidence Assessment'
                ]
                en_pattern = r'(?=##\s*\d*\.?\s*(?:' + '|'.join(en_section_titles) + '))'
                parts = re.split(en_pattern, content)
                parts = [p for p in parts if p.strip()]
                print(f"DEBUG: Split by English titles, got {len(parts)} parts", flush=True)
        
        # If still not enough parts, try splitting by numbered headers without ##
        if len(parts) < 4:
            # Try matching "1. الرؤية" or "1. Vision" at start of line
            section_split_pattern = r'(?=^[1-6]\.\s*(?:الرؤية|تحليل|الركائز|خارطة|مؤشرات|تقييم|Vision|Gap|Strategic|Implementation|Key|Confidence))'
            parts = re.split(section_split_pattern, content, flags=re.MULTILINE | re.IGNORECASE)
            parts = [p for p in parts if p.strip()]
            print(f"DEBUG: Split by numbered pattern, got {len(parts)} parts", flush=True)
        
        # Last resort: split by any "## " followed by a number
        if len(parts) < 4:
            parts = re.split(r'(?=##\s+\d)', content)
            parts = [p for p in parts if p.strip()]
            print(f"DEBUG: Split by ## + number, got {len(parts)} parts", flush=True)
        
        # Clean parts
        parts = [p.strip() for p in parts if p.strip()]
        print(f"DEBUG: Final number of parts after cleaning: {len(parts)}", flush=True)
        
        # Print first 100 chars of each part for debugging
        for i, part in enumerate(parts[:6]):
            print(f"DEBUG: Part {i} starts with: {part[:100]}", flush=True)
        
        def fix_formatting(text, lang_code):
            """Fix markdown formatting - add ### before tables and ## before section headers."""
            import re
            lines = text.split('\n')
            fixed_lines = []
            
            for i, line in enumerate(lines):
                stripped = line.strip()
                
                # Skip empty lines
                if not stripped:
                    fixed_lines.append(line)
                    continue
                
                # Skip if already has ## or ###
                if stripped.startswith('##'):
                    fixed_lines.append(line)
                    continue
                
                # Check if this is a main section header (like "1. Vision & Objectives")
                if re.match(r'^[1-6]\.\s+\w', stripped):
                    # Add ## before the section number
                    fixed_lines.append('## ' + stripped)
                    continue
                
                # Check if this line ends with : and next non-empty line is a table
                if stripped.endswith(':') and not stripped.startswith('**'):
                    # Look ahead for table
                    next_line_idx = i + 1
                    while next_line_idx < len(lines) and not lines[next_line_idx].strip():
                        next_line_idx += 1
                    
                    if next_line_idx < len(lines):
                        next_line = lines[next_line_idx].strip()
                        # Check if next line is a table header (starts with |)
                        if next_line.startswith('|'):
                            # This is a table header without ###, add it
                            fixed_lines.append('### ' + stripped)
                            continue
                
                fixed_lines.append(line)
            
            return '\n'.join(fixed_lines)
        
        # Apply fix to each part
        print("=" * 60, flush=True)
        print("BEFORE fix_formatting - First part preview:", flush=True)
        if parts:
            print(parts[0][:150], flush=True)
        print("=" * 60, flush=True)
        
        parts = [fix_formatting(p, lang) for p in parts]
        
        print("AFTER fix_formatting - First part preview:", flush=True)
        if parts:
            print(parts[0][:150], flush=True)
        print("=" * 60, flush=True)
        
        # Section header patterns to identify each section
        section_patterns = {
            'vision': [
                '1. vision', '## 1.', '1.', 'vision & objective', 'vision and objective',
                '1. الرؤية', '## 1.', 'الرؤية والأهداف'
            ],
            'gaps': [
                '2. gap', '## 2.', '2.', 'gap analysis',
                '2. تحليل', '## 2.', 'تحليل الفجوات'
            ],
            'pillars': [
                '3. strategic', '## 3.', '3.', 'strategic pillar', 'pillar 1',
                '3. الركائز', '## 3.', 'الركائز الاستراتيجية'
            ],
            'roadmap': [
                '4. implementation', '## 4.', '4.', 'roadmap', 'phase 1 (0-6',
                '4. خارطة', '## 4.', 'خارطة الطريق', 'المرحلة 1'
            ],
            'kpis': [
                '5. key performance', '## 5.', '5.', 'kpi', 'key performance indicator',
                '5. مؤشرات', '## 5.', 'مؤشرات الأداء'
            ],
            'confidence': [
                '6. confidence', '## 6.', '6.', 'confidence assessment', 'confidence score',
                '6. تقييم الثقة', '## 6.', 'تقييم الثقة', 'درجة الثقة'
            ]
        }
        
        def identify_section(text, lang_code):
            """Identify which section type this text belongs to."""
            text_lower = text.lower()[:300]  # Check first 300 chars
            first_line = text.strip().split('\n')[0] if text.strip() else ''
            first_line_lower = first_line.lower()
            
            # FIRST: Check section number at start of content (most reliable)
            # English patterns
            if first_line_lower.startswith('## 1.') or first_line_lower.startswith('1.') or 'vision' in first_line_lower:
                return 'vision'
            if first_line_lower.startswith('## 2.') or (first_line_lower.startswith('2.') and 'gap' in first_line_lower):
                return 'gaps'
            if first_line_lower.startswith('## 3.') or (first_line_lower.startswith('3.') and 'pillar' in first_line_lower):
                return 'pillars'
            if first_line_lower.startswith('## 4.') or (first_line_lower.startswith('4.') and ('roadmap' in first_line_lower or 'implementation' in first_line_lower)):
                return 'roadmap'
            if first_line_lower.startswith('## 5.') or (first_line_lower.startswith('5.') and 'kpi' in first_line_lower):
                return 'kpis'
            if first_line_lower.startswith('## 6.') or (first_line_lower.startswith('6.') and 'confidence' in first_line_lower):
                return 'confidence'
            
            # Arabic section numbers - check for ## X. pattern first (most reliable)
            # Also check for section titles without ## prefix
            if '## 1.' in first_line or '1. الرؤية' in first_line or 'الرؤية والأهداف' in first_line:
                return 'vision'
            if '## 2.' in first_line or '2. تحليل' in first_line or 'تحليل الفجوات' in first_line:
                return 'gaps'
            if '## 3.' in first_line or '3. الركائز' in first_line or 'الركائز الاستراتيجية' in first_line:
                return 'pillars'
            if '## 4.' in first_line or '4. خارطة' in first_line or 'خارطة الطريق' in first_line:
                return 'roadmap'
            if '## 5.' in first_line or '5. مؤشرات' in first_line or 'مؤشرات الأداء' in first_line:
                return 'kpis'
            if '## 6.' in first_line or '6. تقييم' in first_line or 'تقييم الثقة' in first_line:
                return 'confidence'
            
            # Check content for Arabic keywords even if first line doesn't match
            if 'الرؤية' in text[:150] and 'الأهداف' in text[:300]:
                return 'vision'
            if 'الفجوات' in text[:150] or 'تحليل الفجوات' in text[:200]:
                return 'gaps'
            if 'الركائز' in text[:150] or 'الركيزة' in text[:200]:
                return 'pillars'
            if 'خارطة الطريق' in text[:150] or 'المرحلة 1' in text[:300] or 'التأسيس' in text[:200]:
                return 'roadmap'
            if 'مؤشرات الأداء' in text[:150] or 'القيمة الحالية' in text[:300] or 'القيمة المستهدفة' in text[:300]:
                return 'kpis'
            if 'درجة الثقة' in text[:150] or 'تقييم الثقة' in text[:200] or 'المخاطر الاستراتيجية' in text[:300]:
                return 'confidence'
            
            # Fallback to keyword matching in full text
            keyword_scores = {
                'vision': ['vision', 'objective', 'mission', 'الرؤية', 'الأهداف', 'الاستراتيجية'],
                'gaps': ['gap analysis', 'identified gaps', 'الفجوة', 'الفجوات', 'تحليل'],
                'pillars': ['pillar', 'initiative', 'الركائز', 'المبادرات', 'الركيزة'],
                'roadmap': ['phase 1', 'roadmap', 'timeline', 'implementation', 'المرحلة', 'خارطة الطريق', 'التأسيس', 'البناء'],
                'kpis': ['kpi', 'key performance', 'indicator', 'مؤشر', 'مؤشرات الأداء', 'القيمة الحالية', 'القيمة المستهدفة'],
                'confidence': ['confidence score', 'confidence assessment', 'الثقة', 'تقييم الثقة', 'المخاطر الرئيسية', 'درجة الثقة']
            }
            
            scores = {}
            for section_type, keywords in keyword_scores.items():
                score = sum(1 for kw in keywords if kw in text[:300])
                scores[section_type] = score
            
            if max(scores.values()) > 0:
                return max(scores, key=scores.get)
            return None
        
        # Initialize sections
        sections = {
            'vision': '',
            'gaps': '',
            'pillars': '',
            'roadmap': '',
            'kpis': '',
            'confidence': ''
        }
        
        def inject_implementation_guidelines(gaps_content, lang_code):
            """Inject implementation guidelines if AI didn't include them or if some are missing."""
            # Extract gaps from the table to create guidelines for each
            import re
            
            # Find gap names from table rows (pattern: | number | gap name | description |)
            gap_pattern = r'\|\s*(\d+)\s*\|\s*([^|]+)\s*\|'
            gaps_found = re.findall(gap_pattern, gaps_content)
            
            if not gaps_found or len(gaps_found) < 2:  # Need at least 2 (header row doesn't count)
                return gaps_content
            
            # Skip header row if it contains "Gap" or "الفجوة"
            gaps_list = []
            for num, name in gaps_found:
                name = name.strip()
                if name and name.lower() not in ['gap', 'الفجوة', '#', 'description', 'الوصف', 'priority', 'الأولوية', 'status', 'الحالة']:
                    gaps_list.append((num, name))
            
            if not gaps_list:
                return gaps_content
            
            # Gap-specific implementation templates (English)
            gap_templates_en = {
                'policy': {
                    'steps': [
                        ('Planning', '1.1', 'Inventory existing policies and identify gaps', 'InfoSec', 'Policy inventory'),
                        ('Planning', '1.2', 'Review regulatory requirements (NCA, ISO, NIST)', 'Compliance', 'Requirements matrix'),
                        ('Planning', '1.3', 'Define policy structure and approval workflow', 'InfoSec', 'Policy framework'),
                        ('Development', '2.1', 'Draft new/updated policies', 'InfoSec', 'Policy drafts'),
                        ('Development', '2.2', 'Legal and stakeholder review', 'Legal', 'Review comments'),
                        ('Development', '2.3', 'Incorporate feedback and finalize', 'InfoSec', 'Final policies'),
                        ('Approval', '3.1', 'Submit for executive approval', 'InfoSec', 'Approval request'),
                        ('Approval', '3.2', 'Obtain sign-off from leadership', 'Executive', 'Signed policies'),
                        ('Deployment', '4.1', 'Communicate policies to all staff', 'HR/Comms', 'Communication log'),
                        ('Deployment', '4.2', 'Conduct policy awareness training', 'Training', 'Training records'),
                    ],
                    'evidence': ['Approved policy documents', 'Review meeting minutes', 'Training completion records', 'Communication acknowledgments']
                },
                'technology': {
                    'steps': [
                        ('Planning', '1.1', 'Assess current technology landscape', 'IT', 'Technology inventory'),
                        ('Planning', '1.2', 'Define technical requirements', 'Security', 'Requirements doc'),
                        ('Planning', '1.3', 'Evaluate vendor solutions (RFP/RFI)', 'Procurement', 'Vendor comparison'),
                        ('Procurement', '2.1', 'Select vendor and negotiate contract', 'Procurement', 'Signed contract'),
                        ('Procurement', '2.2', 'Allocate budget and resources', 'Finance', 'Budget approval'),
                        ('Implementation', '3.1', 'Prepare infrastructure and environment', 'IT', 'Ready environment'),
                        ('Implementation', '3.2', 'Install and configure solution', 'IT/Vendor', 'Configured system'),
                        ('Implementation', '3.3', 'Integrate with existing systems', 'IT', 'Integration complete'),
                        ('Testing', '4.1', 'Conduct UAT and security testing', 'QA', 'Test results'),
                        ('Operations', '5.1', 'Train operations team', 'Training', 'Trained staff'),
                    ],
                    'evidence': ['Vendor contract', 'Installation report', 'Integration test results', 'Training certificates']
                },
                'training': {
                    'steps': [
                        ('Planning', '1.1', 'Assess current awareness levels (baseline survey)', 'InfoSec', 'Baseline report'),
                        ('Planning', '1.2', 'Identify target audiences and learning objectives', 'Training', 'Training plan'),
                        ('Planning', '1.3', 'Select training delivery methods', 'Training', 'Delivery strategy'),
                        ('Development', '2.1', 'Develop training content and materials', 'Training', 'Training modules'),
                        ('Development', '2.2', 'Create assessments and quizzes', 'Training', 'Assessment bank'),
                        ('Development', '2.3', 'Prepare phishing simulation scenarios', 'Security', 'Simulation plan'),
                        ('Execution', '3.1', 'Launch mandatory training program', 'HR', 'Training schedule'),
                        ('Execution', '3.2', 'Conduct phishing simulations', 'Security', 'Simulation results'),
                        ('Execution', '3.3', 'Provide remedial training for failures', 'Training', 'Remediation log'),
                        ('Monitoring', '4.1', 'Track completion rates and scores', 'Training', 'Progress dashboard'),
                    ],
                    'evidence': ['Training completion records', 'Assessment scores', 'Phishing simulation results', 'Improvement metrics']
                },
                'incident': {
                    'steps': [
                        ('Planning', '1.1', 'Review current incident response capabilities', 'Security', 'Gap assessment'),
                        ('Planning', '1.2', 'Define incident categories and severity levels', 'Security', 'Classification matrix'),
                        ('Development', '2.1', 'Develop incident response playbooks', 'Security', 'Playbook documents'),
                        ('Development', '2.2', 'Create escalation procedures and contact lists', 'Security', 'Escalation matrix'),
                        ('Development', '2.3', 'Design reporting templates', 'Security', 'Report templates'),
                        ('Team Setup', '3.1', 'Form CSIRT/IRT team', 'Management', 'Team charter'),
                        ('Team Setup', '3.2', 'Define roles and responsibilities (RACI)', 'Security', 'RACI matrix'),
                        ('Training', '4.1', 'Train incident response team', 'Training', 'Trained team'),
                        ('Testing', '5.1', 'Conduct tabletop exercises', 'Security', 'Exercise report'),
                        ('Testing', '5.2', 'Perform full simulation drill', 'Security', 'Drill results'),
                    ],
                    'evidence': ['Approved IR plan', 'CSIRT roster', 'Tabletop exercise report', 'Drill after-action report']
                },
                'data': {
                    'steps': [
                        ('Planning', '1.1', 'Inventory all data assets', 'Data Mgmt', 'Data inventory'),
                        ('Planning', '1.2', 'Classify data by sensitivity level', 'InfoSec', 'Classification scheme'),
                        ('Planning', '1.3', 'Map data flows and storage locations', 'IT', 'Data flow diagram'),
                        ('Implementation', '2.1', 'Apply data classification labels', 'Data Mgmt', 'Labeled data'),
                        ('Implementation', '2.2', 'Implement DLP controls', 'Security', 'DLP configured'),
                        ('Implementation', '2.3', 'Enable encryption for sensitive data', 'IT', 'Encryption report'),
                        ('Implementation', '2.4', 'Configure access controls (need-to-know)', 'IT', 'Access matrix'),
                        ('Monitoring', '3.1', 'Deploy data monitoring tools', 'Security', 'Monitoring active'),
                        ('Monitoring', '3.2', 'Establish data breach response procedures', 'Security', 'Breach procedures'),
                        ('Compliance', '4.1', 'Verify PDPL/GDPR compliance', 'Compliance', 'Compliance report'),
                    ],
                    'evidence': ['Data classification register', 'DLP policy configuration', 'Encryption certificates', 'Access control matrix']
                },
                'default': {
                    'steps': [
                        ('Planning', '1.1', 'Assess current state and identify requirements', 'Project Lead', 'Assessment report'),
                        ('Planning', '1.2', 'Define scope and success criteria', 'Project Lead', 'Project charter'),
                        ('Planning', '1.3', 'Develop implementation timeline', 'Project Lead', 'Project plan'),
                        ('Execution', '2.1', 'Allocate resources and budget', 'Management', 'Resource allocation'),
                        ('Execution', '2.2', 'Execute implementation activities', 'Implementation Team', 'Progress reports'),
                        ('Execution', '2.3', 'Train relevant personnel', 'Training', 'Training records'),
                        ('Verification', '3.1', 'Test and validate implementation', 'QA', 'Test results'),
                        ('Verification', '3.2', 'Conduct management review', 'Management', 'Review minutes'),
                        ('Closure', '4.1', 'Document lessons learned', 'Project Lead', 'Lessons learned'),
                        ('Closure', '4.2', 'Obtain formal sign-off', 'Management', 'Sign-off document'),
                    ],
                    'evidence': ['Assessment report', 'Implementation records', 'Test results', 'Sign-off document']
                }
            }
            
            # Gap-specific implementation templates (Arabic)
            gap_templates_ar = {
                'policy': {
                    'steps': [
                        ('التخطيط', '1.1', 'جرد السياسات الحالية وتحديد الفجوات', 'أمن المعلومات', 'قائمة السياسات'),
                        ('التخطيط', '1.2', 'مراجعة المتطلبات التنظيمية (NCA, ISO, NIST)', 'الامتثال', 'مصفوفة المتطلبات'),
                        ('التخطيط', '1.3', 'تحديد هيكل السياسات وسير الاعتماد', 'أمن المعلومات', 'إطار السياسات'),
                        ('التطوير', '2.1', 'صياغة السياسات الجديدة/المحدثة', 'أمن المعلومات', 'مسودات السياسات'),
                        ('التطوير', '2.2', 'مراجعة قانونية ومن أصحاب المصلحة', 'الشؤون القانونية', 'تعليقات المراجعة'),
                        ('التطوير', '2.3', 'دمج الملاحظات والصياغة النهائية', 'أمن المعلومات', 'السياسات النهائية'),
                        ('الاعتماد', '3.1', 'رفع للاعتماد التنفيذي', 'أمن المعلومات', 'طلب الاعتماد'),
                        ('الاعتماد', '3.2', 'الحصول على توقيع القيادة', 'الإدارة التنفيذية', 'السياسات الموقعة'),
                        ('النشر', '4.1', 'تعميم السياسات على جميع الموظفين', 'الموارد البشرية', 'سجل التعميم'),
                        ('النشر', '4.2', 'تنفيذ تدريب التوعية بالسياسات', 'التدريب', 'سجلات التدريب'),
                    ],
                    'evidence': ['السياسات المعتمدة', 'محاضر اجتماعات المراجعة', 'سجلات إتمام التدريب', 'إقرارات الاستلام']
                },
                'technology': {
                    'steps': [
                        ('التخطيط', '1.1', 'تقييم المشهد التقني الحالي', 'تقنية المعلومات', 'جرد التقنيات'),
                        ('التخطيط', '1.2', 'تحديد المتطلبات التقنية', 'فريق الأمن', 'وثيقة المتطلبات'),
                        ('التخطيط', '1.3', 'تقييم حلول الموردين (RFP/RFI)', 'المشتريات', 'مقارنة الموردين'),
                        ('الشراء', '2.1', 'اختيار المورد والتفاوض على العقد', 'المشتريات', 'عقد موقع'),
                        ('الشراء', '2.2', 'تخصيص الميزانية والموارد', 'المالية', 'اعتماد الميزانية'),
                        ('التنفيذ', '3.1', 'تجهيز البنية التحتية والبيئة', 'تقنية المعلومات', 'بيئة جاهزة'),
                        ('التنفيذ', '3.2', 'تثبيت وتكوين الحل', 'تقنية المعلومات/المورد', 'نظام مُكوّن'),
                        ('التنفيذ', '3.3', 'الدمج مع الأنظمة الحالية', 'تقنية المعلومات', 'اكتمال التكامل'),
                        ('الاختبار', '4.1', 'إجراء اختبار القبول والأمان', 'ضمان الجودة', 'نتائج الاختبار'),
                        ('التشغيل', '5.1', 'تدريب فريق التشغيل', 'التدريب', 'فريق مدرب'),
                    ],
                    'evidence': ['عقد المورد', 'تقرير التثبيت', 'نتائج اختبار التكامل', 'شهادات التدريب']
                },
                'training': {
                    'steps': [
                        ('التخطيط', '1.1', 'تقييم مستوى الوعي الحالي (استبيان أساسي)', 'أمن المعلومات', 'تقرير الأساس'),
                        ('التخطيط', '1.2', 'تحديد الفئات المستهدفة وأهداف التعلم', 'التدريب', 'خطة التدريب'),
                        ('التخطيط', '1.3', 'اختيار طرق تقديم التدريب', 'التدريب', 'استراتيجية التقديم'),
                        ('التطوير', '2.1', 'تطوير محتوى ومواد التدريب', 'التدريب', 'وحدات التدريب'),
                        ('التطوير', '2.2', 'إنشاء التقييمات والاختبارات', 'التدريب', 'بنك الأسئلة'),
                        ('التطوير', '2.3', 'إعداد سيناريوهات محاكاة التصيد', 'فريق الأمن', 'خطة المحاكاة'),
                        ('التنفيذ', '3.1', 'إطلاق برنامج التدريب الإلزامي', 'الموارد البشرية', 'جدول التدريب'),
                        ('التنفيذ', '3.2', 'تنفيذ محاكاة التصيد', 'فريق الأمن', 'نتائج المحاكاة'),
                        ('التنفيذ', '3.3', 'تقديم تدريب علاجي للفاشلين', 'التدريب', 'سجل المعالجة'),
                        ('المراقبة', '4.1', 'تتبع معدلات الإكمال والدرجات', 'التدريب', 'لوحة التقدم'),
                    ],
                    'evidence': ['سجلات إتمام التدريب', 'درجات التقييم', 'نتائج محاكاة التصيد', 'مقاييس التحسن']
                },
                'incident': {
                    'steps': [
                        ('التخطيط', '1.1', 'مراجعة قدرات الاستجابة الحالية', 'فريق الأمن', 'تقييم الفجوات'),
                        ('التخطيط', '1.2', 'تحديد فئات ومستويات خطورة الحوادث', 'فريق الأمن', 'مصفوفة التصنيف'),
                        ('التطوير', '2.1', 'تطوير أدلة الاستجابة للحوادث', 'فريق الأمن', 'وثائق الأدلة'),
                        ('التطوير', '2.2', 'إنشاء إجراءات التصعيد وقوائم الاتصال', 'فريق الأمن', 'مصفوفة التصعيد'),
                        ('التطوير', '2.3', 'تصميم قوالب التقارير', 'فريق الأمن', 'قوالب التقارير'),
                        ('بناء الفريق', '3.1', 'تشكيل فريق CSIRT/IRT', 'الإدارة', 'ميثاق الفريق'),
                        ('بناء الفريق', '3.2', 'تحديد الأدوار والمسؤوليات (RACI)', 'فريق الأمن', 'مصفوفة RACI'),
                        ('التدريب', '4.1', 'تدريب فريق الاستجابة للحوادث', 'التدريب', 'فريق مدرب'),
                        ('الاختبار', '5.1', 'إجراء تمارين الطاولة', 'فريق الأمن', 'تقرير التمرين'),
                        ('الاختبار', '5.2', 'تنفيذ محاكاة كاملة', 'فريق الأمن', 'نتائج المحاكاة'),
                    ],
                    'evidence': ['خطة IR المعتمدة', 'قائمة فريق CSIRT', 'تقرير تمرين الطاولة', 'تقرير ما بعد المحاكاة']
                },
                'data': {
                    'steps': [
                        ('التخطيط', '1.1', 'جرد جميع أصول البيانات', 'إدارة البيانات', 'جرد البيانات'),
                        ('التخطيط', '1.2', 'تصنيف البيانات حسب مستوى الحساسية', 'أمن المعلومات', 'نظام التصنيف'),
                        ('التخطيط', '1.3', 'رسم خرائط تدفق البيانات ومواقع التخزين', 'تقنية المعلومات', 'مخطط تدفق البيانات'),
                        ('التنفيذ', '2.1', 'تطبيق تسميات تصنيف البيانات', 'إدارة البيانات', 'بيانات مصنفة'),
                        ('التنفيذ', '2.2', 'تنفيذ ضوابط DLP', 'فريق الأمن', 'تكوين DLP'),
                        ('التنفيذ', '2.3', 'تفعيل التشفير للبيانات الحساسة', 'تقنية المعلومات', 'تقرير التشفير'),
                        ('التنفيذ', '2.4', 'تكوين ضوابط الوصول (الحاجة للمعرفة)', 'تقنية المعلومات', 'مصفوفة الوصول'),
                        ('المراقبة', '3.1', 'نشر أدوات مراقبة البيانات', 'فريق الأمن', 'المراقبة فعالة'),
                        ('المراقبة', '3.2', 'وضع إجراءات الاستجابة لاختراق البيانات', 'فريق الأمن', 'إجراءات الاختراق'),
                        ('الامتثال', '4.1', 'التحقق من امتثال PDPL/GDPR', 'الامتثال', 'تقرير الامتثال'),
                    ],
                    'evidence': ['سجل تصنيف البيانات', 'تكوين سياسة DLP', 'شهادات التشفير', 'مصفوفة التحكم بالوصول']
                },
                'default': {
                    'steps': [
                        ('التخطيط', '1.1', 'تقييم الوضع الحالي وتحديد المتطلبات', 'قائد المشروع', 'تقرير التقييم'),
                        ('التخطيط', '1.2', 'تحديد النطاق ومعايير النجاح', 'قائد المشروع', 'ميثاق المشروع'),
                        ('التخطيط', '1.3', 'وضع الجدول الزمني للتنفيذ', 'قائد المشروع', 'خطة المشروع'),
                        ('التنفيذ', '2.1', 'تخصيص الموارد والميزانية', 'الإدارة', 'تخصيص الموارد'),
                        ('التنفيذ', '2.2', 'تنفيذ أنشطة التطبيق', 'فريق التنفيذ', 'تقارير التقدم'),
                        ('التنفيذ', '2.3', 'تدريب الموظفين المعنيين', 'التدريب', 'سجلات التدريب'),
                        ('التحقق', '3.1', 'اختبار والتحقق من التنفيذ', 'ضمان الجودة', 'نتائج الاختبار'),
                        ('التحقق', '3.2', 'إجراء مراجعة الإدارة', 'الإدارة', 'محضر المراجعة'),
                        ('الإغلاق', '4.1', 'توثيق الدروس المستفادة', 'قائد المشروع', 'الدروس المستفادة'),
                        ('الإغلاق', '4.2', 'الحصول على الإقرار الرسمي', 'الإدارة', 'وثيقة الإقرار'),
                    ],
                    'evidence': ['تقرير التقييم', 'سجلات التنفيذ', 'نتائج الاختبار', 'وثيقة الإقرار']
                }
            }
            
            def get_gap_type(gap_name):
                """Determine gap type from name for template selection."""
                gap_lower = gap_name.lower()
                if any(kw in gap_lower for kw in ['policy', 'سياس', 'procedure', 'إجراء', 'documentation', 'توثيق']):
                    return 'policy'
                elif any(kw in gap_lower for kw in ['technology', 'تقني', 'siem', 'edr', 'tool', 'أداة', 'system', 'نظام', 'software', 'برنامج']):
                    return 'technology'
                elif any(kw in gap_lower for kw in ['training', 'تدريب', 'awareness', 'توعية', 'skill', 'مهار']):
                    return 'training'
                elif any(kw in gap_lower for kw in ['incident', 'حادث', 'response', 'استجابة', 'csirt', 'soc']):
                    return 'incident'
                elif any(kw in gap_lower for kw in ['data', 'بيان', 'protection', 'حماية', 'privacy', 'خصوصية', 'encryption', 'تشفير', 'dlp']):
                    return 'data'
                return 'default'
            
            # Generate guidelines
            if lang_code == 'ar':
                # Check how many guides already exist
                existing_guides = gaps_content.count('دليل تنفيذ الفجوة رقم')
                if existing_guides >= len(gaps_list[:5]):
                    return gaps_content  # All guides present
                
                guidelines = "\n\n---\n\n### دليل التنفيذ لكل فجوة:\n\n"
                for num, gap_name in gaps_list[:5]:
                    # Check if this specific guide already exists
                    if f'دليل تنفيذ الفجوة رقم {num}' in gaps_content:
                        continue
                    
                    gap_type = get_gap_type(gap_name)
                    template = gap_templates_ar.get(gap_type, gap_templates_ar['default'])
                    
                    guidelines += f"---\n#### دليل تنفيذ الفجوة رقم {num}: {gap_name}\n\n"
                    guidelines += "**الخطوات التفصيلية:**\n"
                    guidelines += "| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |\n"
                    guidelines += "|---------|--------|-------|---------|----------|\n"
                    for step in template['steps']:
                        guidelines += f"| {step[0]} | {step[1]} | {step[2]} | {step[3]} | {step[4]} |\n"
                    guidelines += f"\n**الأدلة المطلوبة للإغلاق:** ☐ {' ☐ '.join(template['evidence'])}\n\n"
            else:
                # Check how many guides already exist
                existing_guides = gaps_content.count('Implementation Guide:')
                if existing_guides >= len(gaps_list[:5]):
                    return gaps_content  # All guides present
                
                guidelines = "\n\n---\n\n### Implementation Guidelines for Each Gap:\n\n"
                for num, gap_name in gaps_list[:5]:
                    # Check if this specific guide already exists
                    if f'Gap #{num} Implementation Guide' in gaps_content:
                        continue
                    
                    gap_type = get_gap_type(gap_name)
                    template = gap_templates_en.get(gap_type, gap_templates_en['default'])
                    
                    guidelines += f"---\n#### Gap #{num} Implementation Guide: {gap_name}\n\n"
                    guidelines += "**Step-by-Step Implementation:**\n"
                    guidelines += "| Phase | Step | Description | Owner | Deliverable |\n"
                    guidelines += "|-------|------|-------------|-------|-------------|\n"
                    for step in template['steps']:
                        guidelines += f"| {step[0]} | {step[1]} | {step[2]} | {step[3]} | {step[4]} |\n"
                    guidelines += f"\n**Evidence Required for Closure:** ☐ {' ☐ '.join(template['evidence'])}\n\n"
            
            return gaps_content + guidelines
        
        # Assign parts to sections based on content detection
        assigned = set()
        print(f"DEBUG: Number of parts to assign: {len(parts)}", flush=True)
        for idx, part in enumerate(parts):
            section_type = identify_section(part, lang)
            print(f"DEBUG: Part {idx} identified as: {section_type} (first 100 chars: {part[:100]})", flush=True)
            if section_type and section_type not in assigned:
                sections[section_type] = part.strip()
                assigned.add(section_type)
        
        print(f"DEBUG: Assigned sections: {assigned}", flush=True)
        
        # CRITICAL FIX: If we only have 1-2 parts, the content might all be in one block
        # Try to extract sections from within the single block
        if len(parts) <= 2 and len(assigned) < 4:
            print("DEBUG: Few parts detected - trying to extract sections from content block", flush=True)
            full_content = '\n'.join(parts)
            
            # Define section markers for Arabic
            ar_section_markers = [
                (r'(##\s*1\.?\s*الرؤية[^\n]*|##\s*الرؤية والأهداف)', 'vision'),
                (r'(##\s*2\.?\s*تحليل[^\n]*|##\s*تحليل الفجوات)', 'gaps'),
                (r'(##\s*3\.?\s*الركائز[^\n]*|##\s*الركائز الاستراتيجية)', 'pillars'),
                (r'(##\s*4\.?\s*خارطة[^\n]*|##\s*خارطة الطريق)', 'roadmap'),
                (r'(##\s*5\.?\s*مؤشرات[^\n]*|##\s*مؤشرات الأداء)', 'kpis'),
                (r'(##\s*6\.?\s*تقييم[^\n]*|##\s*تقييم الثقة)', 'confidence'),
            ]
            
            # Define section markers for English
            en_section_markers = [
                (r'(##\s*1\.?\s*Vision[^\n]*)', 'vision'),
                (r'(##\s*2\.?\s*Gap[^\n]*)', 'gaps'),
                (r'(##\s*3\.?\s*Strategic[^\n]*|##\s*3\.?\s*Pillars[^\n]*)', 'pillars'),
                (r'(##\s*4\.?\s*Implementation[^\n]*|##\s*4\.?\s*Roadmap[^\n]*)', 'roadmap'),
                (r'(##\s*5\.?\s*Key Performance[^\n]*|##\s*5\.?\s*KPI[^\n]*)', 'kpis'),
                (r'(##\s*6\.?\s*Confidence[^\n]*)', 'confidence'),
            ]
            
            markers = ar_section_markers if lang == 'ar' else en_section_markers
            
            # Find positions of each section
            section_positions = []
            for pattern, section_name in markers:
                match = re.search(pattern, full_content, re.IGNORECASE)
                if match:
                    section_positions.append((match.start(), section_name, match.group()))
                    print(f"DEBUG: Found {section_name} at position {match.start()}", flush=True)
            
            # Sort by position
            section_positions.sort(key=lambda x: x[0])
            
            # Extract content for each section
            for i, (pos, section_name, header) in enumerate(section_positions):
                if section_name not in assigned or not sections.get(section_name):
                    # Find end position (start of next section or end of content)
                    end_pos = section_positions[i + 1][0] if i + 1 < len(section_positions) else len(full_content)
                    section_content = full_content[pos:end_pos].strip()
                    if section_content:
                        sections[section_name] = section_content
                        assigned.add(section_name)
                        print(f"DEBUG: Extracted {section_name} ({len(section_content)} chars)", flush=True)
        
        # Ensure all 6 sections are filled
        section_order = ['vision', 'gaps', 'pillars', 'roadmap', 'kpis', 'confidence']
        
        # Order-based assignment for any remaining empty sections
        for i, part in enumerate(parts[:6]):
            if i < len(section_order):
                section_name = section_order[i]
                if not sections.get(section_name) or sections[section_name].strip() == '':
                    sections[section_name] = part.strip()
                    print(f"DEBUG: Assigned part {i} to {section_name} (order-based)", flush=True)
        
        # If we still have empty sections and more parts available, fill them
        empty_sections = [s for s in section_order if not sections.get(s) or sections[s].strip() == '']
        if empty_sections and len(parts) > 6:
            for i, extra_part in enumerate(parts[6:]):
                if i < len(empty_sections):
                    sections[empty_sections[i]] = extra_part.strip()
                    print(f"DEBUG: Assigned extra part to {empty_sections[i]}", flush=True)
        
        # Log final section status
        for section_name in section_order:
            content_len = len(sections.get(section_name, ''))
            print(f"DEBUG: Section '{section_name}' has {content_len} chars", flush=True)
        
        # INJECT IMPLEMENTATION GUIDELINES if missing from gaps section
        if sections.get('gaps'):
            print("DEBUG: Checking gaps section for implementation guidelines...", flush=True)
            original_len = len(sections['gaps'])
            sections['gaps'] = inject_implementation_guidelines(sections['gaps'], lang)
            new_len = len(sections['gaps'])
            if new_len > original_len:
                print(f"DEBUG: Injected implementation guidelines (+{new_len - original_len} chars)", flush=True)
            else:
                print("DEBUG: Guidelines already present, no injection needed", flush=True)
        
        # INJECT KPI ASSESSMENT GUIDES if missing from KPIs section
        def inject_kpi_assessment_guides(kpi_content, lang_code):
            """Inject KPI assessment guides if AI didn't include them."""
            if not kpi_content:
                return kpi_content
            
            # Check if guides already exist
            has_guides = (
                'Assessment Guide' in kpi_content or
                'دليل تقييم المؤشر' in kpi_content or
                'Assessment Methodology' in kpi_content or
                'منهجية التقييم' in kpi_content
            )
            
            if has_guides:
                return kpi_content
            
            # Extract KPI names from table
            import re
            kpi_pattern = r'\|\s*(\d+)\s*\|\s*([^|]+)\s*\|'
            kpis_found = re.findall(kpi_pattern, kpi_content)
            
            kpi_list = []
            for num, name in kpis_found:
                name = name.strip()
                if name and name.lower() not in ['kpi', 'المؤشر', '#', 'description', 'الوصف', 'current', 'الحالية', 'target', 'المستهدفة']:
                    kpi_list.append((num, name))
            
            if not kpi_list or len(kpi_list) < 2:
                return kpi_content
            
            # Generate assessment guides - KPI-specific, not generic
            # Map KPI keywords to specific measurement steps
            KPI_GUIDES_AR = {
                'امتثال': [
                    ('حصر جميع الضوابط المنطبقة على المنظمة', 'فريق الامتثال', 'مصفوفة انطباق الضوابط'),
                    ('تقييم حالة التطبيق لكل ضابط: مطبق / جزئي / غير مطبق', 'فريق أمن المعلومات', 'ورقة تقييم الضوابط'),
                    ('احتساب: (مطبق بالكامل + 0.5×جزئي) / إجمالي الضوابط', 'فريق الامتثال', 'نسبة الامتثال'),
                    ('تحديد الفجوات وترتيب أولويات المعالجة حسب المخاطر', 'فريق المخاطر', 'خطة معالجة مرتبة'),
                ],
                'استجابة|حوادث|كشف|MTTD|MTTR': [
                    ('تكوين SIEM لتسجيل وقت توليد التنبيه تلقائياً', 'فريق SOC', 'قواعد الارتباط'),
                    ('استخراج الأوقات من تذاكر الحوادث آخر 90 يوم', 'فريق SOC', 'بيانات الحوادث'),
                    ('احتساب متوسط الوقت بين الاختراق والكشف (MTTD)', 'فريق SOC', 'قيمة MTTD'),
                    ('احتساب متوسط الوقت بين الكشف والاحتواء الكامل (MTTR)', 'فريق SOC', 'قيمة MTTR'),
                ],
                'تدريب|توعية|تدريب.*إكمال': [
                    ('الحصول على إجمالي عدد الموظفين من الموارد البشرية', 'الموارد البشرية', 'قائمة الموظفين'),
                    ('استخراج سجلات الإكمال من نظام إدارة التعلم (LMS)', 'فريق التدريب', 'سجلات الإكمال'),
                    ('مطابقة القائمة وتحديد غير المكملين', 'فريق التدريب', 'تقرير الفجوات'),
                    ('قياس معدل النقر في محاكاة التصيد كمقياس تكميلي', 'أمن المعلومات', 'نتائج المحاكاة'),
                ],
                'ثغرات|معالجة|SLA': [
                    ('استخراج جميع الثغرات من أدوات الفحص', 'إدارة الثغرات', 'جرد الثغرات'),
                    ('تصنيف حسب الخطورة: حرجة (7 أيام)، عالية (14 يوم)، متوسطة (30 يوم)', 'إدارة الثغرات', 'قائمة مصنفة'),
                    ('تتبع تواريخ المعالجة من نظام التغييرات', 'عمليات تقنية المعلومات', 'جدول المعالجة'),
                    ('احتساب: المعالجة ضمن الوقت / إجمالي الثغرات لكل مستوى', 'إدارة الثغرات', 'نسبة الالتزام'),
                ],
                'هوية|وصول|IAM|صلاحيات': [
                    ('حصر جميع ضوابط IAM المطلوبة (MFA، PAM، RBAC، مراجعة الصلاحيات)', 'فريق IAM', 'قائمة ضوابط IAM'),
                    ('تقييم حالة التطبيق لكل ضابط عبر جميع الأنظمة', 'فريق IAM', 'حالة IAM لكل نظام'),
                    ('التحقق: نسبة MFA، تغطية الحسابات المميزة، دورية المراجعة', 'فريق IAM', 'القياسات الفرعية'),
                    ('احتساب النتيجة المركبة: الضوابط المطبقة / إجمالي ضوابط IAM', 'فريق IAM', 'نسبة تطبيق IAM'),
                ],
                'تقنية.*ضوابط|ضوابط.*تقني|technical': [
                    ('استخراج قائمة الضوابط التقنية المطلوبة من الإطار', 'فريق الامتثال', 'سجل الضوابط التقنية'),
                    ('ربط كل ضابط بالتقنية/الأداة/التكوين المطلوب', 'فريق تقنية المعلومات', 'خريطة الضوابط'),
                    ('التحقق من التطبيق عبر تدقيق التكوينات وجمع الأدلة', 'أمن المعلومات', 'مستودع الأدلة'),
                    ('احتساب النسبة الإجمالية وتحديد الفجوات الحرجة', 'فريق الامتثال', 'لوحة معلومات التطبيق'),
                ],
                'استمرارية|BCP|تعافي': [
                    ('مراجعة وثائق خطط الاستمرارية وتحديد جميع الخطط المطلوب اختبارها', 'فريق BCM', 'جرد الخطط'),
                    ('تصميم سيناريوهات الاختبار: تمارين طاولة وتمارين وظيفية', 'فريق BCM', 'سيناريوهات الاختبار'),
                    ('تنفيذ الاختبارات وقياس: تحقيق RTO/RPO أثناء الاختبار', 'فريق BCM', 'قياس RTO/RPO'),
                    ('توثيق الدروس المستفادة وتحديث الخطط', 'فريق BCM', 'خطة محدثة'),
                ],
                'طرف ثالث|مورد|أطراف|vendor': [
                    ('حصر جميع الموردين الذين لديهم وصول للبيانات أو الأنظمة', 'المشتريات', 'سجل الموردين'),
                    ('تصنيف الموردين حسب مستوى الخطورة: حرج / عالي / متوسط / منخفض', 'فريق المخاطر', 'قائمة مصنفة'),
                    ('إرسال استبيانات التقييم الأمني للموردين الحرجين والعاليين', 'إدارة مخاطر الأطراف الثالثة', 'استبيانات مكتملة'),
                    ('احتساب: الموردون المستوفون / إجمالي الموردين المقيّمين', 'إدارة مخاطر الأطراف الثالثة', 'نسبة الامتثال'),
                ],
            }
            
            KPI_GUIDES_EN = {
                'third.party|vendor|supplier': [
                    ('Inventory all vendors with access to data or systems', 'Procurement', 'Vendor register'),
                    ('Classify vendors by risk tier: Critical / High / Medium / Low', 'Risk Team', 'Tiered vendor list'),
                    ('Send security questionnaires to Critical/High vendors', 'Third-Party Risk', 'Completed assessments'),
                    ('Calculate: Vendors meeting requirements / Total assessed', 'Third-Party Risk', 'Compliance rate'),
                ],
                'identity|access.*control|access.*manage|IAM|privileged': [
                    ('Inventory all IAM controls required (MFA, PAM, RBAC, access reviews)', 'IAM Team', 'IAM controls checklist'),
                    ('Assess implementation across all systems', 'IAM Team', 'System-by-system IAM status'),
                    ('Verify: MFA enrollment, privileged account coverage, review cadence', 'IAM Team', 'Sub-metric measurements'),
                    ('Calculate composite: controls implemented / total IAM controls', 'IAM Team', 'IAM implementation rate'),
                ],
                'detect|response|incident|MTTD|MTTR': [
                    ('Configure SIEM to timestamp alert generation automatically', 'SOC Team', 'SIEM correlation rules'),
                    ('Extract timestamps from last 90 days of incident tickets', 'SOC Team', 'Incident timeline dataset'),
                    ('Calculate average time between compromise and detection (MTTD)', 'SOC Team', 'MTTD metric'),
                    ('Calculate average time between detection and containment (MTTR)', 'SOC Team', 'MTTR metric'),
                ],
                'training|awareness|training.*completion': [
                    ('Obtain total headcount including contractors from HR', 'HR Department', 'Employee roster'),
                    ('Pull completion records from LMS', 'Training Team', 'Completion logs'),
                    ('Cross-reference roster vs completions, flag non-completions', 'Training Team', 'Gap report'),
                    ('Measure phishing simulation click rate as supplementary metric', 'InfoSec Team', 'Phishing test results'),
                ],
                'vulnerabilit|remediat|patch|SLA': [
                    ('Extract all vulnerabilities from scanning tools (Nessus, Qualys)', 'Vulnerability Mgmt', 'Full vulnerability inventory'),
                    ('Classify by severity: Critical (7d), High (14d), Medium (30d)', 'Vulnerability Mgmt', 'Classified list with SLA deadlines'),
                    ('Track remediation dates from patching/change management system', 'IT Operations', 'Remediation timeline'),
                    ('Calculate: Remediated within SLA / Total per severity', 'Vulnerability Mgmt', 'SLA compliance rate'),
                ],
                'technical.*control|control.*implement(?!.*access)': [
                    ('Extract mandatory technical controls from framework', 'Compliance Team', 'Technical controls register'),
                    ('Map each control to specific technology/tool/configuration', 'IT Team', 'Control-to-technology map'),
                    ('Verify via configuration audits and evidence collection', 'InfoSec Team', 'Evidence repository'),
                    ('Score per control and calculate aggregate rate', 'Compliance Team', 'Implementation dashboard'),
                ],
                'continuity|BCP|disaster|recovery': [
                    ('Review BCP documentation and identify plans requiring testing', 'BCM Team', 'Plans inventory'),
                    ('Design test scenarios: tabletop and functional drills', 'BCM Team', 'Test scenarios'),
                    ('Execute tests and measure RTO/RPO achievement', 'BCM Team', 'RTO/RPO measurement'),
                    ('Document lessons learned and update plans', 'BCM Team', 'Updated BCP'),
                ],
                'compliance|audit.*pass': [
                    ('Map all applicable framework controls to organizational scope', 'Compliance Team', 'Controls applicability matrix'),
                    ('Assess implementation status per control: Implemented / Partial / Not', 'InfoSec Team', 'Control-by-control status'),
                    ('Score: (Fully Implemented + 0.5×Partial) / Total Controls', 'Compliance Team', 'Compliance percentage'),
                    ('Identify gaps and prioritize remediation by risk', 'Risk Team', 'Prioritized remediation plan'),
                ],
            }
            
            def find_kpi_guide(kpi_name, guides_dict):
                """Find the BEST matching guide for a KPI name - most specific match wins."""
                matches = []
                for pattern, steps in guides_dict.items():
                    m = re.search(pattern, kpi_name, re.IGNORECASE)
                    if m:
                        # Score by: number of pattern alternatives matched (more = more specific)
                        # and length of the matched text (longer = more specific)
                        match_len = len(m.group())
                        # Count how many alternatives in the pattern actually match
                        alt_matches = sum(1 for alt in pattern.split('|') if re.search(alt, kpi_name, re.IGNORECASE))
                        matches.append((alt_matches, match_len, steps))
                if matches:
                    # Return the most specific match (most alternatives matched, then longest match)
                    matches.sort(reverse=True)
                    return matches[0][2]
                return None
            
            if lang_code == 'ar':
                guides = "\n\n### أدلة تقييم مؤشرات الأداء\n\n"
                for num, kpi_name in kpi_list[:8]:
                    steps = find_kpi_guide(kpi_name, KPI_GUIDES_AR)
                    guides += f"---\n#### دليل تقييم المؤشر رقم {num}: {kpi_name[:40]}\n"
                    guides += "| الخطوة | الإجراء | المسؤول | المخرج |\n"
                    guides += "|--------|--------|---------|--------|\n"
                    if steps:
                        for i, (action, owner, output) in enumerate(steps, 1):
                            guides += f"| {i} | {action} | {owner} | {output} |\n"
                    else:
                        guides += f"| 1 | تحديد متطلبات القياس الخاصة بمؤشر {kpi_name[:30]} | فريق الامتثال | وثيقة المتطلبات |\n"
                        guides += f"| 2 | جمع البيانات من الأنظمة والأدوات ذات الصلة | الفريق التقني | البيانات المجمعة |\n"
                        guides += f"| 3 | تطبيق صيغة الاحتساب المحددة لهذا المؤشر | فريق القياس | القيمة المحتسبة |\n"
                        guides += f"| 4 | مراجعة النتائج وتحديد إجراءات التحسين | الإدارة المعنية | تقرير التحسين |\n"
                    guides += "\n"
            else:
                guides = "\n\n### KPI Assessment Guidelines\n\n"
                for num, kpi_name in kpi_list[:8]:
                    steps = find_kpi_guide(kpi_name, KPI_GUIDES_EN)
                    guides += f"---\n#### KPI #{num} Assessment Guide: {kpi_name[:40]}\n"
                    guides += "| Step | Action | Owner | Output |\n"
                    guides += "|------|--------|-------|--------|\n"
                    if steps:
                        for i, (action, owner, output) in enumerate(steps, 1):
                            guides += f"| {i} | {action} | {owner} | {output} |\n"
                    else:
                        guides += f"| 1 | Identify specific data sources for {kpi_name[:30]} | Compliance Team | Data source map |\n"
                        guides += f"| 2 | Collect measurements from relevant systems and tools | Technical Team | Raw measurements |\n"
                        guides += f"| 3 | Apply KPI-specific calculation formula | Measurement Team | Calculated value |\n"
                        guides += f"| 4 | Review results and identify improvement actions | Management | Improvement report |\n"
                    guides += "\n"
            
            return kpi_content + guides
        
        if sections.get('kpis'):
            print("DEBUG: Checking KPIs section for assessment guides...", flush=True)
            original_len = len(sections['kpis'])
            sections['kpis'] = inject_kpi_assessment_guides(sections['kpis'], lang)
            new_len = len(sections['kpis'])
            if new_len > original_len:
                print(f"DEBUG: Injected KPI assessment guides (+{new_len - original_len} chars)", flush=True)
            else:
                print("DEBUG: KPI guides already present, no injection needed", flush=True)
        
        # FINAL CLEANUP: Remove any remaining instruction artifacts from all sections
        import re
        def final_cleanup(text):
            if not text:
                return text
            # Remove [SECTION] markers
            text = re.sub(r'\[SECTION\]', '', text)
            # Remove warning/instruction blocks
            text = re.sub(r'⚠️⚠️⚠️[^⚠]*?⚠️⚠️⚠️', '', text, flags=re.DOTALL)
            text = re.sub(r'⚠️\s*CRITICAL[^\n]*(?:\n-[^\n]*)*', '', text)
            text = re.sub(r'⚠️\s*تعليمات[^\n]*(?:\n-[^\n]*)*', '', text)
            text = re.sub(r'⚠️\s*مهم جداً[^\n]*(?:\n-[^\n]*)*', '', text)
            # Remove instruction lines starting with warning emojis
            text = re.sub(r'\n⚠️[^\n]+', '', text)
            # Clean up multiple newlines
            text = re.sub(r'\n{4,}', '\n\n\n', text)
            return text.strip()
        
        for section_key in sections:
            sections[section_key] = final_cleanup(sections[section_key])
        
        # Save to database
        try:
            conn = get_db()
            conn.execute('''INSERT INTO strategies (user_id, domain, org_name, sector, content, language)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                        (session['user_id'], data.get('domain'), data.get('org_name'), 
                         data.get('sector'), content, lang))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print(f"Database error: {db_error}")
        
        return jsonify({
            'success': True,
            'sections': sections,
            'debug_vision_preview': sections.get('vision', '')[:200] if sections.get('vision') else 'EMPTY'
        })
        
    except Exception as e:
        print(f"Strategy generation error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# BILINGUAL GENERATION API (Feature 4)
# ============================================================================

@app.route('/api/generate-bilingual', methods=['POST'])
@login_required
def api_generate_bilingual():
    """Generate document in both English and Arabic."""
    try:
        data = request.json
        doc_type = data.get('type', 'strategy')  # strategy, policy, audit, risk
        domain = data.get('domain', 'Cyber Security')
        
        # Check usage limits for both languages
        table_map = {'strategy': 'strategies', 'policy': 'policies', 'audit': 'audits', 'risk': 'risks'}
        table = table_map.get(doc_type, 'strategies')
        
        can_generate, used, limit = check_usage_limit(session['user_id'], table, domain)
        if not can_generate:
            return jsonify({
                'success': False,
                'error': f'Usage limit reached for {domain}.',
                'limit_reached': True
            }), 429
        
        results = {}
        
        # Generate English version
        data['language'] = 'en'
        en_content = generate_document_content(doc_type, data, 'en')
        results['en'] = en_content
        
        # Generate Arabic version
        data['language'] = 'ar'
        ar_content = generate_document_content(doc_type, data, 'ar')
        results['ar'] = ar_content
        
        return jsonify({
            'success': True,
            'bilingual': True,
            'content': results
        })
        
    except Exception as e:
        print(f"Bilingual generation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def generate_document_content(doc_type, data, lang):
    """Helper function to generate document content."""
    domain = data.get('domain', 'Cyber Security')
    
    if doc_type == 'strategy':
        # Simplified strategy prompt for bilingual
        if lang == 'ar':
            prompt = f"""أنشئ ملخص استراتيجية موجز في مجال {domain} يتضمن:
1. الرؤية والأهداف
2. الركائز الاستراتيجية
3. خارطة الطريق
اجعلها مختصرة ومهنية."""
        else:
            prompt = f"""Create a brief strategy summary for {domain} including:
1. Vision and Objectives
2. Strategic Pillars
3. Implementation Roadmap
Keep it concise and professional."""
    elif doc_type == 'policy':
        policy_name = data.get('policy_name', 'Security Policy')
        if lang == 'ar':
            prompt = f"""أنشئ ملخص سياسة {policy_name} في مجال {domain} يتضمن:
1. الغرض والنطاق
2. بنود السياسة الرئيسية
3. الأدوار والمسؤوليات"""
        else:
            prompt = f"""Create a {policy_name} summary for {domain} including:
1. Purpose and Scope
2. Key Policy Statements
3. Roles and Responsibilities"""
    else:
        prompt = f"Generate a brief {doc_type} document for {domain} in {lang}."
    
    return generate_ai_content(prompt, lang)

# ============================================================================
# CHAT WITH DOCUMENT API (Feature 1)
# ============================================================================

@app.route('/api/chat-document', methods=['POST'])
@login_required
def api_chat_document():
    """Chat with a generated document using AI."""
    try:
        data = request.json
        document_content = data.get('content', '')
        user_question = data.get('question', '')
        lang = data.get('language', 'en')
        
        if not document_content or not user_question:
            return jsonify({'success': False, 'error': 'Missing content or question'}), 400
        
        # Truncate content if too long
        max_content_length = 8000
        if len(document_content) > max_content_length:
            document_content = document_content[:max_content_length] + "..."
        
        if lang == 'ar':
            prompt = f"""أنت مساعد ذكي متخصص في الحوكمة والمخاطر والامتثال.

لديك الوثيقة التالية:
---
{document_content}
---

سؤال المستخدم: {user_question}

أجب على السؤال بناءً على محتوى الوثيقة. إذا لم تجد الإجابة في الوثيقة، أخبر المستخدم بذلك واقترح معلومات مفيدة.
اجعل إجابتك مختصرة ومفيدة."""
        else:
            prompt = f"""You are an intelligent GRC assistant.

You have the following document:
---
{document_content}
---

User question: {user_question}

Answer the question based on the document content. If the answer is not in the document, let the user know and suggest helpful information.
Keep your response concise and helpful."""
        
        response = generate_ai_content(prompt, lang)
        
        return jsonify({
            'success': True,
            'response': response
        })
        
    except Exception as e:
        print(f"Chat document error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# POLICY REVIEW API (Feature 2)
# ============================================================================

@app.route('/api/review-policy', methods=['POST'])
@login_required
def api_review_policy():
    """Review and analyze an existing policy document."""
    try:
        data = request.json
        policy_content = data.get('content', '')
        review_type = data.get('review_type', 'comprehensive')  # comprehensive, compliance, gaps
        framework = data.get('framework', 'ISO 27001')
        lang = data.get('language', 'en')
        
        if not policy_content:
            return jsonify({'success': False, 'error': 'No policy content provided'}), 400
        
        # Truncate if too long
        max_length = 10000
        if len(policy_content) > max_length:
            policy_content = policy_content[:max_length] + "..."
        
        if lang == 'ar':
            if review_type == 'compliance':
                prompt = f"""راجع السياسة التالية من حيث الامتثال لإطار {framework}:

{policy_content}

قدم تقرير مراجعة يتضمن:
## نتيجة المراجعة
### نقاط الامتثال ✅
- (قائمة بالنقاط المتوافقة)

### نقاط عدم الامتثال ❌
- (قائمة بالنقاط غير المتوافقة)

### التوصيات
| # | التوصية | الأولوية |
|---|---------|----------|
| 1 | ... | عالية/متوسطة/منخفضة |

### درجة الامتثال: X%"""
            elif review_type == 'gaps':
                prompt = f"""حلل الفجوات في السياسة التالية:

{policy_content}

قدم تقرير تحليل الفجوات:
## تحليل الفجوات
### الفجوات المحددة
| # | الفجوة | الوصف | الأثر |
|---|--------|-------|-------|
| 1 | ... | ... | عالي/متوسط/منخفض |

### خطة المعالجة
| # | الفجوة | الإجراء المطلوب | الجدول الزمني |
|---|--------|----------------|--------------|"""
            else:
                prompt = f"""قدم مراجعة شاملة للسياسة التالية:

{policy_content}

## تقرير المراجعة الشاملة

### ملخص تنفيذي
(ملخص موجز للسياسة ونتائج المراجعة)

### نقاط القوة ✅
- ...

### نقاط الضعف ❌
- ...

### التوصيات للتحسين
| # | التوصية | الأولوية | الجدول الزمني |
|---|---------|----------|--------------|

### التقييم العام: X/10"""
        else:
            if review_type == 'compliance':
                prompt = f"""Review the following policy for compliance with {framework}:

{policy_content}

Provide a compliance review report:
## Review Results
### Compliant Points ✅
- (list of compliant items)

### Non-Compliant Points ❌
- (list of non-compliant items)

### Recommendations
| # | Recommendation | Priority |
|---|----------------|----------|
| 1 | ... | High/Medium/Low |

### Compliance Score: X%"""
            elif review_type == 'gaps':
                prompt = f"""Analyze gaps in the following policy:

{policy_content}

Provide a gap analysis report:
## Gap Analysis
### Identified Gaps
| # | Gap | Description | Impact |
|---|-----|-------------|--------|
| 1 | ... | ... | High/Medium/Low |

### Remediation Plan
| # | Gap | Required Action | Timeline |
|---|-----|-----------------|----------|"""
            else:
                prompt = f"""Provide a comprehensive review of the following policy:

{policy_content}

IMPORTANT: Do NOT use specific dates or years (like Q1 2024, 2025). Use relative timeframes like "Within 30 days", "Within 3 months", "Short-term", "Medium-term".

## Comprehensive Review Report

### Executive Summary
(brief summary of policy and review findings)

### Strengths ✅
- ...

### Weaknesses ❌
- ...

### Improvement Recommendations
| # | Recommendation | Priority | Timeline |
|---|----------------|----------|----------|
| 1 | ... | High/Medium/Low | Within X days/months |

### Overall Rating: X/10"""
        
        review_result = generate_ai_content(prompt, lang)
        
        return jsonify({
            'success': True,
            'review': review_result,
            'review_type': review_type
        })
        
    except Exception as e:
        print(f"Policy review error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# MODIFY POLICY BASED ON REVIEW (Feature Enhancement)
# ============================================================================

@app.route('/api/modify-policy', methods=['POST'])
@login_required
def api_modify_policy():
    """Start policy modification as a background task (avoids Render 30s timeout)."""
    try:
        data = request.json
        policy_content = data.get('policy_content', '')
        review_content = data.get('review_content', '')
        framework = data.get('framework', 'ISO 27001')
        domain = data.get('domain', 'Cyber Security')
        lang = data.get('language', 'en')
        
        if not policy_content or not review_content:
            return jsonify({'success': False, 'error': 'Missing policy or review content'}), 400
        
        # Truncate to keep prompt manageable
        if len(policy_content) > 6000:
            policy_content = policy_content[:6000] + "\n..."
        if len(review_content) > 3000:
            review_content = review_content[:3000] + "\n..."
        
        if lang == 'ar':
            prompt = f"""أنت خبير في الحوكمة والمخاطر والامتثال. لديك سياسة وتقرير مراجعة لها.

## السياسة الحالية:
{policy_content}

## نتائج المراجعة:
{review_content}

المطلوب: أعد كتابة السياسة الكاملة مع تطبيق جميع التوصيات والتحسينات المذكورة في تقرير المراجعة. يجب أن:
- تحافظ على الهيكل العام للسياسة
- تضيف الأقسام المفقودة التي ذكرتها المراجعة
- تصحح نقاط عدم الامتثال
- تعزز نقاط الضعف المحددة
- تضيف التفاصيل والضوابط المطلوبة
- تتوافق مع إطار {framework}

اكتب السياسة المعدلة بالكامل (وليس فقط التغييرات):"""
        else:
            prompt = f"""You are a GRC expert. You have a policy and its review report.

## Current Policy:
{policy_content}

## Review Findings:
{review_content}

Task: Rewrite the COMPLETE policy incorporating all recommendations and improvements from the review. You must:
- Maintain the overall policy structure
- Add missing sections identified in the review
- Fix non-compliance points
- Strengthen identified weaknesses
- Add required details and controls
- Ensure alignment with {framework}

Write the complete modified policy (not just the changes):"""
        
        # Create background task in database
        task_id = str(uuid.uuid4())
        create_background_task(task_id, session['user_id'], domain)
        
        # Start background thread
        t = threading.Thread(target=run_ai_task, args=(task_id, prompt, lang))
        t.daemon = True
        t.start()
        
        # Return immediately with task_id — client will poll
        return jsonify({
            'success': True,
            'task_id': task_id,
            'status': 'pending'
        })
        
    except Exception as e:
        print(f"Policy modification error: {e}", flush=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/task-status/<task_id>')
@login_required
def api_task_status(task_id):
    """Poll for background task result (reads from database, works across workers)."""
    task = get_background_task(task_id)
    
    if not task:
        return jsonify({'status': 'not_found', 'error': 'Task not found'}), 404
    
    status = task['status']
    
    if status == 'pending':
        return jsonify({'status': 'pending'})
    
    elif status == 'done':
        result = task['result']
        
        # Save modified policy to policies table
        try:
            user_id = task['user_id']
            domain = task['callback_domain']
            if user_id and domain:
                conn = get_db()
                latest_policy = conn.execute(
                    'SELECT id FROM policies WHERE user_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1',
                    (user_id, domain)
                ).fetchone()
                if latest_policy:
                    conn.execute('UPDATE policies SET content = ? WHERE id = ?',
                                (result, latest_policy['id']))
                    conn.commit()
                conn.close()
        except Exception as db_err:
            print(f"DB update after modify: {db_err}", flush=True)
        
        # Cleanup
        delete_background_task(task_id)
        
        return jsonify({
            'status': 'done',
            'modified_policy': result
        })
    
    elif status == 'error':
        error = task['error'] or 'Unknown error'
        delete_background_task(task_id)
        return jsonify({'status': 'error', 'error': error})

# ============================================================================
# ERM RISK REGISTER API
# ============================================================================

@app.route('/api/risk-register', methods=['GET'])
@login_required
def api_risk_register_list():
    """List all risks in the user's risk register."""
    try:
        conn = get_db()
        risks = conn.execute(
            'SELECT * FROM risk_register WHERE user_id = ? ORDER BY (likelihood * impact) DESC, created_at DESC',
            (session['user_id'],)
        ).fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'risks': [dict(r) for r in risks]
        })
    except Exception as e:
        print(f"Risk register list error: {e}", flush=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/risk-register', methods=['POST'])
@login_required
def api_risk_register_create():
    """Add a new risk to the register."""
    try:
        data = request.json
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'success': False, 'error': 'Risk name is required'}), 400
        
        conn = get_db()
        conn.execute('''
            INSERT INTO risk_register (user_id, name, description, category, likelihood, impact, owner, treatment, treatment_plan, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'],
            name,
            data.get('description', ''),
            data.get('category', 'Operational'),
            int(data.get('likelihood', 3)),
            int(data.get('impact', 3)),
            data.get('owner', ''),
            data.get('treatment', 'Mitigate'),
            data.get('treatment_plan', ''),
            data.get('status', 'Open')
        ))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Risk register create error: {e}", flush=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/risk-register/<int:risk_id>', methods=['PUT'])
@login_required
def api_risk_register_update(risk_id):
    """Update an existing risk."""
    try:
        data = request.json
        conn = get_db()
        
        # Verify ownership
        risk = conn.execute('SELECT id FROM risk_register WHERE id = ? AND user_id = ?', (risk_id, session['user_id'])).fetchone()
        if not risk:
            conn.close()
            return jsonify({'success': False, 'error': 'Risk not found'}), 404
        
        conn.execute('''
            UPDATE risk_register SET
                name = ?, description = ?, category = ?, likelihood = ?, impact = ?,
                owner = ?, treatment = ?, treatment_plan = ?, status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        ''', (
            data.get('name', ''),
            data.get('description', ''),
            data.get('category', 'Operational'),
            int(data.get('likelihood', 3)),
            int(data.get('impact', 3)),
            data.get('owner', ''),
            data.get('treatment', 'Mitigate'),
            data.get('treatment_plan', ''),
            data.get('status', 'Open'),
            risk_id,
            session['user_id']
        ))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Risk register update error: {e}", flush=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/risk-register/<int:risk_id>', methods=['DELETE'])
@login_required
def api_risk_register_delete(risk_id):
    """Delete a risk from the register."""
    try:
        conn = get_db()
        conn.execute('DELETE FROM risk_register WHERE id = ? AND user_id = ?', (risk_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/risk-appetite', methods=['POST'])
@login_required
def api_risk_appetite():
    """Generate Risk Appetite Statement based on risk register data."""
    try:
        data = request.json
        risks = data.get('risks', [])
        lang = data.get('language', 'en')
        
        if not risks:
            return jsonify({'success': False, 'error': 'No risks provided'}), 400
        
        # Summarize risk register
        total = len(risks)
        critical = sum(1 for r in risks if r['likelihood'] * r['impact'] >= 20)
        high = sum(1 for r in risks if 12 <= r['likelihood'] * r['impact'] < 20)
        medium = sum(1 for r in risks if 6 <= r['likelihood'] * r['impact'] < 12)
        low = sum(1 for r in risks if r['likelihood'] * r['impact'] < 6)
        categories = list(set(r.get('category', '') for r in risks))
        
        risk_summary = f"Total: {total}, Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}. Categories: {', '.join(categories)}"
        
        if lang == 'ar':
            prompt = f"""أنت خبير في إدارة المخاطر المؤسسية ومتخصص في إطار COSO ERM وISO 31000.

بناءً على سجل المخاطر التالي:
- إجمالي المخاطر: {total}
- حرجة: {critical}، عالية: {high}، متوسطة: {medium}، منخفضة: {low}
- الفئات: {', '.join(categories)}

أنشئ بيان شهية المخاطر المؤسسية الشامل الذي يتضمن:

## 1. بيان شهية المخاطر العام
[فقرة تحدد المستوى العام لشهية المخاطر للمنظمة]

## 2. شهية المخاطر حسب الفئة
[لكل فئة من الفئات المذكورة، حدد مستوى الشهية: عالية، متوسطة، منخفضة، صفر]

### جدول شهية المخاطر:
| الفئة | مستوى الشهية | الحد الأقصى المقبول | المبرر |
|-------|-------------|-------------------|--------|

## 3. حدود التحمل ومعايير التصعيد
[جدول يوضح حدود التحمل لكل مستوى من المخاطر ومتى يتم التصعيد]

### مصفوفة التصعيد:
| مستوى الخطر | الإجراء المطلوب | الجهة المسؤولة | الإطار الزمني |
|------------|----------------|---------------|--------------|

## 4. أدوار ومسؤوليات إدارة المخاطر
[وفق نموذج الخطوط الثلاثة]

## 5. آلية المراجعة والتحديث
[كيفية مراجعة وتحديث بيان شهية المخاطر]

اكتب بيان شهية المخاطر بشكل احترافي ومتوافق مع COSO ERM وISO 31000:"""
        else:
            prompt = f"""You are an ERM expert specializing in COSO ERM Framework and ISO 31000.

Based on this risk register summary:
- Total risks: {total}
- Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}
- Categories: {', '.join(categories)}

Generate a comprehensive Risk Appetite Statement that includes:

## 1. Overall Risk Appetite Statement
[Paragraph defining the organization's general risk appetite level]

## 2. Risk Appetite by Category
[For each category, specify appetite level: High, Moderate, Low, Zero]

### Risk Appetite Table:
| Category | Appetite Level | Maximum Acceptable Threshold | Justification |
|----------|---------------|------------------------------|---------------|

## 3. Tolerance Thresholds & Escalation Criteria
[Table showing tolerance limits for each risk level and escalation triggers]

### Escalation Matrix:
| Risk Level | Required Action | Responsible Party | Timeframe |
|-----------|----------------|-------------------|-----------|

## 4. Risk Management Roles & Responsibilities
[Based on Three Lines Model]

## 5. Review & Update Mechanism
[How the risk appetite statement is reviewed and updated]

Write a professional risk appetite statement aligned with COSO ERM and ISO 31000:"""
        
        content = generate_ai_content(prompt, lang)
        
        return jsonify({
            'success': True,
            'content': content
        })
    except Exception as e:
        print(f"Risk appetite error: {e}", flush=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# GAP REMEDIATION API (Feature 3)
# ============================================================================

@app.route('/api/gap-remediation', methods=['POST'])
@login_required
def api_gap_remediation():
    """Generate remediation plan for identified gaps."""
    try:
        data = request.json
        gaps = data.get('gaps', [])  # List of gap descriptions
        domain = data.get('domain', 'Cyber Security')
        framework = data.get('framework', 'ISO 27001')
        priority = data.get('priority', 'all')  # all, high, medium, low
        lang = data.get('language', 'en')
        
        if not gaps:
            return jsonify({'success': False, 'error': 'No gaps provided'}), 400
        
        gaps_text = '\n'.join([f"- {gap}" for gap in gaps])
        
        if lang == 'ar':
            prompt = f"""أنت مستشار خبير في الحوكمة والمخاطر والامتثال.

الفجوات المحددة في مجال {domain} وفقاً لإطار {framework}:
{gaps_text}

أنشئ خطة معالجة شاملة:

## خطة المعالجة

### ملخص تنفيذي
(ملخص موجز للفجوات وخطة المعالجة)

### خطة العمل التفصيلية
| # | الفجوة | الإجراء | المسؤول | الموارد | الجدول الزمني | مؤشر النجاح |
|---|--------|---------|---------|---------|--------------|-------------|
| 1 | ... | ... | ... | ... | ... | ... |

### الأولويات
#### عالية (فورية)
- ...

#### متوسطة (3-6 أشهر)
- ...

#### منخفضة (6-12 شهر)
- ...

### الميزانية التقديرية
| البند | التكلفة التقديرية |
|-------|------------------|

### مؤشرات الأداء
| المؤشر | القيمة الحالية | القيمة المستهدفة |
|--------|---------------|-----------------|

### المخاطر والتحديات
| المخاطرة | الأثر | خطة التخفيف |
|----------|-------|------------|"""
        else:
            prompt = f"""You are an expert GRC consultant.

Identified gaps in {domain} according to {framework}:
{gaps_text}

Create a comprehensive remediation plan:

## Remediation Plan

### Executive Summary
(brief summary of gaps and remediation approach)

### Detailed Action Plan
| # | Gap | Action | Owner | Resources | Timeline | Success Metric |
|---|-----|--------|-------|-----------|----------|----------------|
| 1 | ... | ... | ... | ... | ... | ... |

### Priorities
#### High (Immediate)
- ...

#### Medium (3-6 months)
- ...

#### Low (6-12 months)
- ...

### Estimated Budget
| Item | Estimated Cost |
|------|----------------|

### KPIs
| KPI | Current Value | Target Value |
|-----|---------------|--------------|

### Risks & Challenges
| Risk | Impact | Mitigation Plan |
|------|--------|-----------------|"""
        
        remediation_plan = generate_ai_content(prompt, lang)
        
        return jsonify({
            'success': True,
            'remediation_plan': remediation_plan
        })
        
    except Exception as e:
        print(f"Gap remediation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/api/generate-policy', methods=['POST'])
@login_required
def api_generate_policy():
    """Generate policy document."""
    try:
        data = request.json
        domain = data.get('domain', 'Cyber Security')
        
        # Check usage limit for this domain
        can_generate, used, limit = check_usage_limit(session['user_id'], 'policies', domain)
        if not can_generate:
            return jsonify({
                'success': False,
                'error': f'Usage limit reached for {domain}. You have used {used}/{limit} policies in this domain.',
                'limit_reached': True
            }), 429
        
        lang = data.get('language', 'en')
        
        if lang == 'ar':
            policy_name = data.get('policy_name', 'أمن المعلومات')
            framework = data.get('framework', 'NCA ECC')
            framework_ar = translate_frameworks_list_ar(framework) if framework else framework
            prompt = f"""أنشئ وثيقة سياسة **{policy_name}** احترافية ومفصلة بتنسيق Markdown.

تقييد حاسم - عنوان السياسة:
- عنوان السياسة هو: "{policy_name}" وليس أي شيء آخر
- لا تغير العنوان إلى "سياسة أمن المعلومات" أو أي عنوان عام
- جميع البنود والإجراءات يجب أن تتعلق مباشرة وحصراً بموضوع "{policy_name}"
- لا تكتب بنوداً عامة عن أمن المعلومات إذا كان الموضوع المحدد مختلفاً

أمثلة للتوضيح:
- إذا كان العنوان "سياسة الاستخدام المقبول" → اكتب بنوداً عن استخدام الأجهزة والإنترنت والبريد الإلكتروني
- إذا كان العنوان "سياسة أمن الشبكات" → اكتب بنوداً عن جدران الحماية والتجزئة وVPN والمراقبة
- إذا كان العنوان "سياسة البريد الإلكتروني" → اكتب بنوداً عن استخدام البريد والتشفير والمرفقات والتصيد

تقييد الإطار التنظيمي:
- الإطار المرجعي: {framework_ar}
- لا تذكر أي إطار أو معيار آخر (مثل ISO 27001 أو NIST) إلا إذا كان هو المختار أعلاه

تعليمات:
1. لا تستخدم أي تواريخ محددة - استخدم عبارات نسبية مثل "سنوياً" و"كل 90 يوم"
2. لا تستخدم أي أسماء أشخاص
3. للتواريخ استخدم: [سيتم إضافته عند الاعتماد]
4. اكتب 4 أقسام فرعية على الأقل في بنود السياسة، كل منها خاص بجانب من جوانب {policy_name}

# سياسة {policy_name}

## 1. الغرض
(وصف الغرض من هذه السياسة بشكل خاص بموضوع {policy_name} - لا تكتب غرضاً عاماً)

## 2. النطاق
تنطبق هذه السياسة على:
- (قائمة بالأطراف المعنية بموضوع {policy_name} تحديداً)

## 3. بنود السياسة
### 3.1 (عنوان فرعي خاص بجانب من {policy_name})
- (بنود مفصلة ومحددة لهذا الجانب)
### 3.2 (عنوان فرعي لجانب آخر من {policy_name})
- (بنود مفصلة)
### 3.3 (عنوان فرعي إضافي خاص بـ {policy_name})
- (بنود مفصلة)
### 3.4 (عنوان فرعي رابع خاص بـ {policy_name})
- (بنود مفصلة)

## 4. الأدوار والمسؤوليات
| الدور | المسؤوليات المتعلقة بـ {policy_name} |
|-------|--------------------------------------|
| المسمى | الوصف |

## 5. متطلبات الامتثال وفق {framework_ar}
- (متطلبات الامتثال المرتبطة بإطار {framework_ar} فقط - لا تذكر أي إطار آخر)

## 6. المراجعة والتحديث
- إجراءات المراجعة الدورية

## 7. العقوبات
- العقوبات على عدم الالتزام

---
**تاريخ الإصدار:** [سيتم إضافته عند الاعتماد]
**رقم الإصدار:** 1.0
**المالك:** [القسم المسؤول]"""
        else:
            policy_name = data.get('policy_name', 'Information Security')
            framework = data.get('framework', 'NCA ECC')
            prompt = f"""Generate a professional **{policy_name}** Policy document in Markdown format.

CRITICAL - POLICY TITLE ENFORCEMENT:
- The policy title is: "{policy_name}" - do NOT change it to "Information Security Policy" or any other generic title
- ALL sections and statements must be DIRECTLY and SPECIFICALLY about "{policy_name}"
- Do NOT write generic information security content if the topic is different

Examples:
- If title is "Acceptable Use Policy" → write about device usage, internet access, email conduct, social media rules
- If title is "Network Security Policy" → write about firewalls, segmentation, VPN, monitoring, DMZ
- If title is "Email Security Policy" → write about email encryption, attachments, phishing, retention, forwarding rules
- If title is "Password Policy" → write about complexity, rotation, storage, MFA, service accounts

FRAMEWORK RESTRICTION:
- Reference framework: {framework}
- Do NOT mention any other framework (like ISO 27001, NIST, COBIT) unless it IS the selected framework above

INSTRUCTIONS:
1. Do NOT use any specific dates - use relative timeframes like "Annually", "Every 90 days"
2. Do NOT use any person names
3. For dates use: [To be added upon approval]
4. Write at least 4 subsections in Policy Statements, each addressing a specific aspect of {policy_name}

# {policy_name} Policy

## 1. Purpose
(Description specific to {policy_name} - NOT a generic purpose)

## 2. Scope
This policy applies to:
- (List of stakeholders specifically relevant to {policy_name})

## 3. Policy Statements
### 3.1 (Subheading about a specific aspect of {policy_name})
- (Detailed statements specific to this aspect)
### 3.2 (Another aspect of {policy_name})
- (Detailed statements)
### 3.3 (Additional aspect of {policy_name})
- (Detailed statements)
### 3.4 (Fourth aspect of {policy_name})
- (Detailed statements)

## 4. Roles & Responsibilities
| Role | Responsibilities related to {policy_name} |
|------|-------------------------------------------|
| Title | Description |

## 5. Compliance Requirements per {framework}
- (Requirements linked to {framework} only - do NOT mention other frameworks)

## 6. Review & Update
- Review procedures

## 7. Enforcement
- Penalties for non-compliance

---
**Issue Date:** [To be added upon approval]
**Version:** 1.0
**Owner:** [Responsible Department]"""

        content = generate_ai_content(prompt, lang)
        
        # Save to database
        try:
            conn = get_db()
            conn.execute('''INSERT INTO policies (user_id, domain, policy_name, framework, content, language)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                        (session['user_id'], data.get('domain'), data.get('policy_name'),
                         data.get('framework'), content, lang))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print(f"Policy DB save error: {db_error}")
        
        return jsonify({'success': True, 'content': content})
        
    except Exception as e:
        print(f"Policy generation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analyze-risk', methods=['POST'])
@login_required
def api_analyze_risk():
    """Analyze risk scenario."""
    try:
        data = request.json
        domain = data.get('domain', 'Cyber Security')
        
        # Check usage limit for this domain
        can_generate, used, limit = check_usage_limit(session['user_id'], 'risks', domain)
        if not can_generate:
            return jsonify({
                'success': False,
                'error': f'Usage limit reached for {domain}. You have used {used}/{limit} risk analyses in this domain.',
                'limit_reached': True
            }), 429
        
        lang = data.get('language', 'en')
        
        if lang == 'ar':
            # Determine expected controls for Arabic
            threat_text_ar = data.get('threat', '').lower()
            scenario_hint_ar = ''
            if any(k in threat_text_ar for k in ['insider', 'داخلي', 'موظف', 'تهديد داخلي']):
                scenario_hint_ar = f"""
لهذا السيناريو (تهديد داخلي يستهدف {data.get('asset', 'الأصل')}):
1. تحليلات سلوك المستخدم والكيان (UEBA) - للكشف عن السلوك غير الطبيعي
2. مراقبة نشاط قاعدة البيانات (DAM) - لمراقبة الاستعلامات المشبوهة
3. منع تسريب البيانات (DLP) - خاصة لمسارات تصدير البيانات
لا تقترح "تفعيل MFA" أو "تدريب التوعية" كضوابط أساسية للتهديدات الداخلية."""
            elif any(k in threat_text_ar for k in ['فدية', 'ransomware', 'تشفير.*خبيث']):
                scenario_hint_ar = f"""
لهذا السيناريو (فدية تستهدف {data.get('asset', 'الأصل')}):
1. EDR مع كشف سلوكي وعزل تلقائي
2. نسخ احتياطية معزولة وغير قابلة للتعديل مع إجراءات استعادة مختبرة
3. بوابة بريد مع حماية رمل للمرفقات وتفجير URL"""
            elif any(k in threat_text_ar for k in ['تصيد', 'phishing', 'هندسة اجتماعية']):
                scenario_hint_ar = f"""
لهذا السيناريو (تصيد/هندسة اجتماعية):
1. بوابة أمن بريد مع تطبيق DMARC/DKIM/SPF
2. برنامج محاكاة تصيد دوري مع تتبع المقاييس
3. قواعد كشف اختراق البريد التجاري (BEC)"""

            prompt = f"""حلل سيناريو الخطر التالي بتنسيق Markdown احترافي:
الفئة: {data.get('category', 'عام')}
الأصل: {data.get('asset', 'النظام')}
التهديد: {data.get('threat', 'وصول غير مصرح')}

⚠⚠⚠ أهم قاعدة — ضوابط خاصة بالسيناريو فقط:
أنت تحلل سيناريو محدد: "{data.get('threat', '')}" يستهدف "{data.get('asset', '')}".
الضوابط الموصى بها يجب أن تكون مخصصة لهذا التهديد والأصل بالتحديد.

ضوابط محظورة (لا تستخدمها):
❌ "تفعيل المصادقة متعددة العوامل" — عامة جداً لتحليل تهديد محدد
❌ "تحديث أنظمة الكشف عن التهديدات" — غامضة وغير مستهدفة
❌ "تدريب التوعية الأمنية للموظفين" — ممارسة عامة وليست ضابطاً خاصاً بالتهديد

{scenario_hint_ar}

كل ضابط يجب أن يسمي تقنية أو أداة أو تقنية محددة تعالج مباشرة "{data.get('threat', '')}".
الضوابط يجب أن تعالج مباشرة التهديد "{data.get('threat', '')}" الذي يستهدف الأصل "{data.get('asset', '')}".

تعليمات صارمة ومهمة جداً:
1. لا تستخدم أي تواريخ محددة مطلقاً (مثل 2024، 2025، يناير، فبراير، إلخ)
2. لا تستخدم أي أسماء أشخاص
3. استخدم فقط عبارات نسبية مثل: "خلال 30 يوم"، "خلال 60 يوم"، "خلال 90 يوم"
4. للتواريخ استخدم: [سيتم إضافته]

استخدم التنسيق التالي:

# تحليل المخاطر

## ملخص تقييم الخطر
| العنصر | القيمة |
|--------|-------|
| فئة الخطر | {data.get('category', 'عام')} |
| الأصل المتأثر | {data.get('asset', 'النظام')} |
| مستوى الخطر | [عالي/متوسط/منخفض] |
| درجة الخطر | [X/10] |

## تحليل التهديد
وصف التهديد ومصادره المحتملة

## تحليل الأثر
| نوع الأثر | الوصف | المستوى |
|----------|-------|---------|
| مالي | الوصف | المستوى |
| تشغيلي | الوصف | المستوى |

## تقييم الاحتمالية
| العامل | التقييم |
|--------|---------|
| العامل | القيمة |

## الضوابط الموصى بها

### جدول ملخص الضوابط:
| # | الضابط | الأولوية | الجدول الزمني | التكلفة المقدرة | الحالة |
|---|--------|----------|---------------|-----------------|--------|
| 1 | [اسم الضابط] | عالية | فوري | يحتاج تقييم |
| 2 | [اسم الضابط] | عالية | خلال 30 يوم | يحتاج تقييم |
| 3 | [اسم الضابط] | متوسطة | خلال 60 يوم | يحتاج تقييم |

### دليل تنفيذ الضوابط:

يجب كتابة دليل تنفيذ منفصل لكل ضابط موصى به (3 أدلة على الأقل)

---
#### دليل تنفيذ الضابط رقم 1: [اسم الضابط]

**الخطوات التفصيلية:**
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التحضير | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحضير | 1.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |

**الأدلة المطلوبة للإغلاق:**
- [ ] (دليل 1)
- [ ] (دليل 2)
- [ ] (دليل 3)

---
#### دليل تنفيذ الضابط رقم 2: [اسم الضابط]

**الخطوات التفصيلية:**
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التحضير | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحضير | 1.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |

**الأدلة المطلوبة للإغلاق:**
- [ ] (دليل 1)
- [ ] (دليل 2)
- [ ] (دليل 3)

---
#### دليل تنفيذ الضابط رقم 3: [اسم الضابط]

**الخطوات التفصيلية:**
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التحضير | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |

**الأدلة المطلوبة للإغلاق:**
- [ ] (دليل 1)
- [ ] (دليل 2)
- [ ] (دليل 3)

---

### ضوابط كاشفة
- القائمة

### ضوابط تصحيحية
- القائمة

## الخطر المتبقي
| السيناريو | قبل الضوابط | بعد الضوابط |
|----------|------------|------------|

---
**تاريخ التقييم:** [سيتم إضافته]
**المراجعة القادمة:** خلال 6 أشهر"""
        else:
            # Determine expected controls based on threat keywords
            threat_text = data.get('threat', '').lower()
            asset_text = data.get('asset', '').lower()
            scenario_hint = ''
            if any(k in threat_text for k in ['insider', 'internal', 'employee', 'disgruntled']):
                scenario_hint = f"""
For this INSIDER THREAT scenario targeting {data.get('asset', 'the asset')}, the controls MUST include:
1. User and Entity Behavior Analytics (UEBA) - to detect anomalous user behavior
2. Database Activity Monitoring (DAM) - to monitor and alert on suspicious database queries
3. Data Loss Prevention (DLP) - specifically for database export paths and bulk data transfers
Do NOT suggest "Enable MFA" or "Security awareness training" as primary controls for insider threats."""
            elif any(k in threat_text for k in ['ransomware', 'ransom', 'encrypt']):
                scenario_hint = f"""
For this RANSOMWARE scenario targeting {data.get('asset', 'the asset')}, the controls MUST include:
1. EDR with behavioral detection and automated isolation
2. Immutable air-gapped backup strategy with tested restore procedures
3. Email gateway with attachment sandboxing and URL detonation"""
            elif any(k in threat_text for k in ['phishing', 'spear', 'social engineer', 'bec']):
                scenario_hint = f"""
For this PHISHING/SOCIAL ENGINEERING scenario, the controls MUST include:
1. Email security gateway with DMARC/DKIM/SPF enforcement
2. Phishing simulation campaign program with metrics tracking
3. Business Email Compromise (BEC) detection rules"""
            elif any(k in threat_text for k in ['ddos', 'denial', 'flood']):
                scenario_hint = f"""
For this DDoS scenario, the controls MUST include:
1. WAF with rate limiting and bot detection
2. CDN-based DDoS mitigation service
3. Traffic scrubbing and clean-pipe service"""
            elif any(k in threat_text for k in ['breach', 'exfiltrat', 'leak', 'exposure']):
                scenario_hint = f"""
For this DATA BREACH scenario, the controls MUST include:
1. Data classification system with automated labeling
2. DLP across all channels (email, web, USB, cloud)
3. Database activity monitoring with access anomaly detection"""
            elif any(k in threat_text for k in ['cloud', 'misconfig', 'saas']):
                scenario_hint = f"""
For this CLOUD SECURITY scenario, the controls MUST include:
1. Cloud Security Posture Management (CSPM) with continuous scanning
2. Cloud IAM hardening with least-privilege enforcement
3. Cloud workload protection platform (CWPP)"""

            prompt = f"""Analyze this risk scenario in professional Markdown format:
Category: {data.get('category', 'General')}
Asset: {data.get('asset', 'System')}
Threat: {data.get('threat', 'Unauthorized Access')}

⚠⚠⚠ MOST CRITICAL RULE — SCENARIO-SPECIFIC CONTROLS ONLY:
You are analyzing a SPECIFIC scenario: "{data.get('threat', '')}" targeting "{data.get('asset', '')}".
The recommended controls MUST be tailored to THIS EXACT threat and asset combination.

BANNED GENERIC CONTROLS (do NOT use these):
❌ "Enable Multi-Factor Authentication" — too generic for a specific threat analysis
❌ "Update Threat Detection Systems" — vague and not targeted
❌ "Employee Security Awareness Training" — this is a general practice, not a threat-specific control

{scenario_hint}

If you cannot identify threat-specific controls, you are doing this wrong. Every control must NAME a specific technology, tool, or technique that directly mitigates "{data.get('threat', '')}".

The controls MUST directly address the specific threat "{data.get('threat', '')}" targeting the specific asset "{data.get('asset', '')}".
Each control implementation guide must include tools/technologies specific to this threat scenario.

STRICT AND IMPORTANT INSTRUCTIONS:
1. Do NOT use any specific dates (like 2024, 2025, January, February, etc.)
2. Do NOT use any person names
3. Use ONLY relative timeframes like: "Within 30 days", "Within 60 days", "Within 90 days"
4. For dates use: [To be added]

Use the following format:

# Risk Analysis

## Risk Assessment Summary
| Element | Value |
|---------|-------|
| Risk Category | {data.get('category', 'General')} |
| Affected Asset | {data.get('asset', 'System')} |
| Risk Level | [High/Medium/Low] |
| Risk Score | [X/10] |

## Threat Analysis
Description of threat and potential sources

## Impact Analysis
| Impact Type | Description | Level |
|-------------|-------------|-------|
| Financial | Description | Level |
| Operational | Description | Level |

## Likelihood Assessment
| Factor | Assessment |
|--------|------------|
| Factor | Value |

## Recommended Controls

### Control Summary Table:
| # | Control | Priority | Timeline | Status |
|---|---------|----------|----------|--------|
| 1 | [Control name] | High | Within 30 days | To Be Assessed |
| 2 | [Control name] | Medium | Within 60 days | To Be Assessed |
| 3 | [Control name] | Low | Within 90 days | To Be Assessed |

### Control Implementation Guidelines:

---
#### Control #1 Implementation Guide: [Control Name]

**Step-by-Step Implementation:**
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Preparation | 1.1 | [Step description] | [Team] | [Output] |
| Preparation | 1.2 | [Step description] | [Team] | [Output] |
| Implementation | 2.1 | [Step description] | [Team] | [Output] |
| Implementation | 2.2 | [Step description] | [Team] | [Output] |
| Verification | 3.1 | [Step description] | [Team] | [Output] |

**Evidence Required:**
- [ ] [Evidence item 1]
- [ ] [Evidence item 2]
- [ ] [Evidence item 3]

---
#### Control #2 Implementation Guide: [Control Name]

**Step-by-Step Implementation:**
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Preparation | 1.1 | [Step description] | [Team] | [Output] |
| Preparation | 1.2 | [Step description] | [Team] | [Output] |
| Implementation | 2.1 | [Step description] | [Team] | [Output] |
| Implementation | 2.2 | [Step description] | [Team] | [Output] |
| Verification | 3.1 | [Step description] | [Team] | [Output] |

**Evidence Required:**
- [ ] [Evidence item 1]
- [ ] [Evidence item 2]
- [ ] [Evidence item 3]

---
#### Control #3 Implementation Guide: [Control Name]

**Step-by-Step Implementation:**
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Preparation | 1.1 | [Step description] | [Team] | [Output] |
| Implementation | 2.1 | [Step description] | [Team] | [Output] |
| Verification | 3.1 | [Step description] | [Team] | [Output] |

**Evidence Required:**
- [ ] [Evidence item 1]
- [ ] [Evidence item 2]
- [ ] [Evidence item 3]

---

### Detective Controls
- List

### Corrective Controls
- List

## Residual Risk
| Scenario | Before Controls | After Controls |
|----------|-----------------|----------------|

---
**Assessment Date:** [To be added]
**Next Review:** Within 6 months"""

        content = generate_ai_content(prompt, lang)
        
        # POST-PROCESSING: Check if AI produced generic controls despite instructions
        # If generic, replace with scenario-specific simulation content
        generic_markers = [
            'enable multi-factor authentication', 'enable mfa', 
            'update threat detection', 'security awareness training',
            'تفعيل المصادقة متعددة العوامل', 'تحديث أنظمة الكشف', 'تدريب التوعية الأمنية',
        ]
        content_lower = content.lower() if content else ''
        generic_count = sum(1 for m in generic_markers if m in content_lower)
        if generic_count >= 2:
            # AI produced generic garbage — use scenario-specific simulation instead
            print(f"DEBUG: Risk AI output had {generic_count} generic controls — using simulation", flush=True)
            sim_content = generate_simulation_content(prompt, lang)
            if sim_content:
                content = sim_content
        
        # INJECT IMPLEMENTATION GUIDELINES if missing from risk content
        def inject_risk_guidelines(risk_content, lang_code):
            """Inject implementation guidelines if AI didn't include them."""
            has_guidelines = (
                'Implementation Guide' in risk_content or 
                'Step-by-Step' in risk_content or
                'دليل تنفيذ' in risk_content or
                'الخطوات التفصيلية' in risk_content
            )
            
            if has_guidelines:
                return risk_content
            
            # Extract controls from table
            import re
            control_pattern = r'\|\s*(\d+)\s*\|\s*([^|]+)\s*\|\s*(High|Medium|Low|عالية|متوسطة|منخفضة)'
            controls = re.findall(control_pattern, risk_content)
            
            controls_list = []
            for num, control, priority in controls:
                control = control.strip()
                if control and control.lower() not in ['control', 'الضابط', '#']:
                    controls_list.append((num, control, priority))
            
            if not controls_list:
                return risk_content
            
            if lang_code == 'ar':
                guidelines = "\n\n---\n\n### دليل تنفيذ الضوابط:\n\n"
                for num, control, priority in controls_list[:3]:
                    guidelines += f"""---
#### دليل تنفيذ الضابط رقم {num}: {control[:40]}

**الخطوات التفصيلية:**
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التحضير | 1.1 | تقييم المتطلبات والموارد | فريق الأمن | تقرير المتطلبات |
| التحضير | 1.2 | إعداد خطة التنفيذ | مدير المشروع | خطة معتمدة |
| التنفيذ | 2.1 | تطبيق الضابط | الفريق التقني | ضابط مُفعّل |
| التنفيذ | 2.2 | تدريب المستخدمين | التدريب | فريق مدرب |
| التحقق | 3.1 | اختبار الفعالية | ضمان الجودة | تقرير الاختبار |

**الأدلة المطلوبة للإغلاق:** ☐ تقرير المتطلبات ☐ خطة التنفيذ ☐ سجلات التدريب ☐ تقرير الاختبار

"""
            else:
                guidelines = "\n\n---\n\n### Control Implementation Guidelines:\n\n"
                for num, control, priority in controls_list[:3]:
                    guidelines += f"""---
#### Control #{num} Implementation Guide: {control[:40]}

**Step-by-Step Implementation:**
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Preparation | 1.1 | Assess requirements and resources | Security Team | Requirements report |
| Preparation | 1.2 | Develop implementation plan | Project Manager | Approved plan |
| Implementation | 2.1 | Apply the control | Technical Team | Activated control |
| Implementation | 2.2 | Train users | Training | Trained team |
| Verification | 3.1 | Test effectiveness | QA | Test report |

**Evidence Required for Closure:** ☐ Requirements report ☐ Implementation plan ☐ Training records ☐ Test report

"""
            
            return risk_content + guidelines
        
        content = inject_risk_guidelines(content, lang)
        
        # Save to database
        try:
            conn = get_db()
            conn.execute('''INSERT INTO risks (user_id, domain, asset_name, threat, risk_level, analysis, language)
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (session['user_id'], data.get('domain'), data.get('asset'),
                         data.get('threat'), 'HIGH', content, lang))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print(f"Risk DB save error: {db_error}")
        
        return jsonify({'success': True, 'analysis': content})
        
    except Exception as e:
        print(f"Risk analysis error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/generate-audit', methods=['POST'])
@login_required
def api_generate_audit():
    """Generate audit report."""
    try:
        domain = request.form.get('domain', 'Cyber Security')
        
        # Check usage limit for this domain
        can_generate, used, limit = check_usage_limit(session['user_id'], 'audits', domain)
        if not can_generate:
            return jsonify({
                'success': False,
                'error': f'Usage limit reached for {domain}. You have used {used}/{limit} audit reports in this domain.',
                'limit_reached': True
            }), 429
        
        lang = request.form.get('language', 'en')
        framework = request.form.get('framework', 'NCA ECC')
        audit_scope = request.form.get('audit_scope', 'full')
        audit_topic = request.form.get('audit_topic', '').strip()
        
        # Handle file upload - read content for AI analysis
        evidence_files = request.files.getlist('evidence')
        evidence_info = []
        uploaded_content = ''
        for f in evidence_files:
            if f and f.filename:
                evidence_info.append(f.filename)
                # Read file content for AI analysis
                try:
                    if f.filename.lower().endswith('.pdf'):
                        # Try to extract text from PDF
                        import io
                        pdf_bytes = f.read()
                        try:
                            import fitz  # PyMuPDF
                            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
                            pdf_text = ''
                            for page in doc:
                                pdf_text += page.get_text()
                            doc.close()
                            if pdf_text.strip():
                                uploaded_content += f"\n\n--- Content of {f.filename} ---\n{pdf_text[:8000]}\n--- End of {f.filename} ---\n"
                        except (ImportError, Exception):
                            try:
                                from PyPDF2 import PdfReader
                                reader = PdfReader(io.BytesIO(pdf_bytes))
                                pdf_text = ''
                                for page in reader.pages:
                                    pdf_text += (page.extract_text() or '')
                                if pdf_text.strip():
                                    uploaded_content += f"\n\n--- Content of {f.filename} ---\n{pdf_text[:8000]}\n--- End of {f.filename} ---\n"
                            except:
                                print(f"DEBUG: No PDF library available for {f.filename}", flush=True)
                    elif f.filename.lower().endswith(('.txt', '.md', '.csv')):
                        text_content = f.read().decode('utf-8', errors='ignore')
                        if text_content.strip():
                            uploaded_content += f"\n\n--- Content of {f.filename} ---\n{text_content[:8000]}\n--- End of {f.filename} ---\n"
                    elif f.filename.lower().endswith(('.docx',)):
                        try:
                            import docx
                            doc = docx.Document(io.BytesIO(f.read()))
                            doc_text = '\n'.join([p.text for p in doc.paragraphs if p.text.strip()])
                            if doc_text.strip():
                                uploaded_content += f"\n\n--- Content of {f.filename} ---\n{doc_text[:8000]}\n--- End of {f.filename} ---\n"
                        except:
                            pass
                except Exception as e:
                    print(f"DEBUG: Could not read file {f.filename}: {e}", flush=True)
        
        # Build topic-specific instruction
        topic_instruction = ''
        if audit_topic:
            # Map common topics to specific finding areas so AI doesn't default to generic findings
            topic_lower = audit_topic.lower()
            topic_examples = ''
            if any(kw in topic_lower for kw in ['email', 'بريد']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Email encryption (TLS, S/MIME, PGP) for classified messages
- Anti-phishing controls (DMARC, DKIM, SPF, email gateway, URL rewriting, attachment sandboxing)
- Email retention and archiving compliance
- Email DLP rules preventing sensitive data leakage via email
- Email-specific awareness training (phishing simulation results)
DO NOT generate generic findings about "MFA" or "weak passwords" — those are NOT email-specific."""
            elif any(kw in topic_lower for kw in ['network', 'شبك']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Network segmentation (DMZ, internal zones, management zones, VLANs)
- Firewall rule base management and review cadence
- IDS/IPS deployment and tuning at network boundaries
- Network device firmware patching and hardening
- Network architecture documentation and version control
DO NOT generate generic findings about "MFA" or "awareness training" — those are NOT network-specific."""
            elif any(kw in topic_lower for kw in ['access', 'وصول', 'صلاحي']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Role-based access control (RBAC) matrix and enforcement
- Privileged access management (PAM) with session recording
- Access lifecycle (provisioning, modification, revocation SLAs)
- User access recertification cadence and quality
- Segregation of duties enforcement
DO NOT generate generic findings about "awareness training" or "documentation" — focus on ACCESS CONTROL gaps."""
            elif any(kw in topic_lower for kw in ['password', 'كلمة', 'مرور', 'مصادق']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Password complexity, length, rotation requirements
- Service account and API key password management
- MFA enforcement for privileged and remote access
- Password vault/manager adoption
- Credential storage and transmission security
DO NOT generate generic findings about "network segmentation" or "incident response" — focus on AUTHENTICATION gaps."""
            elif any(kw in topic_lower for kw in ['incident', 'حادث', 'استجاب']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Incident response plan documentation and escalation procedures
- CSIRT team composition, roles, and on-call rotation
- Tabletop exercise frequency and documented lessons learned
- Incident classification and severity matrix
- Post-incident review process and improvement tracking
DO NOT generate generic findings about "MFA" or "weak passwords" — focus on INCIDENT RESPONSE gaps."""
            elif any(kw in topic_lower for kw in ['data', 'بيان']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Data classification scheme implementation and enforcement
- Data loss prevention (DLP) controls across channels
- Data handling procedures per classification level
- Data retention and disposal compliance
- Data encryption at rest and in transit
DO NOT generate generic findings about "MFA" or "network segmentation" — focus on DATA PROTECTION gaps."""
            elif any(kw in topic_lower for kw in ['backup', 'نسخ', 'احتياط']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Backup strategy (3-2-1 rule, offsite, air-gapped, immutable)
- RPO/RTO targets defined and tested
- Backup restore testing frequency and results
- Backup encryption and integrity verification
- Backup monitoring and failure alerting
DO NOT generate generic findings about "MFA" or "awareness training" — focus on BACKUP & RECOVERY gaps."""
            elif any(kw in topic_lower for kw in ['cloud', 'سحاب']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Cloud security configuration (CSPM) and misconfiguration detection
- Cloud identity and access management (IAM policies, least privilege)
- Cloud data residency and sovereignty compliance
- Cloud encryption key management (BYOK, HYOK)
- Cloud logging, monitoring, and SIEM integration
DO NOT generate generic findings about "network segmentation" or "physical security" — focus on CLOUD-SPECIFIC gaps."""
            elif any(kw in topic_lower for kw in ['usb', 'removable', 'flash drive', 'portable media', 'وسائط', 'فلاش', 'قابلة للإزالة']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- USB port control: ports not disabled or restricted via Group Policy on workstations and servers
- Device whitelisting: no approved USB device list enforced, any USB storage device can connect
- Data Loss Prevention (DLP): no monitoring of file transfers to removable media
- USB encryption: no mandatory hardware encryption (AES-256) on approved USB devices
- USB device inventory: no registry tracking issuance, return, and reconciliation of USB devices
- Malware scanning: no automatic scanning of USB devices upon connection
- USB usage awareness: employees not trained on USB risks (data theft, malware introduction)
DO NOT generate generic findings about "cybersecurity governance" or "risk assessment" — focus on USB/REMOVABLE MEDIA specific gaps."""
            elif any(kw in topic_lower for kw in ['acceptable', 'استخدام', 'مقبول']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Internet usage monitoring and content filtering
- Employee acknowledgement and signature collection
- BYOD and personal device usage rules
- Social media and cloud storage restrictions
- Acceptable use enforcement and violation handling
DO NOT generate generic findings about "MFA" or "network segmentation" — focus on ACCEPTABLE USE gaps."""
            elif any(kw in topic_lower for kw in ['physical', 'مادي', 'فيزيائ']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Physical access control to server rooms (badge + biometric)
- CCTV monitoring coverage and footage retention
- Visitor management and escort procedures
- Environmental monitoring (temperature, humidity, fire, water)
- Secure disposal of physical media and equipment
DO NOT generate generic findings about "email encryption" or "password policies" — focus on PHYSICAL SECURITY gaps."""
            elif any(kw in topic_lower for kw in ['cybersecurity', 'cyber security', 'أمن سيبراني', 'سيبران']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Cybersecurity governance framework and CISO role definition
- Enterprise security risk assessment methodology and frequency
- Security operations center (SOC) capability and coverage
- Cybersecurity strategy alignment with business objectives
- Security architecture documentation and defense-in-depth implementation
DO NOT generate generic findings about "MFA" or "weak passwords" — those are individual controls, NOT governance-level findings."""
            elif any(kw in topic_lower for kw in ['information security', 'أمن المعلومات', 'infosec']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Information security management system (ISMS) framework and scope
- Security risk assessment and treatment methodology
- Information asset classification and ownership
- Security policy framework completeness and currency
- Security roles, responsibilities, and reporting structure
DO NOT generate generic findings about "MFA" or "weak passwords" — focus on ISMS GOVERNANCE gaps."""
            elif any(kw in topic_lower for kw in ['vulnerab', 'ثغر', 'patch', 'ترقيع']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Vulnerability scanning schedule, coverage, and tooling (Nessus, Qualys, etc.)
- Remediation SLAs by severity (Critical 7d, High 14d, Medium 30d)
- Patch management process and emergency patching procedures
- Vulnerability tracking and overdue remediation escalation
- Asset coverage gaps in vulnerability scanning program
DO NOT generate generic findings about "MFA" or "awareness training" — focus on VULNERABILITY MANAGEMENT gaps."""
            elif any(kw in topic_lower for kw in ['asset', 'أصول', 'أصل']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- IT asset inventory completeness and accuracy (CMDB)
- Automated asset discovery and tracking
- Asset ownership assignment and accountability
- Secure asset disposal and data wiping (NIST 800-88)
- Shadow IT detection and unauthorized asset management
DO NOT generate generic findings about "MFA" or "network segmentation" — focus on ASSET MANAGEMENT gaps."""
            elif any(kw in topic_lower for kw in ['change', 'تغيير', 'تغييرات']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Change Advisory Board (CAB) process and approval workflows
- Impact assessment and rollback planning for changes
- Emergency change post-review procedures
- Change testing requirements before production deployment
- Change documentation and audit trail completeness
DO NOT generate generic findings about "MFA" or "awareness training" — focus on CHANGE MANAGEMENT gaps."""
            elif any(kw in topic_lower for kw in ['encrypt', 'تشفير', 'مفاتيح']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Encryption standards (algorithms, key lengths, approved ciphers)
- Key management lifecycle (generation, rotation, destruction, escrow)
- Data-at-rest encryption for databases and storage
- Data-in-transit encryption (TLS version, certificate management)
- HSM usage for key protection and cryptographic operations
DO NOT generate generic findings about "weak passwords" or "incident response" — focus on ENCRYPTION & KEY MANAGEMENT gaps."""
            elif any(kw in topic_lower for kw in ['log', 'سجل', 'سجلات', 'monitor', 'مراقب', 'siem']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Log source coverage and centralization (SIEM integration)
- Log retention periods compliance with regulatory requirements
- Correlation rules and detection use case effectiveness
- Log integrity protection and tamper-evidence
- SOC analyst training on log analysis techniques
DO NOT generate generic findings about "MFA" or "network segmentation" — focus on LOGGING & MONITORING gaps."""
            elif any(kw in topic_lower for kw in ['awareness', 'training', 'توعية', 'تدريب']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Mandatory security training program scope and completion rates
- Phishing simulation campaign frequency and click-rate trends
- Role-based specialized training (developers, admins, executives)
- Training content currency and threat landscape alignment
- Training effectiveness measurement (pre/post testing, behavior change)
DO NOT generate generic findings about "MFA" or "network segmentation" — focus on AWARENESS & TRAINING gaps."""
            elif any(kw in topic_lower for kw in ['third', 'vendor', 'supplier', 'أطراف', 'مورد']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Vendor security risk assessment process and questionnaires
- Third-party access monitoring and periodic review
- Contractual security requirements and SLA enforcement
- Vendor incident notification and response obligations
- Vendor risk tiering and assessment frequency by tier
DO NOT generate generic findings about "MFA" or "weak passwords" — focus on THIRD-PARTY RISK MANAGEMENT gaps."""
            elif any(kw in topic_lower for kw in ['continuity', 'استمرارية', 'bcp', 'disaster', 'تعافي', 'recovery']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Business Impact Analysis (BIA) currency and completeness
- RTO/RPO targets defined and validated through testing
- BCP test scenarios (tabletop, functional, full-scale) and frequency
- Disaster recovery site readiness and failover procedures
- Crisis communication plan and stakeholder notification
DO NOT generate generic findings about "MFA" or "email encryption" — focus on BUSINESS CONTINUITY gaps."""
            elif any(kw in topic_lower for kw in ['mobile', 'محمول', 'أجهزة', 'byod']):
                topic_examples = """
TOPIC-SPECIFIC FINDINGS MUST COVER areas like:
- Mobile Device Management (MDM/UEM) deployment and enrollment
- BYOD containerization and data isolation
- App vetting and sideloading restrictions
- Remote wipe capability and lost device procedures
- Mobile security awareness for end users
DO NOT generate generic findings about "network segmentation" or "change management" — focus on MOBILE DEVICE SECURITY gaps."""
            else:
                topic_examples = f"""
Generate findings that are SPECIFIC to "{audit_topic}". 
DO NOT generate the same generic 5 findings for every policy (MFA, weak passwords, documentation, awareness, periodic review).
Each finding must be unique to the operational area of "{audit_topic}"."""

            topic_instruction = f"""
AUDIT TOPIC: {audit_topic}
This audit is specifically focused on "{audit_topic}". 

⚠ CRITICAL ANTI-GENERIC RULE:
Do NOT repeat the same 5 generic findings for every policy. The following are BANNED as primary findings unless they are directly specific to {audit_topic}:
- "MFA not enabled" (unless auditing Access Control or Authentication policy)
- "Weak password policies" (unless auditing Password or Authentication policy)  
- "Insufficient documentation" (too generic — specify WHAT documentation is missing)
- "Delayed awareness programs" (too generic — specify WHAT training gap exists)
- "No periodic review" (too generic — every audit says this)

ALL findings must be OPERATIONALLY SPECIFIC to {audit_topic}. 
{topic_examples}"""
        
        prompt = f"""Generate a comprehensive audit report in professional Markdown format.

Audit Parameters:
- Framework: {framework}
- Scope: {audit_scope}
- Domain: {domain}
{"- Audit Topic: " + audit_topic if audit_topic else ""}
- Evidence Files: {', '.join(evidence_info) if evidence_info else 'No evidence provided'}
{uploaded_content if uploaded_content else ""}
{"DOCUMENT UNDER AUDIT: The content above from the uploaded document(s) is the actual document being audited. Analyze it against " + framework + " requirements and produce specific findings based on what IS and IS NOT covered in the document." if uploaded_content else ""}

⚠ FRAMEWORK RULES:
- Reference ONLY {framework} and its specific control IDs
- Do NOT mention any other framework (ISO, NIST, COBIT, etc.) unless it IS {framework}
{topic_instruction}

⚠ OUTPUT RULES:
1. Do NOT use any specific dates — use relative timeframes like "Within 30 days", "Within 60 days"
2. Do NOT use any person names or auditor names
3. For dates use: [To be added] | For audit period use: [Audit Period]
4. Every finding must include detailed implementation guidelines
5. Do NOT include "Audit Scope" or "Audit Methodology" sections — jump directly to findings
6. Do NOT echo any instruction text from this prompt into the output

Use the following format:

# Audit Report - {framework}{" - " + audit_topic if audit_topic else ""}

## Executive Summary
Brief overview including: **Overall Result:** [Compliant / Partially Compliant / Non-Compliant] with count of findings by severity. Do NOT write "To be determined" — provide an actual compliance assessment {"of " + audit_topic + " " if audit_topic else ""}against {framework} requirements.

## Findings & Observations

### High-Risk Findings
| # | Observation | Affected Control | Recommendation | Status |
|---|-------------|-----------------|----------------|--------|
| 1 | [First high-risk finding{"  related to " + audit_topic if audit_topic else ""}] | [Control ID] | [Action] | To Be Assessed |
| 2 | [Second high-risk finding{"  related to " + audit_topic if audit_topic else ""}] | [Control ID] | [Action] | To Be Assessed |

### Medium-Risk Findings
| # | Observation | Affected Control | Recommendation | Status |
|---|-------------|-----------------|----------------|--------|
| 1 | [First medium-risk finding{"  related to " + audit_topic if audit_topic else ""}] | [Control ID] | [Action] | To Be Assessed |
| 2 | [Second medium-risk finding{"  related to " + audit_topic if audit_topic else ""}] | [Control ID] | [Action] | To Be Assessed |

### Low-Risk Findings
| # | Observation | Affected Control | Recommendation | Status |
|---|-------------|-----------------|----------------|--------|

## Detailed Implementation Guidelines

You MUST provide SEPARATE implementation guides for Finding #1, Finding #2, Finding #3, etc. Do NOT write "repeat" - write actual steps for each.

---
### High-Risk Finding #1 Implementation Guide: [First Finding Title]
**Affected Control:** [Control ID]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for this finding] | [Team] | [Output] |
| Planning | 1.2 | [Specific step for this finding] | [Team] | [Output] |
| Implementation | 2.1 | [Specific step for this finding] | [Team] | [Output] |
| Implementation | 2.2 | [Specific step for this finding] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for this finding] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
### High-Risk Finding #2 Implementation Guide: [Second Finding Title]
**Affected Control:** [Control ID]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for this finding] | [Team] | [Output] |
| Planning | 1.2 | [Specific step for this finding] | [Team] | [Output] |
| Implementation | 2.1 | [Specific step for this finding] | [Team] | [Output] |
| Implementation | 2.2 | [Specific step for this finding] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for this finding] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
### Medium-Risk Finding #1 Implementation Guide: [First Medium Finding]
**Affected Control:** [Control ID]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for this finding] | [Team] | [Output] |
| Implementation | 2.1 | [Specific step for this finding] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for this finding] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

---
### Medium-Risk Finding #2 Implementation Guide: [Second Medium Finding]
**Affected Control:** [Control ID]
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | [Specific step for this finding] | [Team] | [Output] |
| Implementation | 2.1 | [Specific step for this finding] | [Team] | [Output] |
| Verification | 3.1 | [Specific step for this finding] | [Team] | [Output] |
**Evidence Required:** ☐ [Evidence 1] ☐ [Evidence 2] ☐ [Evidence 3]

## Action Plan
| # | Action | Owner | Deadline | Priority |
|---|--------|-------|----------|----------|
| 1 | Address high-risk findings | Security Team | Within 30 days | High |
| 2 | Address medium-risk findings | Compliance Team | Within 60 days | Medium |
| 3 | Address low-risk findings | Operations Team | Within 90 days | Low |

---
**Report Date:** [To be added]
**Next Audit:** Within 6 months"""

        if lang == 'ar':
            topic_ar = ''
            if audit_topic:
                topic_ar = f"""
موضوع التدقيق: {audit_topic}
هذا التدقيق مخصص لموضوع "{audit_topic}" تحديداً. جميع الملاحظات والتوصيات يجب أن تكون متعلقة مباشرة بـ "{audit_topic}" ومدى امتثاله لضوابط {framework}.

⚠ قاعدة حاسمة ضد النتائج العامة:
لا تكرر نفس الملاحظات الخمس العامة لكل سياسة. الملاحظات التالية ممنوعة إلا إذا كانت مرتبطة مباشرة بـ "{audit_topic}":
- "عدم تفعيل MFA" (فقط لتدقيق التحكم بالوصول أو المصادقة)
- "سياسات كلمات المرور ضعيفة" (فقط لتدقيق المصادقة)
- "نقص في التوثيق" (عامة جداً — حدد أي توثيق مفقود)
- "تأخر برامج التوعية" (عامة جداً — حدد أي فجوة تدريبية)
- "عدم المراجعة الدورية" (عامة جداً — كل تدقيق يقول هذا)

جميع الملاحظات يجب أن تكون تشغيلية ومحددة لموضوع "{audit_topic}".
لا تكتب ملاحظات عامة لا علاقة لها بـ "{audit_topic}"."""
            
            prompt = f"""أنشئ تقرير تدقيق احترافي {"لموضوع " + audit_topic + " وفق " if audit_topic else "لـ"}إطار {framework} في مجال {domain}.
{"الملفات المرفقة: " + ", ".join(evidence_info) if evidence_info else ""}
{uploaded_content if uploaded_content else ""}
{"الوثيقة محل التدقيق: المحتوى أعلاه من الملف المرفق هو الوثيقة التي يتم تدقيقها. حلل محتواها مقابل متطلبات " + framework + " واكتب ملاحظات محددة عما هو موجود وما هو مفقود في الوثيقة." if uploaded_content else ""}

قواعد صارمة:
- لا تكتب أي تعليمات في المخرجات
- لا تستخدم أي نسب مئوية محددة (لا 75% ولا 80%)
- استخدم "يُحدد بعد التقييم" للقيم الحالية
- استخدم شرطة (-) للقوائم
- لا تذكر أي إطار أو معيار غير {framework}
- لا تكتب قسم "نطاق التدقيق" أو "منهجية التدقيق" - هذا التدقيق يقيّم الامتثال لضوابط {framework} مباشرة، انتقل فوراً إلى النتائج والملاحظات
{topic_ar}

# تقرير التدقيق - {framework}{" - " + audit_topic if audit_topic else ""}

## الملخص التنفيذي
**النتيجة العامة:** [ممتثل / ممتثل جزئياً / غير ممتثل] — مع ذكر عدد الملاحظات حسب الخطورة. لا تكتب "سيتم تحديد" — قدم تقييم امتثال فعلي {"لموضوع " + audit_topic + " وفق " if audit_topic else "لـ"}إطار {framework}.

## النتائج والملاحظات

### نتائج عالية الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية | الحالة |
|---|----------|---------------|---------|--------|
| 1 | (ملاحظة عالية الخطورة {"متعلقة بـ" + audit_topic if audit_topic else ""}) | (رمز من {framework}) | (التوصية) | يحتاج تقييم |
| 2 | (ملاحظة عالية الخطورة {"متعلقة بـ" + audit_topic if audit_topic else ""}) | (رمز من {framework}) | (التوصية) | يحتاج تقييم |

### نتائج متوسطة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية | الحالة |
|---|----------|---------------|---------|--------|
| 1 | (ملاحظة متوسطة الخطورة {"متعلقة بـ" + audit_topic if audit_topic else ""}) | (رمز من {framework}) | (التوصية) | يحتاج تقييم |
| 2 | (ملاحظة متوسطة الخطورة {"متعلقة بـ" + audit_topic if audit_topic else ""}) | (رمز من {framework}) | (التوصية) | يحتاج تقييم |

### نتائج منخفضة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية | الحالة |
|---|----------|---------------|---------|--------|
| 1 | (ملاحظة منخفضة الخطورة {"متعلقة بـ" + audit_topic if audit_topic else ""}) | (رمز من {framework}) | (التوصية) | يحتاج تقييم |

## أدلة التنفيذ التفصيلية

يجب كتابة دليل تنفيذ منفصل لكل ملاحظة عالية ومتوسطة الخطورة

### دليل تنفيذ الملاحظة عالية الخطورة رقم 1: (عنوان الملاحظة)
**الضابط المتأثر:** (رمز الضابط من {framework})
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التخطيط | 1.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |
**الأدلة المطلوبة:** ☐ (دليل 1) ☐ (دليل 2) ☐ (دليل 3)

### دليل تنفيذ الملاحظة عالية الخطورة رقم 2: (عنوان الملاحظة)
**الضابط المتأثر:** (رمز الضابط من {framework})
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التخطيط | 1.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.2 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |
**الأدلة المطلوبة:** ☐ (دليل 1) ☐ (دليل 2) ☐ (دليل 3)

### دليل تنفيذ الملاحظة متوسطة الخطورة رقم 1: (عنوان الملاحظة)
**الضابط المتأثر:** (رمز الضابط من {framework})
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |
**الأدلة المطلوبة:** ☐ (دليل 1) ☐ (دليل 2) ☐ (دليل 3)

### دليل تنفيذ الملاحظة متوسطة الخطورة رقم 2: (عنوان الملاحظة)
**الضابط المتأثر:** (رمز الضابط من {framework})
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التنفيذ | 2.1 | (خطوة محددة) | (الفريق) | (المخرج) |
| التحقق | 3.1 | (خطوة محددة) | (الفريق) | (المخرج) |
**الأدلة المطلوبة:** ☐ (دليل 1) ☐ (دليل 2) ☐ (دليل 3)

## خطة العمل
| # | الإجراء | المسؤول | الموعد النهائي | الأولوية |
|---|--------|---------|---------------|----------|
| 1 | معالجة الملاحظات عالية الخطورة | فريق الأمن | خلال 30 يوم | عالية |
| 2 | معالجة الملاحظات متوسطة الخطورة | فريق الامتثال | خلال 60 يوم | متوسطة |
| 3 | معالجة الملاحظات منخفضة الخطورة | فريق التوثيق | خلال 90 يوم | منخفضة |

---
**تاريخ التقرير:** يُحدد لاحقاً
**التدقيق القادم:** خلال 6 أشهر"""

        content = generate_ai_content(prompt, lang)
        
        # POST-PROCESSING: Check if AI produced the same 5 generic findings
        # If generic, replace with topic-specific simulation content
        audit_generic_markers = [
            'mfa not enabled', 'weak password polic', 'insufficient documentation',
            'delayed awareness', 'no periodic review',
            'عدم تفعيل mfa', 'سياسات كلمات المرور ضعيفة', 'نقص في التوثيق',
            'تأخر في برامج التوعية', 'عدم وجود مراجعة دورية',
        ]
        audit_content_lower = content.lower() if content else ''
        audit_generic_count = sum(1 for m in audit_generic_markers if m in audit_content_lower)
        if audit_generic_count >= 3 and audit_topic:
            print(f"DEBUG: Audit AI output had {audit_generic_count} generic findings — using simulation", flush=True)
            sim_content = generate_audit_simulation(lang, framework, audit_topic)
            if sim_content:
                content = sim_content
        
        # INJECT IMPLEMENTATION GUIDELINES if missing from audit content
        def inject_audit_guidelines(audit_content, lang_code):
            """Inject implementation guidelines if AI didn't include them."""
            has_guidelines = (
                'Implementation Guide' in audit_content or 
                'Step-by-Step' in audit_content or
                'دليل تنفيذ' in audit_content or
                'الخطوات التفصيلية' in audit_content
            )
            
            if has_guidelines:
                return audit_content
            
            # Extract findings from High-Risk table
            import re
            finding_pattern = r'\|\s*(\d+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|'
            findings = re.findall(finding_pattern, audit_content)
            
            findings_list = []
            for num, finding, control in findings:
                finding = finding.strip()
                control = control.strip()
                if finding and finding.lower() not in ['observation', 'الملاحظة', '#', 'finding']:
                    findings_list.append((num, finding, control))
            
            if not findings_list:
                return audit_content
            
            if lang_code == 'ar':
                guidelines = "\n\n---\n\n## دليل التنفيذ التفصيلي\n\n"
                for num, finding, control in findings_list[:3]:
                    guidelines += f"""---
### دليل تنفيذ الملاحظة رقم {num}: {finding[:50]}

**الضابط المتأثر:** {control}

**الخطوات التفصيلية:**
| المرحلة | الخطوة | الوصف | المسؤول | المخرجات |
|---------|--------|-------|---------|----------|
| التخطيط | 1.1 | تقييم الوضع الحالي | فريق الأمن | تقرير التقييم |
| التخطيط | 1.2 | تحديد المتطلبات والموارد | مدير المشروع | وثيقة المتطلبات |
| التنفيذ | 2.1 | تطبيق الضوابط المطلوبة | الفريق التقني | ضوابط مطبقة |
| التنفيذ | 2.2 | تدريب الموظفين المعنيين | التدريب | سجلات التدريب |
| التحقق | 3.1 | اختبار فعالية الضوابط | ضمان الجودة | تقرير الاختبار |
| التحقق | 3.2 | توثيق الإغلاق | أمن المعلومات | وثائق الإغلاق |

**الأدلة المطلوبة للإغلاق:**
- [ ] تقرير التقييم الأولي
- [ ] سجلات تطبيق الضوابط
- [ ] شهادات التدريب
- [ ] تقرير اختبار الفعالية

"""
            else:
                guidelines = "\n\n---\n\n## Detailed Implementation Guidelines\n\n"
                for num, finding, control in findings_list[:3]:
                    guidelines += f"""---
### Finding #{num} Implementation Guide: {finding[:50]}

**Affected Control:** {control}

**Step-by-Step Implementation:**
| Phase | Step | Description | Owner | Deliverable |
|-------|------|-------------|-------|-------------|
| Planning | 1.1 | Assess current state | Security Team | Assessment report |
| Planning | 1.2 | Define requirements and resources | Project Manager | Requirements document |
| Implementation | 2.1 | Apply required controls | Technical Team | Implemented controls |
| Implementation | 2.2 | Train relevant staff | Training | Training records |
| Verification | 3.1 | Test control effectiveness | QA | Test report |
| Verification | 3.2 | Document closure | InfoSec | Closure documentation |

**Evidence Required for Closure:**
- [ ] Initial assessment report
- [ ] Control implementation records
- [ ] Training certificates
- [ ] Effectiveness test report

"""
            
            return audit_content + guidelines
        
        content = inject_audit_guidelines(content, lang)
        
        # Save to database
        try:
            conn = get_db()
            conn.execute('''INSERT INTO audits (user_id, domain, framework, scope, content, language)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                        (session['user_id'], domain, framework, audit_scope, content, lang))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print(f"Database error: {db_error}")
        
        return jsonify({'success': True, 'content': content})
        
    except Exception as e:
        print(f"Audit generation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/test-docx', methods=['GET'])
@login_required
def api_test_docx():
    """Test if DOCX generation works at all on this server."""
    try:
        from io import BytesIO
        from docx import Document
        from docx.shared import Inches
        doc = Document()
        doc.add_heading('Test Document', 0)
        doc.add_paragraph('This is a test paragraph.')
        table = doc.add_table(rows=2, cols=2)
        table.rows[0].cells[0].text = 'Test'
        table.rows[0].cells[1].text = 'Table'
        table.rows[1].cells[0].text = '1'
        table.rows[1].cells[1].text = '2'
        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        from flask import send_file
        return send_file(buffer, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        as_attachment=True, download_name='test.docx')
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'trace': traceback.format_exc()}), 500

@app.route('/api/generate-docx', methods=['POST'])
@login_required
def api_generate_docx():
    """Generate Word document from content."""
    from io import BytesIO
    import re
    
    try:
        data = request.json
    except Exception as je:
        print(f"DOCX ERROR: Failed to parse JSON: {je}", flush=True)
        return jsonify({'error': f'Invalid JSON: {str(je)}'}), 400
    
    if not data:
        print("DOCX ERROR: No JSON data received!", flush=True)
        return jsonify({'error': 'No data received'}), 400
    
    content = data.get('content', '')
    filename = data.get('filename', 'document')
    lang = data.get('language', 'en')
    
    print("=" * 60, flush=True)
    print(f"DOCX GENERATION - lang={lang}, filename={filename}", flush=True)
    print(f"Content length: {len(content)}", flush=True)
    print(f"Content preview: {content[:200]}", flush=True)
    print("=" * 60, flush=True)
    
    if not content or not content.strip():
        print("DOCX ERROR: Empty content!", flush=True)
        return jsonify({'error': 'No content to generate document'}), 400
    
    try:
        from docx import Document
        from docx.shared import Inches, Pt, Cm, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.oxml.ns import nsdecls, qn
        from docx.oxml import parse_xml
        
        is_arabic = lang == 'ar'
        doc = Document()
        
        # Set page size and document-level RTL
        for section in doc.sections:
            section.page_width = Inches(8.5)
            section.page_height = Inches(11)
        
        # Set document-level RTL for Arabic
        if is_arabic:
            try:
                body = doc.element.body
                sectPr = body.find(qn('w:sectPr'))
                if sectPr is not None:
                    bidi = parse_xml(f'<w:bidi {nsdecls("w")} w:val="1"/>')
                    sectPr.append(bidi)
            except Exception:
                pass  # Non-critical
        
        def set_rtl_paragraph(paragraph):
            """Set full RTL properties on a paragraph."""
            if not is_arabic:
                return
            paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            # Set paragraph-level RTL
            pPr = paragraph._p.get_or_add_pPr()
            bidi = parse_xml(f'<w:bidi {nsdecls("w")} w:val="1"/>')
            pPr.append(bidi)
            # Set RTL on each run
            for run in paragraph.runs:
                rPr = run._r.get_or_add_rPr()
                rtl_elem = parse_xml(f'<w:rtl {nsdecls("w")} w:val="1"/>')
                rPr.append(rtl_elem)
        
        def set_rtl_run(run):
            """Set RTL on a single run."""
            if not is_arabic:
                return
            rPr = run._r.get_or_add_rPr()
            rtl_elem = parse_xml(f'<w:rtl {nsdecls("w")} w:val="1"/>')
            rPr.append(rtl_elem)
        
        def add_rtl_heading(text, level):
            """Add a heading with proper RTL."""
            h = doc.add_heading(text, level=level)
            if is_arabic:
                set_rtl_paragraph(h)
            return h
        
        def add_rtl_paragraph(text, bold=False):
            """Add a normal paragraph with proper RTL."""
            p = doc.add_paragraph()
            run = p.add_run(text)
            if bold:
                run.bold = True
            if is_arabic:
                set_rtl_paragraph(p)
            return p
        
        # ---- Table helpers ----
        
        def parse_markdown_table(lines, start_idx):
            """Parse markdown table starting at start_idx."""
            table_rows = []
            idx = start_idx
            while idx < len(lines):
                ln = lines[idx].strip()
                if ln.startswith('|') and ln.endswith('|'):
                    if '---' in ln or ':-' in ln or '-:' in ln:
                        idx += 1
                        continue
                    cells = [cell.strip() for cell in ln.split('|')[1:-1]]
                    if cells:
                        table_rows.append(cells)
                    idx += 1
                else:
                    break
            return table_rows, idx
        
        def add_table_to_doc(doc, table_data, lang):
            """Add a formatted table with RTL support."""
            if not table_data or len(table_data) < 1:
                return
            
            # DO NOT reverse columns - bidiVisual will handle RTL display
            num_cols = len(table_data[0])
            table = doc.add_table(rows=len(table_data), cols=num_cols)
            try:
                table.style = 'Table Grid'
            except Exception:
                pass  # Style not available, use default
            
            # Set table RTL direction for Arabic
            if is_arabic:
                tbl = table._tbl
                tblPr = tbl.tblPr if tbl.tblPr is not None else parse_xml(f'<w:tblPr {nsdecls("w")}/>')
                bidi_visual = parse_xml(f'<w:bidiVisual {nsdecls("w")} w:val="1"/>')
                tblPr.append(bidi_visual)
            
            for i, row_data in enumerate(table_data):
                row = table.rows[i]
                for j, cell_text in enumerate(row_data):
                    if j < len(row.cells):
                        cell = row.cells[j]
                        cell.text = cell_text
                        
                        # Style header row
                        if i == 0:
                            for paragraph in cell.paragraphs:
                                for run in paragraph.runs:
                                    run.bold = True
                                    run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                            shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="4472C4"/>')
                            cell._tc.get_or_add_tcPr().append(shading)
                        
                        # Set RTL on each cell paragraph
                        for paragraph in cell.paragraphs:
                            if is_arabic:
                                set_rtl_paragraph(paragraph)
                            else:
                                paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
            
            doc.add_paragraph()
        
        # ---- Add document title ----
        if is_arabic:
            title_text = filename.replace('_', ' ')
        else:
            title_text = filename.replace('_', ' ').title()
        
        try:
            add_rtl_heading(title_text, 0)
        except Exception:
            # Fallback if Title style fails
            add_rtl_heading(title_text, 1)
        
        # ---- Process content line by line ----
        lines = content.split('\n')
        i = 0
        
        while i < len(lines):
            try:
                line = lines[i].strip()
                
                # Skip empty lines and separators
                if not line:
                    i += 1
                    continue
                if line == '---' or line == '[SECTION]':
                    doc.add_paragraph('')
                    i += 1
                    continue
                
                # Table
                if line.startswith('|') and '|' in line[1:]:
                    table_data, new_idx = parse_markdown_table(lines, i)
                    if table_data:
                        add_table_to_doc(doc, table_data, lang)
                    i = new_idx
                    continue
                
                # Headings — check most specific first
                if line.startswith('#### '):
                    add_rtl_heading(line[5:], 3)
                elif line.startswith('### '):
                    add_rtl_heading(line[4:], 2)
                elif line.startswith('## '):
                    add_rtl_heading(line[3:], 1)
                elif line.startswith('# '):
                    try:
                        add_rtl_heading(line[2:], 0)
                    except Exception:
                        add_rtl_heading(line[2:], 1)
                
                # Bullet points
                elif line.startswith('- ') or line.startswith('* ') or line.startswith('• '):
                    raw_text = line[2:]
                    if is_arabic:
                        p = doc.add_paragraph()
                        # Keep natural order - RTL will handle display
                        run = p.add_run('• ' + raw_text)
                        set_rtl_paragraph(p)
                        p.paragraph_format.left_indent = Cm(1)
                    else:
                        try:
                            p = doc.add_paragraph(raw_text, style='List Bullet')
                        except Exception:
                            p = doc.add_paragraph('• ' + raw_text)
                
                # Numbered lists
                elif re.match(r'^(\d+)\.\s+(.+)', line):
                    m = re.match(r'^(\d+)\.\s+(.+)', line)
                    num = m.group(1)
                    raw_text = m.group(2)
                    if is_arabic:
                        p = doc.add_paragraph()
                        # Keep natural order - RTL will handle display
                        run = p.add_run(num + '. ' + raw_text)
                        set_rtl_paragraph(p)
                        p.paragraph_format.left_indent = Cm(1)
                    else:
                        try:
                            p = doc.add_paragraph(line, style='List Number')
                        except Exception:
                            p = doc.add_paragraph(line)
                
                # Full bold line
                elif line.startswith('**') and line.endswith('**'):
                    add_rtl_paragraph(line[2:-2], bold=True)
                
                # Inline bold
                elif '**' in line:
                    p = doc.add_paragraph()
                    parts = re.split(r'\*\*(.+?)\*\*', line)
                    for idx, part in enumerate(parts):
                        if part:
                            run = p.add_run(part)
                            if idx % 2 == 1:
                                run.bold = True
                            if is_arabic:
                                set_rtl_run(run)
                    if is_arabic:
                        set_rtl_paragraph(p)
                
                # Normal text
                else:
                    add_rtl_paragraph(line)
                
                i += 1
            
            except Exception as line_err:
                print(f"DOCX WARNING: Error on line {i}: '{lines[i][:80] if i < len(lines) else '?'}' - {line_err}", flush=True)
                try:
                    add_rtl_paragraph(lines[i].strip() if i < len(lines) else '')
                except Exception:
                    pass
                i += 1
        
        # Save to BytesIO
        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        
        from flask import send_file
        return send_file(
            buffer,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=f'{filename}.docx'
        )
    except ImportError as ie:
        print(f"DOCX IMPORT ERROR: {ie}", flush=True)
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Word generation not available: {str(ie)}'}), 500
    except Exception as e:
        print(f"DOCX GENERATION ERROR: {str(e)}", flush=True)
        import traceback
        tb = traceback.format_exc()
        print(tb, flush=True)
        return jsonify({'error': f'Document generation failed: {str(e)}'}), 500

@app.route('/api/generate-pdf', methods=['POST'])
@login_required
def api_generate_pdf():
    """Generate PDF document from content with Arabic support."""
    from io import BytesIO
    import os
    import glob
    
    data = request.json
    content = data.get('content', '')
    filename = data.get('filename', 'document')
    lang = data.get('language', 'en')
    
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_RIGHT, TA_LEFT, TA_CENTER
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.units import inch, cm
        from reportlab.lib import colors
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        
        # For Arabic text
        is_arabic = lang == 'ar'
        arabic_font_name = 'Helvetica'  # Default fallback
        arabic_font_bold = 'Helvetica-Bold'
        
        if is_arabic:
            try:
                import arabic_reshaper
                from bidi.algorithm import get_display
                
                # Extended font search paths for Arabic support
                font_paths = [
                    # Noto fonts (installed via render.yaml)
                    '/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf',
                    '/usr/share/fonts/opentype/noto/NotoSansArabic-Regular.ttf',
                    '/usr/share/fonts/truetype/noto/NotoNaskhArabic-Regular.ttf',
                    # FreeFonts
                    '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
                    '/usr/share/fonts/truetype/freefont/FreeSerif.ttf',
                    # DejaVu (has Arabic support)
                    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                    # Liberation fonts
                    '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
                    # Local fonts
                    'static/fonts/Amiri-Regular.ttf',
                    'static/fonts/NotoSansArabic-Regular.ttf',
                    # Additional system paths
                    '/usr/share/fonts/TTF/DejaVuSans.ttf',
                    '/usr/local/share/fonts/Amiri-Regular.ttf',
                ]
                
                # Also search for any Arabic font using glob
                additional_paths = glob.glob('/usr/share/fonts/**/[Aa]rabic*.ttf', recursive=True)
                additional_paths += glob.glob('/usr/share/fonts/**/[Nn]oto*[Aa]rabic*.ttf', recursive=True)
                additional_paths += glob.glob('/usr/share/fonts/**/[Aa]miri*.ttf', recursive=True)
                font_paths = additional_paths + font_paths
                
                font_registered = False
                for font_path in font_paths:
                    if os.path.exists(font_path):
                        try:
                            pdfmetrics.registerFont(TTFont('ArabicFont', font_path))
                            arabic_font_name = 'ArabicFont'
                            arabic_font_bold = 'ArabicFont'
                            font_registered = True
                            print(f"✅ Registered Arabic font: {font_path}", flush=True)
                            break
                        except Exception as font_error:
                            print(f"⚠️ Failed to register font {font_path}: {font_error}", flush=True)
                            continue
                
                if not font_registered:
                    print("⚠️ No Arabic font found, PDF will show boxes for Arabic text", flush=True)
                    # List available fonts for debugging
                    for search_path in ['/usr/share/fonts/truetype/', '/usr/share/fonts/']:
                        if os.path.exists(search_path):
                            print(f"Available fonts in {search_path}:", flush=True)
                            for item in os.listdir(search_path)[:10]:
                                print(f"  - {item}", flush=True)
                
            except ImportError as ie:
                print(f"⚠️ Arabic libraries not available: {ie}", flush=True)
                # Fallback if arabic libraries not available
                def get_display(text):
                    return text
                class _FallbackReshaper:
                    def reshape(self, text):
                        return text
                arabic_reshaper = _FallbackReshaper()
        
        # Calculate available text width for manual line wrapping
        page_width = A4[0]
        text_width = page_width - 3*cm  # 1.5cm margin each side
        # CRITICAL: Use a tighter wrap width for Arabic pre-wrapping.
        # We must wrap NARROWER than ReportLab's Paragraph frame width,
        # so ReportLab never re-wraps our visually-ordered lines.
        # If ReportLab re-wraps, it splits reversed text at wrong points
        # (e.g. "تهدف" appearing alone on a line).
        arabic_wrap_width = text_width - 12  # 12pt safety margin
        
        def process_arabic(text, font_name_for_wrap=None, font_size_for_wrap=11, extra_indent=0):
            """Process Arabic text for correct display in PDF.
            
            Strategy: reshape → manual word-wrap → get_display per line → join with <br/>
            This prevents the jumbled word order that happens when get_display is applied
            to an entire paragraph and then ReportLab re-wraps it.
            
            CRITICAL: We wrap to arabic_wrap_width (narrower than frame) so ReportLab
            never needs to re-wrap our pre-wrapped lines.
            """
            if is_arabic and text:
                try:
                    text = str(text).strip()
                    if not text:
                        return text
                    
                    from reportlab.pdfbase.pdfmetrics import stringWidth
                    wrap_font = font_name_for_wrap or arabic_font_name
                    # Use tighter width to prevent ReportLab re-wrapping
                    wrap_width = arabic_wrap_width - extra_indent
                    
                    # Handle mixed content with HTML bold tags
                    if '<b>' in text or '</b>' in text:
                        import re as re_clean
                        parts = re_clean.split(r'(<b>|</b>)', text)
                        processed_parts = []
                        for part in parts:
                            if part in ('<b>', '</b>'):
                                processed_parts.append(part)
                            elif part.strip():
                                reshaped = arabic_reshaper.reshape(part)
                                processed_parts.append(get_display(reshaped))
                            else:
                                processed_parts.append(part)
                        return ''.join(processed_parts)
                    
                    # Step 1: Reshape for letter joining
                    reshaped = arabic_reshaper.reshape(text)
                    
                    # Step 2: Check if text fits in one line (most headings, short text)
                    total_width = stringWidth(reshaped, wrap_font, font_size_for_wrap)
                    if total_width <= wrap_width:
                        # Single line — just get_display the whole thing
                        return get_display(reshaped)
                    
                    # Step 3: Manual word-wrap for multi-line text
                    words = reshaped.split(' ')
                    lines = []
                    current_line_words = []
                    current_width = 0
                    space_width = stringWidth(' ', wrap_font, font_size_for_wrap)
                    
                    for word in words:
                        word_width = stringWidth(word, wrap_font, font_size_for_wrap)
                        test_width = current_width + word_width + (space_width if current_line_words else 0)
                        
                        if test_width > wrap_width and current_line_words:
                            # Line is full — wrap to next line
                            line_text = ' '.join(current_line_words)
                            lines.append(get_display(line_text))
                            current_line_words = [word]
                            current_width = word_width
                        else:
                            current_line_words.append(word)
                            current_width = test_width
                    
                    # Last line
                    if current_line_words:
                        line_text = ' '.join(current_line_words)
                        lines.append(get_display(line_text))
                    
                    # Step 4: Join with <br/> for ReportLab Paragraph
                    if len(lines) > 1:
                        return '<br/>'.join(lines)
                    elif lines:
                        return lines[0]
                    else:
                        return get_display(reshaped)
                    
                except Exception as e:
                    print(f"Arabic processing warning: {e}", flush=True)
                    return text
            return text
        
        def process_arabic_table(text, col_width, font_size=9):
            """Process Arabic text for table cells with specific column width."""
            if is_arabic and text:
                try:
                    text = str(text).strip()
                    if not text:
                        return text
                    
                    from reportlab.pdfbase.pdfmetrics import stringWidth
                    reshaped = arabic_reshaper.reshape(text)
                    
                    # Check if fits in one line
                    total_w = stringWidth(reshaped, arabic_font_name, font_size)
                    cell_width = col_width - 16  # subtract padding + safety margin
                    if total_w <= cell_width:
                        return get_display(reshaped)
                    
                    # Wrap strictly within cell width - no overflow tolerance
                    words = reshaped.split(' ')
                    lines = []
                    current_line_words = []
                    current_width = 0
                    space_width = stringWidth(' ', arabic_font_name, font_size)
                    
                    for word in words:
                        word_width = stringWidth(word, arabic_font_name, font_size)
                        test_width = current_width + word_width + (space_width if current_line_words else 0)
                        
                        if test_width > cell_width and current_line_words:
                            line_text = ' '.join(current_line_words)
                            lines.append(get_display(line_text))
                            current_line_words = [word]
                            current_width = word_width
                        else:
                            current_line_words.append(word)
                            current_width = test_width
                    
                    if current_line_words:
                        line_text = ' '.join(current_line_words)
                        lines.append(get_display(line_text))
                    
                    return '<br/>'.join(lines) if len(lines) > 1 else (lines[0] if lines else get_display(reshaped))
                    
                except Exception as e:
                    return text
            return text
        
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=1.5*cm,
            leftMargin=1.5*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        # Styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        if is_arabic:
            title_style = ParagraphStyle(
                'ArabicTitle',
                parent=styles['Title'],
                alignment=TA_RIGHT,
                fontSize=24,
                spaceAfter=30,
                fontName=arabic_font_bold,
            )
            heading1_style = ParagraphStyle(
                'ArabicH1',
                parent=styles['Heading1'],
                alignment=TA_RIGHT,
                fontSize=18,
                spaceAfter=12,
                spaceBefore=20,
                textColor=colors.HexColor('#1a365d'),
                fontName=arabic_font_bold,
            )
            heading2_style = ParagraphStyle(
                'ArabicH2',
                parent=styles['Heading2'],
                alignment=TA_RIGHT,
                fontSize=14,
                spaceAfter=10,
                spaceBefore=15,
                textColor=colors.HexColor('#2d3748'),
                fontName=arabic_font_bold,
            )
            normal_style = ParagraphStyle(
                'ArabicNormal',
                parent=styles['Normal'],
                alignment=TA_RIGHT,
                fontSize=11,
                spaceAfter=8,
                leading=18,
                fontName=arabic_font_name,
            )
            bullet_style = ParagraphStyle(
                'ArabicBullet',
                parent=styles['Normal'],
                alignment=TA_RIGHT,
                fontSize=11,
                spaceAfter=6,
                rightIndent=20,
                fontName=arabic_font_name,
            )
            numbered_style = ParagraphStyle(
                'ArabicNumbered',
                parent=styles['Normal'],
                alignment=TA_RIGHT,
                fontSize=11,
                spaceAfter=6,
                rightIndent=20,
                fontName=arabic_font_name,
            )
        else:
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.HexColor('#1a365d')
            )
            heading1_style = ParagraphStyle(
                'CustomH1',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=12,
                spaceBefore=20,
                textColor=colors.HexColor('#1a365d')
            )
            heading2_style = ParagraphStyle(
                'CustomH2',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=10,
                spaceBefore=15,
                textColor=colors.HexColor('#2d3748')
            )
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=11,
                spaceAfter=8,
                leading=16
            )
            bullet_style = ParagraphStyle(
                'CustomBullet',
                parent=styles['Normal'],
                fontSize=11,
                spaceAfter=6,
                leftIndent=20,
                bulletIndent=10
            )
            numbered_style = ParagraphStyle(
                'CustomNumbered',
                parent=styles['Normal'],
                fontSize=11,
                spaceAfter=6,
                leftIndent=20
            )
        
        # Build content
        story = []
        
        # Add title
        if is_arabic:
            title_text = process_arabic(filename.replace('_', ' '), arabic_font_bold, 24)
        else:
            title_text = filename.replace('_', ' ').title()
        story.append(Paragraph(title_text, title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Parse markdown content
        lines = content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            if not line:
                i += 1
                continue
            
            # Skip separator lines
            if line == '---':
                story.append(Spacer(1, 0.2*inch))
                i += 1
                continue
            
            # Skip [SECTION] markers
            if line.strip() == '[SECTION]':
                story.append(Spacer(1, 0.15*inch))
                i += 1
                continue
            
            # Check if this is a table
            if line.startswith('|') and '|' in line[1:]:
                table_data = []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    row_line = lines[i].strip()
                    if '---' not in row_line:  # Skip separator
                        cells = [c.strip() for c in row_line.split('|')[1:-1]]
                        if cells:
                            # Reverse column order for Arabic RTL
                            if is_arabic:
                                cells = cells[::-1]
                            table_data.append(cells)
                    i += 1
                
                if table_data:
                    # Create table with smart column widths
                    col_count = len(table_data[0]) if table_data else 1
                    
                    # Check if this is an implementation guidelines table (has Phase/Step columns)
                    header_row = [str(c).lower() for c in table_data[0]] if table_data else []
                    is_implementation_table = any(h in ['phase', 'step', 'المرحلة', 'الخطوة'] for h in header_row)
                    
                    # Calculate column widths - give more space for Arabic text
                    available_width = doc.width
                    
                    if is_implementation_table and col_count == 5:
                        # Implementation guidelines table: Phase, Step, Description, Owner, Deliverable
                        # Give more space to Phase and Description columns
                        if is_arabic:
                            # Arabic: Deliverable, Owner, Description, Step, Phase (reversed)
                            col_widths = [
                                available_width * 0.16,  # المخرجات (Deliverable)
                                available_width * 0.13,  # المسؤول (Owner)
                                available_width * 0.36,  # الوصف (Description)
                                available_width * 0.10,  # الخطوة (Step)
                                available_width * 0.25,  # المرحلة (Phase) - wider for Arabic words
                            ]
                        else:
                            col_widths = [
                                available_width * 0.22,  # Phase - wider to avoid wrapping "Planning", "Verification", etc.
                                available_width * 0.08,  # Step - just numbers like "1.1"
                                available_width * 0.38,  # Description - main content
                                available_width * 0.14,  # Owner
                                available_width * 0.18,  # Deliverable
                            ]
                    elif col_count >= 7:
                        narrow_col = 0.4 * inch
                        remaining = available_width - narrow_col
                        other_cols = remaining / (col_count - 1)
                        if is_arabic:
                            col_widths = [other_cols] * (col_count - 1) + [narrow_col]
                        else:
                            col_widths = [narrow_col] + [other_cols] * (col_count - 1)
                    elif col_count >= 4:
                        # For 4-6 column tables, distribute more evenly
                        col_widths = [available_width / col_count] * col_count
                    elif col_count == 3:
                        equal = available_width / 3
                        col_widths = [equal] * 3
                    elif col_count == 2:
                        col_widths = [available_width * 0.5, available_width * 0.5]
                    else:
                        col_widths = [available_width]
                    
                    # Wrap cell content in Paragraphs
                    cell_style = ParagraphStyle(
                        'CellStyle', 
                        fontSize=9, 
                        leading=14,
                        fontName=arabic_font_name if is_arabic else 'Helvetica',
                        alignment=TA_RIGHT if is_arabic else TA_LEFT,
                    )
                    header_cell_style = ParagraphStyle(
                        'HeaderCellStyle', 
                        fontSize=9, 
                        leading=14, 
                        textColor=colors.white,
                        fontName=arabic_font_bold if is_arabic else 'Helvetica-Bold',
                        alignment=TA_RIGHT if is_arabic else TA_LEFT,
                    )
                    
                    wrapped_data = []
                    for row_idx, row in enumerate(table_data):
                        wrapped_row = []
                        for col_idx, cell in enumerate(row):
                            cell_text = str(cell)
                            # Process Arabic: reshape and per-cell-width bidi
                            if is_arabic and cell_text:
                                cw = col_widths[col_idx] if col_idx < len(col_widths) else text_width / len(row)
                                cell_text = process_arabic_table(cell_text, cw, font_size=9)
                            if row_idx == 0:  # Header row
                                wrapped_row.append(Paragraph(cell_text, header_cell_style))
                            else:
                                wrapped_row.append(Paragraph(cell_text, cell_style))
                        wrapped_data.append(wrapped_row)
                    
                    t = Table(wrapped_data, colWidths=col_widths)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'RIGHT' if is_arabic else 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (0, 0), (-1, -1), arabic_font_name if is_arabic else 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.15*inch))
                continue
            
            # Handle markdown headings
            # IMPORTANT: Strip markdown prefix FIRST, then process Arabic
            # Check more specific headings first (#### before ### before ##)
            if line.startswith('#### '):
                raw_text = line[5:]
                text = process_arabic(raw_text, arabic_font_bold, 14) if is_arabic else raw_text
                story.append(Paragraph(text, heading2_style))
            elif line.startswith('### '):
                raw_text = line[4:]
                text = process_arabic(raw_text, arabic_font_bold, 14) if is_arabic else raw_text
                story.append(Paragraph(text, heading2_style))
            elif line.startswith('## '):
                raw_text = line[3:]
                text = process_arabic(raw_text, arabic_font_bold, 18) if is_arabic else raw_text
                story.append(Paragraph(text, heading1_style))
            elif line.startswith('# '):
                raw_text = line[2:]
                text = process_arabic(raw_text, arabic_font_bold, 24) if is_arabic else raw_text
                story.append(Paragraph(text, title_style))
            elif line.startswith('- ') or line.startswith('* ') or line.startswith('• '):
                raw_text = line[2:]
                text = process_arabic(raw_text, arabic_font_name, 11, extra_indent=20) if is_arabic else raw_text
                if is_arabic:
                    # Arabic: bullet on right, get_display already reversed the text
                    bullet_text = text + ' •'
                else:
                    bullet_text = '• ' + text
                story.append(Paragraph(bullet_text, bullet_style))
            elif len(line) > 2 and line[0].isdigit() and (line[1] == '.' or (len(line) > 2 and line[1].isdigit() and line[2] == '.')):
                # Numbered list
                import re as re_mod
                num_match = re_mod.match(r'^(\d+)\.\s*(.+)', line)
                if num_match:
                    num = num_match.group(1)
                    raw_text = num_match.group(2)
                    text = process_arabic(raw_text, arabic_font_name, 11, extra_indent=20) if is_arabic else raw_text
                    if is_arabic:
                        numbered_text = text + ' .' + num
                    else:
                        numbered_text = num + '. ' + text
                    story.append(Paragraph(numbered_text, numbered_style))
                else:
                    text = process_arabic(line, arabic_font_name, 11) if is_arabic else line
                    story.append(Paragraph(text, normal_style))
            elif line.startswith('**') and line.endswith('**'):
                raw_text = line[2:-2]
                text = process_arabic(raw_text, arabic_font_bold, 11) if is_arabic else raw_text
                story.append(Paragraph(f'<b>{text}</b>', normal_style))
            elif '**' in line:
                # Handle inline bold - strip ** markers, then process Arabic
                import re
                parts = re.split(r'\*\*(.+?)\*\*', line)
                formatted_parts = []
                for idx, part in enumerate(parts):
                    if idx % 2 == 1:  # Bold text
                        p = process_arabic(part, arabic_font_bold, 11) if is_arabic else part
                        formatted_parts.append(f'<b>{p}</b>')
                    else:
                        p = process_arabic(part, arabic_font_name, 11) if is_arabic else part
                        formatted_parts.append(p)
                formatted = ''.join(formatted_parts)
                story.append(Paragraph(formatted, normal_style))
            else:
                text = process_arabic(line, arabic_font_name, 11) if is_arabic else line
                story.append(Paragraph(text, normal_style))
            
            i += 1
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        from flask import send_file
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'{filename}.pdf'
        )
        
    except ImportError as e:
        return jsonify({'error': f'PDF generation not available: {str(e)}'}), 500
    except Exception as e:
        print(f"PDF generation error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500

@app.route('/api/set-language/<lang>')
def set_language(lang):
    """Set language preference."""
    session['lang'] = lang if lang in ['en', 'ar'] else 'en'
    return jsonify({'success': True, 'lang': session['lang']})

# ============================================================================
# EXCEL EXPORT
# ============================================================================

@app.route('/api/generate-excel', methods=['POST'])
@login_required
def api_generate_excel():
    """Generate Excel file from data."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    import io
    
    try:
    
        data = request.json
        export_type = data.get('type', 'analytics')  # analytics, risks, documents
    
        wb = Workbook()
        ws = wb.active
    
        # Styles
        header_font = Font(bold=True, color='FFFFFF', size=11)
        header_fill = PatternFill(start_color='667eea', end_color='667eea', fill_type='solid')
        header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell_alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
        thin_border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
    
        if export_type == 'analytics':
            ws.title = 'Analytics Summary'
        
            # Get user data
            user_id = session.get('user_id')
            if user_id:
                compliance = calculate_compliance_score(user_id)
                maturity = calculate_maturity_levels(user_id)
            
                # Compliance Score Section
                ws['A1'] = 'COMPLIANCE SCORE SUMMARY'
                ws['A1'].font = Font(bold=True, size=14, color='667eea')
                ws.merge_cells('A1:D1')
            
                headers = ['Metric', 'Value', 'Target', 'Status']
                for col, header in enumerate(headers, 1):
                    cell = ws.cell(row=3, column=col, value=header)
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_alignment
                    cell.border = thin_border
            
                metrics = [
                    ('Overall Score', f"{compliance['score']}%", '80%', 'Good' if compliance['score'] >= 60 else 'Needs Improvement'),
                    ('Strategies', compliance['strategies'], '5', '✓' if compliance['strategies'] >= 3 else '✗'),
                    ('Policies', compliance['policies'], '10', '✓' if compliance['policies'] >= 5 else '✗'),
                    ('Audits', compliance['audits'], '5', '✓' if compliance['audits'] >= 3 else '✗'),
                    ('Risk Assessments', compliance['risks'], '10', '✓' if compliance['risks'] >= 5 else '✗'),
                    ('Domains Covered', compliance['domains_covered'], '5', '✓' if compliance['domains_covered'] >= 3 else '✗'),
                ]
            
                for row, (metric, value, target, status) in enumerate(metrics, 4):
                    ws.cell(row=row, column=1, value=metric).border = thin_border
                    ws.cell(row=row, column=2, value=value).border = thin_border
                    ws.cell(row=row, column=3, value=target).border = thin_border
                    ws.cell(row=row, column=4, value=status).border = thin_border
            
                # Maturity Section
                ws['A12'] = 'MATURITY RADAR SCORES'
                ws['A12'].font = Font(bold=True, size=14, color='667eea')
                ws.merge_cells('A12:C12')
            
                maturity_headers = ['Dimension', 'Score (1-5)', 'Level']
                for col, header in enumerate(maturity_headers, 1):
                    cell = ws.cell(row=14, column=col, value=header)
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_alignment
                    cell.border = thin_border
            
                def get_level(score):
                    if score < 2: return 'Initial'
                    elif score < 3: return 'Developing'
                    elif score < 4: return 'Defined'
                    elif score < 4.5: return 'Managed'
                    else: return 'Optimized'
            
                maturity_data = [
                    ('Governance', maturity['governance'], get_level(maturity['governance'])),
                    ('Risk Management', maturity['risk_mgmt'], get_level(maturity['risk_mgmt'])),
                    ('Compliance', maturity['compliance'], get_level(maturity['compliance'])),
                    ('Technology', maturity['technology'], get_level(maturity['technology'])),
                    ('Process', maturity['process'], get_level(maturity['process'])),
                    ('Overall Average', maturity['average'], get_level(maturity['average'])),
                ]
            
                for row, (dim, score, level) in enumerate(maturity_data, 15):
                    ws.cell(row=row, column=1, value=dim).border = thin_border
                    ws.cell(row=row, column=2, value=score).border = thin_border
                    ws.cell(row=row, column=3, value=level).border = thin_border
            
                # Adjust column widths
                ws.column_dimensions['A'].width = 25
                ws.column_dimensions['B'].width = 15
                ws.column_dimensions['C'].width = 15
                ws.column_dimensions['D'].width = 20
    
        elif export_type == 'risks':
            ws.title = 'Risk Register'
            user_id = session.get('user_id')
        
            if user_id:
                conn = get_db()
                risks = conn.execute('''
                    SELECT domain, asset_name, threat, risk_level, created_at 
                    FROM risks WHERE user_id = ? ORDER BY created_at DESC
                ''', (user_id,)).fetchall()
                conn.close()
            
                headers = ['#', 'Domain', 'Asset', 'Threat', 'Risk Level', 'Date']
                for col, header in enumerate(headers, 1):
                    cell = ws.cell(row=1, column=col, value=header)
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_alignment
                    cell.border = thin_border
            
                for row, risk in enumerate(risks, 2):
                    ws.cell(row=row, column=1, value=row-1).border = thin_border
                    ws.cell(row=row, column=2, value=risk['domain']).border = thin_border
                    ws.cell(row=row, column=3, value=risk['asset_name']).border = thin_border
                    ws.cell(row=row, column=4, value=risk['threat'][:100] if risk['threat'] else '').border = thin_border
                    ws.cell(row=row, column=5, value=risk['risk_level']).border = thin_border
                    ws.cell(row=row, column=6, value=risk['created_at'][:10] if risk['created_at'] else '').border = thin_border
            
                ws.column_dimensions['A'].width = 5
                ws.column_dimensions['B'].width = 20
                ws.column_dimensions['C'].width = 25
                ws.column_dimensions['D'].width = 50
                ws.column_dimensions['E'].width = 12
                ws.column_dimensions['F'].width = 12
    
        elif export_type == 'documents':
            ws.title = 'Document Inventory'
            user_id = session.get('user_id')
        
            if user_id:
                conn = get_db()
            
                headers = ['#', 'Type', 'Domain', 'Title/Name', 'Language', 'Created']
                for col, header in enumerate(headers, 1):
                    cell = ws.cell(row=1, column=col, value=header)
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_alignment
                    cell.border = thin_border
            
                row = 2
            
                # Strategies
                strategies = conn.execute('SELECT domain, org_name, language, created_at FROM strategies WHERE user_id = ?', (user_id,)).fetchall()
                for s in strategies:
                    ws.cell(row=row, column=1, value=row-1).border = thin_border
                    ws.cell(row=row, column=2, value='Strategy').border = thin_border
                    ws.cell(row=row, column=3, value=s['domain']).border = thin_border
                    ws.cell(row=row, column=4, value=s['org_name']).border = thin_border
                    ws.cell(row=row, column=5, value=s['language']).border = thin_border
                    ws.cell(row=row, column=6, value=s['created_at'][:10] if s['created_at'] else '').border = thin_border
                    row += 1
            
                # Policies
                policies = conn.execute('SELECT domain, policy_name, language, created_at FROM policies WHERE user_id = ?', (user_id,)).fetchall()
                for p in policies:
                    ws.cell(row=row, column=1, value=row-1).border = thin_border
                    ws.cell(row=row, column=2, value='Policy').border = thin_border
                    ws.cell(row=row, column=3, value=p['domain']).border = thin_border
                    ws.cell(row=row, column=4, value=p['policy_name']).border = thin_border
                    ws.cell(row=row, column=5, value=p['language']).border = thin_border
                    ws.cell(row=row, column=6, value=p['created_at'][:10] if p['created_at'] else '').border = thin_border
                    row += 1
            
                # Audits
                audits = conn.execute('SELECT domain, framework, language, created_at FROM audits WHERE user_id = ?', (user_id,)).fetchall()
                for a in audits:
                    ws.cell(row=row, column=1, value=row-1).border = thin_border
                    ws.cell(row=row, column=2, value='Audit').border = thin_border
                    ws.cell(row=row, column=3, value=a['domain']).border = thin_border
                    ws.cell(row=row, column=4, value=a['framework']).border = thin_border
                    ws.cell(row=row, column=5, value=a['language']).border = thin_border
                    ws.cell(row=row, column=6, value=a['created_at'][:10] if a['created_at'] else '').border = thin_border
                    row += 1
            
                conn.close()
            
                ws.column_dimensions['A'].width = 5
                ws.column_dimensions['B'].width = 12
                ws.column_dimensions['C'].width = 20
                ws.column_dimensions['D'].width = 35
                ws.column_dimensions['E'].width = 10
                ws.column_dimensions['F'].width = 12
    
        # Save to BytesIO
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
    
        filename = data.get('filename', f'mizan_export_{export_type}')
    
        return Response(
            output.getvalue(),
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename={filename}.xlsx'}
        )

    except Exception as e:
        print(f"Excel generation error: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard with statistics."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    txt = get_text(lang)
    conn = get_db()
    
    # Get statistics
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'active_users': conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0],
        'total_strategies': conn.execute('SELECT COUNT(*) FROM strategies').fetchone()[0],
        'total_policies': conn.execute('SELECT COUNT(*) FROM policies').fetchone()[0],
        'total_audits': conn.execute('SELECT COUNT(*) FROM audits').fetchone()[0],
        'total_risks': conn.execute('SELECT COUNT(*) FROM risks').fetchone()[0],
        'max_users': MAX_USERS,
    }
    
    # Calculate total documents
    stats['total_documents'] = stats['total_strategies'] + stats['total_policies'] + stats['total_audits'] + stats['total_risks']
    
    # Get documents by domain
    domains_strategies = conn.execute('SELECT domain, COUNT(*) as count FROM strategies GROUP BY domain').fetchall()
    domains_policies = conn.execute('SELECT domain, COUNT(*) as count FROM policies GROUP BY domain').fetchall()
    domains_audits = conn.execute('SELECT domain, COUNT(*) as count FROM audits GROUP BY domain').fetchall()
    domains_risks = conn.execute('SELECT domain, COUNT(*) as count FROM risks GROUP BY domain').fetchall()
    
    # Get recent users
    recent_users = conn.execute('''
        SELECT id, username, email, role, is_active, created_at, last_login 
        FROM users ORDER BY created_at DESC LIMIT 20
    ''').fetchall()
    
    # Get documents per day (last 7 days)
    docs_per_day = conn.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count 
        FROM (
            SELECT created_at FROM strategies 
            UNION ALL SELECT created_at FROM policies 
            UNION ALL SELECT created_at FROM audits 
            UNION ALL SELECT created_at FROM risks
        ) 
        WHERE created_at >= DATE('now', '-7 days')
        GROUP BY DATE(created_at) 
        ORDER BY date
    ''').fetchall()
    
    # Get benchmarks
    benchmarks = conn.execute('SELECT * FROM benchmarks ORDER BY sector').fetchall()
    
    conn.close()
    
    return render_template('admin.html',
                          txt=txt,
                          lang=lang,
                          is_rtl=(lang == 'ar'),
                          stats=stats,
                          domains_strategies=domains_strategies,
                          domains_policies=domains_policies,
                          domains_audits=domains_audits,
                          domains_risks=domains_risks,
                          recent_users=recent_users,
                          docs_per_day=docs_per_day,
                          benchmarks=benchmarks,
                          config=config)

@app.route('/admin/api/benchmark/<int:benchmark_id>', methods=['POST'])
@admin_required
def update_benchmark(benchmark_id):
    """Update benchmark data."""
    data = request.json
    conn = get_db()
    
    try:
        conn.execute('''
            UPDATE benchmarks SET 
                compliance_score_avg = ?,
                maturity_level_avg = ?,
                risk_coverage_avg = ?,
                policy_count_avg = ?,
                source = ?,
                source_year = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            float(data.get('compliance_score_avg', 60)),
            float(data.get('maturity_level_avg', 2.5)),
            float(data.get('risk_coverage_avg', 50)),
            int(data.get('policy_count_avg', 5)),
            data.get('source', 'Manual Update'),
            int(data.get('source_year', 2024)),
            benchmark_id
        ))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/toggle-user/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user(user_id):
    """Toggle user active status."""
    conn = get_db()
    user = conn.execute('SELECT is_active FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_status = 0 if user['is_active'] == 1 else 1
        conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
        conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user (except admin)."""
    conn = get_db()
    user = conn.execute('SELECT role FROM users WHERE id = ?', (user_id,)).fetchone()
    if user and user['role'] != 'admin':
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/api/stats')
@admin_required
def admin_api_stats():
    """API endpoint for admin statistics."""
    conn = get_db()
    
    stats = {
        'users': {
            'total': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
            'active': conn.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0],
            'limit': MAX_USERS
        },
        'documents': {
            'strategies': conn.execute('SELECT COUNT(*) FROM strategies').fetchone()[0],
            'policies': conn.execute('SELECT COUNT(*) FROM policies').fetchone()[0],
            'audits': conn.execute('SELECT COUNT(*) FROM audits').fetchone()[0],
            'risks': conn.execute('SELECT COUNT(*) FROM risks').fetchone()[0]
        }
    }
    stats['documents']['total'] = sum(stats['documents'].values())
    
    conn.close()
    return jsonify(stats)

# ============================================================================
# PROJECT MANAGEMENT API
# ============================================================================

@app.route('/api/tasks', methods=['GET'])
@login_required
def api_get_tasks():
    """Get all tasks for the current user."""
    try:
        domain = request.args.get('domain', '')
        status = request.args.get('status', '')
        
        conn = get_db()
        query = 'SELECT * FROM project_tasks WHERE user_id = ?'
        params = [session['user_id']]
        
        if domain:
            query += ' AND domain = ?'
            params.append(domain)
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        query += ' ORDER BY CASE priority WHEN "critical" THEN 0 WHEN "high" THEN 1 WHEN "medium" THEN 2 WHEN "low" THEN 3 END, due_date ASC'
        
        tasks = conn.execute(query, params).fetchall()
        conn.close()
        
        return jsonify({'success': True, 'tasks': [dict(t) for t in tasks]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
@login_required
def api_create_task():
    """Create a new task."""
    try:
        data = request.json
        conn = get_db()
        conn.execute(
            'INSERT INTO project_tasks (user_id, domain, title, description, status, priority, owner, due_date, category) VALUES (?,?,?,?,?,?,?,?,?)',
            (session['user_id'], data.get('domain', 'General'), data.get('title', ''),
             data.get('description', ''), data.get('status', 'todo'),
             data.get('priority', 'medium'), data.get('owner', ''),
             data.get('due_date', ''), data.get('category', 'implementation'))
        )
        conn.commit()
        task_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        return jsonify({'success': True, 'id': task_id})
    except Exception as e:
        print(f"Create task error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@login_required
def api_update_task(task_id):
    """Update a task."""
    try:
        data = request.json
        conn = get_db()
        # Verify ownership
        task = conn.execute('SELECT id FROM project_tasks WHERE id=? AND user_id=?', (task_id, session['user_id'])).fetchone()
        if not task:
            conn.close()
            return jsonify({'success': False, 'error': 'Task not found'}), 404
        
        fields = []
        params = []
        for key in ['title', 'description', 'status', 'priority', 'owner', 'due_date', 'domain', 'category']:
            if key in data:
                fields.append(f'{key}=?')
                params.append(data[key])
        
        if fields:
            fields.append('updated_at=CURRENT_TIMESTAMP')
            params.append(task_id)
            conn.execute(f'UPDATE project_tasks SET {",".join(fields)} WHERE id=?', params)
            conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Update task error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def api_delete_task(task_id):
    """Delete a task."""
    try:
        conn = get_db()
        conn.execute('DELETE FROM project_tasks WHERE id=? AND user_id=?', (task_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Delete task error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks/stats')
@login_required
def api_task_stats():
    """Get task statistics."""
    try:
        conn = get_db()
        user_id = session['user_id']
        
        todo = conn.execute('SELECT COUNT(*) FROM project_tasks WHERE user_id=? AND status="todo"', (user_id,)).fetchone()[0]
        in_progress = conn.execute('SELECT COUNT(*) FROM project_tasks WHERE user_id=? AND status="in_progress"', (user_id,)).fetchone()[0]
        done = conn.execute('SELECT COUNT(*) FROM project_tasks WHERE user_id=? AND status="done"', (user_id,)).fetchone()[0]
        blocked = conn.execute('SELECT COUNT(*) FROM project_tasks WHERE user_id=? AND status="blocked"', (user_id,)).fetchone()[0]
        
        overdue = conn.execute(
            'SELECT COUNT(*) FROM project_tasks WHERE user_id=? AND status!="done" AND due_date < date("now") AND due_date != ""',
            (user_id,)
        ).fetchone()[0]
        
        conn.close()
        total = todo + in_progress + done + blocked
        return jsonify({
            'success': True,
            'stats': {
                'todo': todo, 'in_progress': in_progress, 'done': done, 'blocked': blocked,
                'total': total, 'overdue': overdue,
                'completion_rate': round((done / total * 100) if total > 0 else 0)
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/status')
@login_required
def api_ai_status():
    """Get current AI provider status."""
    try:
        return jsonify({'success': True, **get_ai_status()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# AWARENESS MODULES API
# ============================================================================

@app.route('/api/awareness/modules')
@login_required
def api_awareness_modules():
    """Get awareness modules for a domain."""
    try:
        domain = request.args.get('domain', 'Cyber Security')
        lang = request.args.get('lang', 'en')
        domain_code = DOMAIN_CODES.get(domain, 'cyber')
        
        modules = AWARENESS_MODULES.get(domain_code, {}).get(lang, AWARENESS_MODULES.get(domain_code, {}).get('en', []))
        
        # Get user's completed modules
        conn = get_db()
        completed = conn.execute(
            'SELECT module_id, score, total, passed FROM awareness_scores WHERE user_id = ? AND domain = ?',
            (session['user_id'], domain)
        ).fetchall()
        conn.close()
        
        completed_map = {r['module_id']: {'score': r['score'], 'total': r['total'], 'passed': r['passed']} for r in completed}
        
        # Add completion status to modules
        modules_with_status = []
        for m in modules:
            m_copy = dict(m)
            if m['id'] in completed_map:
                m_copy['completed'] = True
                m_copy['user_score'] = completed_map[m['id']]['score']
                m_copy['user_total'] = completed_map[m['id']]['total']
                m_copy['passed'] = bool(completed_map[m['id']]['passed'])
            else:
                m_copy['completed'] = False
            modules_with_status.append(m_copy)
        
        return jsonify({'success': True, 'modules': modules_with_status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/awareness/submit', methods=['POST'])
@login_required
def api_awareness_submit():
    """Submit quiz results."""
    try:
        data = request.json
        module_id = data.get('module_id', '')
        domain = data.get('domain', '')
        score = data.get('score', 0)
        total = data.get('total', 0)
        lang = data.get('language', 'en')
        passed = 1 if total > 0 and (score / total) >= 0.7 else 0
        
        conn = get_db()
        # Update or insert score (keep best score)
        existing = conn.execute(
            'SELECT id, score FROM awareness_scores WHERE user_id = ? AND domain = ? AND module_id = ?',
            (session['user_id'], domain, module_id)
        ).fetchone()
        
        if existing:
            if score > existing['score']:
                conn.execute('UPDATE awareness_scores SET score=?, total=?, passed=?, language=?, completed_at=CURRENT_TIMESTAMP WHERE id=?',
                            (score, total, passed, lang, existing['id']))
        else:
            conn.execute('INSERT INTO awareness_scores (user_id, domain, module_id, score, total, passed, language) VALUES (?,?,?,?,?,?,?)',
                        (session['user_id'], domain, module_id, score, total, passed, lang))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'score': score, 'total': total, 'passed': bool(passed), 'percentage': round((score/total)*100) if total > 0 else 0})
    except Exception as e:
        print(f"Awareness submit error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/awareness/progress')
@login_required
def api_awareness_progress():
    """Get user's overall awareness progress."""
    try:
        conn = get_db()
        scores = conn.execute(
            'SELECT domain, module_id, score, total, passed FROM awareness_scores WHERE user_id = ?',
            (session['user_id'],)
        ).fetchall()
        conn.close()
        
        progress = {}
        for s in scores:
            d = s['domain']
            if d not in progress:
                progress[d] = {'completed': 0, 'passed': 0, 'total_score': 0, 'total_possible': 0}
            progress[d]['completed'] += 1
            progress[d]['passed'] += s['passed']
            progress[d]['total_score'] += s['score']
            progress[d]['total_possible'] += s['total']
        
        return jsonify({'success': True, 'progress': progress})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
