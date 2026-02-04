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
app.secret_key = os.getenv('SECRET_KEY', 'mizan-grc-default-secret-key-change-in-production-2026')
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
    "cyber": [
        "NCA ECC (Essential Cybersecurity Controls)",
        "NCA CSCC (Critical Systems Cybersecurity Controls)", 
        "NCA DCC (Data Cybersecurity Controls)",
        "NCA OTCC (Operational Technology Cybersecurity Controls)",
        "NCA TCC (Telework Cybersecurity Controls)",
        "NCA OSMACC (Social Media Cybersecurity Controls)",
        "NCA CCC (Cloud Cybersecurity Controls)",
        "NCA NCS (National Cryptographic Standards)",
        "NCA CGIoT (Cybersecurity Guidelines for IoT)",
        "SAMA CSF",
        "ISO 27001:2022"
    ],
    "data": ["NDMO/SDAIA", "PDPL", "GDPR", "NCA DCC", "DGA Standards"],
    "ai": ["SDAIA AI Ethics", "NIST AI RMF", "EU AI Act", "ISO 42001"],
    "dt": ["DGA Digital Policy", "COBIT 2019", "TOGAF", "ITIL 4"],
    "global": ["ISO 27001:2022", "ISO 22301", "NIST CSF 2.0", "ISO 9001", "ISO 31000"],
    "erm": [
        "ISO 31000:2018 (Risk Management)",
        "COSO ERM Framework (2017)",
        "IRM Risk Management Standard",
        "AS/NZS 4360",
        "ISO 31010 (Risk Assessment Techniques)",
        "Basel III/IV",
        "Solvency II",
        "NIST RMF (SP 800-37)",
        "King IV (Corporate Governance)",
        "FERMA Risk Management Standard"
    ]
}

# Domain-specific foundational technologies/controls
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
    """Check if OpenAI API is available."""
    return bool(config.OPENAI_API_KEY)

def generate_ai_content(prompt, language='en'):
    """Generate content using OpenAI API."""
    print(f"DEBUG: generate_ai_content called, API key present: {bool(config.OPENAI_API_KEY)}", flush=True)
    
    if not config.OPENAI_API_KEY:
        print("DEBUG: No API key, using simulation", flush=True)
        return generate_simulation_content(prompt, language)
    
    try:
        import openai
        client = openai.OpenAI(api_key=config.OPENAI_API_KEY)
        
        system_prompt = "You are an expert GRC consultant. Provide professional, detailed responses."
        if language == 'ar':
            system_prompt = "أنت مستشار خبير في الحوكمة والمخاطر والامتثال. قدم ردوداً مهنية ومفصلة باللغة العربية."
        
        print(f"DEBUG: Calling OpenAI API...", flush=True)
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000,
            temperature=0.7
        )
        
        print(f"DEBUG: OpenAI API success, response length: {len(response.choices[0].message.content)}", flush=True)
        return response.choices[0].message.content
    except Exception as e:
        print(f"DEBUG: AI Error - falling back to simulation: {e}", flush=True)
        return generate_simulation_content(prompt, language)

def generate_simulation_content(prompt, language='en'):
    """Generate simulated content when AI is unavailable - detects content type from prompt."""
    prompt_lower = prompt.lower()
    
    # Detect content type from prompt - check most specific patterns first
    # Strategy has specific markers like "6 separate sections", "Vision & Objectives", "[SECTION]"
    if '[section]' in prompt_lower or '6 separate sections' in prompt_lower or 'vision & objective' in prompt_lower or 'الرؤية والأهداف' in prompt_lower or 'استراتيجية شاملة' in prompt_lower:
        return generate_strategy_simulation(language)
    elif ('rewrite' in prompt_lower and 'policy' in prompt_lower) or ('modify' in prompt_lower and 'policy' in prompt_lower) or ('أعد كتابة' in prompt_lower and 'سياسة' in prompt_lower) or 'review findings' in prompt_lower or 'نتائج المراجعة' in prompt_lower:
        # Policy modification based on review - return a modified policy simulation
        return generate_policy_simulation(language)
    elif ('review' in prompt_lower and 'policy' in prompt_lower) or ('مراجعة' in prompt_lower and 'سياسة' in prompt_lower):
        return generate_policy_simulation(language)
    elif 'policy' in prompt_lower or 'سياسة' in prompt_lower:
        return generate_policy_simulation(language)
    elif 'audit' in prompt_lower or 'تدقيق' in prompt_lower:
        return generate_audit_simulation(language)
    elif 'analyze' in prompt_lower and 'risk' in prompt_lower or 'حلل' in prompt_lower and 'خطر' in prompt_lower:
        return generate_risk_simulation(language)
    else:
        # Default to strategy
        return generate_strategy_simulation(language)

def generate_strategy_simulation(language='en'):
    """Generate strategy simulation content."""
    if language == 'ar':
        return """## 1. الرؤية والأهداف

**الرؤية:**
تأسيس المنظمة كنموذج للتميز في الأمن السيبراني في القطاع الحكومي، مع تحقيق أعلى معايير الحوكمة والامتثال وحماية الأصول الرقمية.

### الأهداف الاستراتيجية:
| # | الهدف | المؤشر المستهدف | الإطار الزمني |
|---|-------|----------------|---------------|
| 1 | تحقيق الامتثال الكامل للأطر التنظيمية | امتثال > 95% | خلال 12 شهر |
| 2 | تعزيز قدرات الكشف والاستجابة | تقليل وقت الاستجابة 50% | خلال 18 شهر |
| 3 | تطوير برنامج توعية شامل | تغطية 100% من الموظفين | خلال 6 أشهر |
| 4 | تنفيذ تقنيات أمنية متقدمة | نشر SIEM و EDR | خلال 12 شهر |
| 5 | إنشاء فريق استجابة مركزي | فريق عمل 24/7 | خلال 9 أشهر |

[SECTION]

## 2. تحليل الفجوات

| # | الفجوة | الوصف | الأولوية |
|---|--------|-------|----------|
| 1 | فجوة السياسات | الحاجة لتحديث السياسات لتتوافق مع المتطلبات التنظيمية | عالية |
| 2 | فجوة التقنية | نقص في أدوات SIEM و EDR ومراقبة الشبكة | عالية |
| 3 | فجوة التدريب | برامج توعية غير كافية للموظفين | متوسطة |
| 4 | فجوة الاستجابة | خطة استجابة للحوادث غير مكتملة | عالية |
| 5 | فجوة البيانات | ضوابط حماية البيانات تحتاج تعزيز | متوسطة |

[SECTION]

## 3. الركائز الاستراتيجية

### الركيزة 1: الامتثال والحوكمة
• تطوير إطار شامل لإدارة الامتثال
• إنشاء فريق مراقبة مستمرة
• تحديث السياسات والإجراءات بشكل دوري

### الركيزة 2: التقنية والابتكار
• نشر أدوات الأمان المتقدمة (SIEM, EDR, NDR)
• تنفيذ حلول حماية البيانات والتشفير
• تطبيق المصادقة متعددة العوامل

### الركيزة 3: تمكين القوى العاملة
• برنامج تدريب مستمر لجميع المستويات
• شهر التوعية السيبرانية السنوي
• شهادات مهنية للفريق التقني

### الركيزة 4: إدارة الحوادث
• فريق استجابة مركزي يعمل على مدار الساعة
• تمارين محاكاة ربع سنوية
• خطة تعافي من الكوارث محدثة

[SECTION]

## 4. خارطة الطريق

### المرحلة 1 (0-6 أشهر)
| # | النشاط | المسؤول | الموعد |
|---|--------|---------|--------|
| 1 | مراجعة السياسات وتحليل الفجوات | أمن المعلومات | الشهر 2 |
| 2 | بدء برامج التدريب الأساسية | الموارد البشرية | الشهر 3 |
| 3 | اختيار ونشر حلول SIEM | تقنية المعلومات | الشهر 6 |

### المرحلة 2 (6-12 شهر)
| # | النشاط | المسؤول | الموعد |
|---|--------|---------|--------|
| 1 | استكمال تحديث السياسات | أمن المعلومات | الشهر 8 |
| 2 | توسيع التدريب لجميع الأقسام | الموارد البشرية | الشهر 10 |
| 3 | إنشاء فريق الاستجابة للحوادث | أمن المعلومات | الشهر 12 |

### المرحلة 3 (12-24 شهر)
| # | النشاط | المسؤول | الموعد |
|---|--------|---------|--------|
| 1 | تعزيز حماية البيانات | تقنية المعلومات | الشهر 18 |
| 2 | تدقيقات منتظمة | التدقيق الداخلي | مستمر |
| 3 | تقييم فعالية البرامج | أمن المعلومات | الشهر 24 |

[SECTION]

## 5. مؤشرات الأداء الرئيسية

| # | المؤشر | القيمة الحالية | القيمة المستهدفة | الإطار الزمني |
|---|--------|---------------|-----------------|---------------|
| 1 | نسبة الامتثال | 65% | > 95% | خلال 12 شهر |
| 2 | وقت الاستجابة للحوادث | 4 ساعات | < 1 ساعة | خلال 12 شهر |
| 3 | معدل إكمال التدريب | 40% | > 90% | خلال 6 أشهر |
| 4 | تقليل الحوادث الناجحة | - | 40% | خلال 18 شهر |
| 5 | معدل نجاح التدقيق | 70% | > 95% | خلال 12 شهر |
| 6 | تشفير البيانات الحساسة | 50% | 100% | خلال 12 شهر |
| 7 | تغطية MFA | 30% | 100% | خلال 6 أشهر |
| 8 | تقليل الإيجابيات الكاذبة | - | 50% | خلال 18 شهر |

[SECTION]

## 6. تقييم الثقة والمخاطر

**درجة الثقة:** 75% - بناءً على توفر الموارد والدعم التنفيذي

### المخاطر الرئيسية:
| # | الخطر | الاحتمالية | الأثر | خطة التخفيف |
|---|-------|-----------|-------|-------------|
| 1 | مقاومة التغيير | متوسطة | عالي | برامج إدارة التغيير والتواصل |
| 2 | قيود الميزانية | عالية | عالي | التنفيذ المرحلي وترتيب الأولويات |
| 3 | نقص المهارات | متوسطة | متوسط | التدريب المكثف والتوظيف |
| 4 | تعقيد التكامل | متوسطة | متوسط | التخطيط الدقيق والاختبار |
| 5 | تطور التهديدات | عالية | عالي | المراقبة المستمرة والتحديث |"""
    else:
        return """## 1. Vision & Objectives

**Vision:**
Establish the organization as a model of cybersecurity excellence in the government sector, achieving the highest standards of governance, compliance, and digital asset protection.

### Strategic Objectives:
| # | Objective | Target Metric | Timeframe |
|---|-----------|---------------|-----------|
| 1 | Achieve full compliance with regulatory frameworks | Compliance > 95% | Within 12 months |
| 2 | Enhance detection and response capabilities | Reduce response time 50% | Within 18 months |
| 3 | Develop comprehensive awareness program | 100% employee coverage | Within 6 months |
| 4 | Implement advanced security technologies | Deploy SIEM & EDR | Within 12 months |
| 5 | Establish centralized incident response team | 24/7 operations | Within 9 months |

[SECTION]

## 2. Gap Analysis

| # | Gap | Description | Priority |
|---|-----|-------------|----------|
| 1 | Policy Gap | Need to update policies to meet regulatory requirements | High |
| 2 | Technology Gap | Lack of SIEM, EDR, and network monitoring tools | High |
| 3 | Training Gap | Insufficient awareness programs for employees | Medium |
| 4 | Response Gap | Incomplete incident response plan | High |
| 5 | Data Gap | Data protection controls need strengthening | Medium |

[SECTION]

## 3. Strategic Pillars

### Pillar 1: Compliance & Governance
• Develop comprehensive compliance management framework
• Establish continuous monitoring team
• Regular policy and procedure updates

### Pillar 2: Technology & Innovation
• Deploy advanced security tools (SIEM, EDR, NDR)
• Implement data protection and encryption solutions
• Enable multi-factor authentication

### Pillar 3: Workforce Empowerment
• Continuous training program for all levels
• Annual cyber awareness month
• Professional certifications for technical team

### Pillar 4: Incident Management
• 24/7 centralized response team
• Quarterly simulation exercises
• Updated disaster recovery plan

[SECTION]

## 4. Implementation Roadmap

### Phase 1 (0-6 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | Policy review and gap analysis | InfoSec | Month 2 |
| 2 | Begin basic training programs | HR | Month 3 |
| 3 | Select and deploy SIEM solutions | IT | Month 6 |

### Phase 2 (6-12 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | Complete policy updates | InfoSec | Month 8 |
| 2 | Expand training across departments | HR | Month 10 |
| 3 | Establish incident response team | InfoSec | Month 12 |

### Phase 3 (12-24 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | Enhance data protection | IT | Month 18 |
| 2 | Regular audits | Internal Audit | Ongoing |
| 3 | Evaluate program effectiveness | InfoSec | Month 24 |

[SECTION]

## 5. Key Performance Indicators

| # | KPI | Current Value | Target Value | Timeframe |
|---|-----|---------------|--------------|-----------|
| 1 | Compliance rate | 65% | > 95% | Within 12 months |
| 2 | Incident response time | 4 hours | < 1 hour | Within 12 months |
| 3 | Training completion rate | 40% | > 90% | Within 6 months |
| 4 | Successful attack reduction | - | 40% | Within 18 months |
| 5 | Audit pass rate | 70% | > 95% | Within 12 months |
| 6 | Sensitive data encryption | 50% | 100% | Within 12 months |
| 7 | MFA coverage | 30% | 100% | Within 6 months |
| 8 | False positive reduction | - | 50% | Within 18 months |

[SECTION]

## 6. Confidence Assessment & Risks

**Confidence Score:** 75% - Based on resource availability and executive support

### Key Risks:
| # | Risk | Likelihood | Impact | Mitigation Plan |
|---|------|------------|--------|-----------------|
| 1 | Resistance to change | Medium | High | Change management and communication programs |
| 2 | Budget constraints | High | High | Phased implementation and prioritization |
| 3 | Skills shortage | Medium | Medium | Intensive training and recruitment |
| 4 | Integration complexity | Medium | Medium | Careful planning and testing |
| 5 | Evolving threats | High | High | Continuous monitoring and updates |"""

def generate_policy_simulation(language='en'):
    """Generate policy simulation content."""
    if language == 'ar':
        return """# سياسة أمن المعلومات

## 1. الغرض
تهدف هذه السياسة إلى وضع إطار شامل لحماية أصول المعلومات في المنظمة وضمان سرية وسلامة وتوافر البيانات.

## 2. النطاق
تنطبق هذه السياسة على:
- جميع الموظفين والمتعاقدين والشركاء
- جميع أنظمة المعلومات والبنية التحتية
- جميع البيانات المعالجة والمخزنة والمنقولة

## 3. بنود السياسة

### 3.1 التحكم في الوصول
- يجب تطبيق مبدأ الحد الأدنى من الصلاحيات
- مراجعة صلاحيات الوصول كل 90 يوماً
- تفعيل المصادقة متعددة العوامل للأنظمة الحساسة

### 3.2 حماية البيانات
- تصنيف جميع البيانات حسب مستوى الحساسية
- تشفير البيانات الحساسة أثناء النقل والتخزين
- النسخ الاحتياطي اليومي للبيانات الهامة

### 3.3 إدارة الحوادث
- الإبلاغ الفوري عن أي حادث أمني
- تفعيل خطة الاستجابة للحوادث خلال ساعة واحدة
- توثيق جميع الحوادث والدروس المستفادة

### 3.4 التوعية والتدريب
- تدريب أمني إلزامي سنوي لجميع الموظفين
- تمارين محاكاة التصيد الاحتيالي ربع سنوية
- تحديثات أمنية شهرية

## 4. الأدوار والمسؤوليات

| الدور | المسؤوليات |
|-------|-----------|
| مدير أمن المعلومات | الإشراف العام على تنفيذ السياسة |
| مديرو الأقسام | ضمان التزام فرقهم بالسياسة |
| جميع الموظفين | الالتزام بالسياسة والإبلاغ عن الحوادث |

## 5. متطلبات الامتثال
- الامتثال للوائح الهيئة الوطنية للأمن السيبراني
- الالتزام بمعايير ISO 27001
- مراجعة داخلية ربع سنوية

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
**المالك:** إدارة أمن المعلومات
**المراجعة القادمة:** خلال سنة"""
    else:
        return """# Information Security Policy

## 1. Purpose
This policy establishes a comprehensive framework for protecting the organization's information assets and ensuring the confidentiality, integrity, and availability of data.

## 2. Scope
This policy applies to:
- All employees, contractors, and partners
- All information systems and infrastructure
- All data processed, stored, and transmitted

## 3. Policy Statements

### 3.1 Access Control
- Principle of least privilege must be applied
- Access rights reviewed every 90 days
- Multi-factor authentication required for sensitive systems

### 3.2 Data Protection
- All data classified by sensitivity level
- Sensitive data encrypted in transit and at rest
- Daily backups of critical data

### 3.3 Incident Management
- Immediate reporting of any security incident
- Incident response plan activated within 1 hour
- All incidents documented with lessons learned

### 3.4 Awareness & Training
- Annual mandatory security training for all staff
- Quarterly phishing simulation exercises
- Monthly security updates

## 4. Roles & Responsibilities

| Role | Responsibilities |
|------|-----------------|
| CISO | Overall oversight of policy implementation |
| Department Managers | Ensure team compliance with policy |
| All Employees | Comply with policy and report incidents |

## 5. Compliance Requirements
- Compliance with NCA regulations
- Adherence to ISO 27001 standards
- Quarterly internal reviews

## 6. Review & Update
- Policy reviewed annually or upon significant changes
- Updates approved by governance committee
- All stakeholders notified of changes

## 7. Enforcement
Non-compliance may result in:
- Disciplinary action
- Contract termination
- Legal proceedings

---
**Issue Date:** [To be added upon approval]
**Version:** 1.0
**Owner:** Information Security Department
**Next Review:** Within 1 year"""

def generate_audit_simulation(language='en'):
    """Generate audit simulation content."""
    if language == 'ar':
        return """# تقرير التدقيق

## الملخص التنفيذي
أجري هذا التدقيق لتقييم مدى امتثال المنظمة للأطر التنظيمية المعتمدة. يغطي التقرير الفترة من [تاريخ البداية] إلى [تاريخ النهاية].

**النتيجة العامة:** امتثال جزئي (72%)

## نطاق التدقيق
- مراجعة السياسات والإجراءات
- تقييم الضوابط التقنية
- فحص سجلات الوصول
- مقابلات مع الموظفين الرئيسيين

## منهجية التدقيق
1. جمع الأدلة والوثائق
2. تحليل الفجوات
3. اختبار الضوابط
4. تقييم المخاطر
5. إعداد التوصيات

## النتائج والملاحظات

### نتائج عالية الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية |
|---|----------|---------------|---------|
| 1 | عدم تفعيل MFA للأنظمة الحساسة | AC-2 | تفعيل فوري للمصادقة متعددة العوامل |
| 2 | سياسات كلمات المرور ضعيفة | IA-5 | تحديث متطلبات كلمات المرور |

### نتائج متوسطة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية |
|---|----------|---------------|---------|
| 3 | تأخر في تحديث الأنظمة | SI-2 | تطبيق جدول تحديث منتظم |
| 4 | نقص في التوثيق | PL-1 | تحديث الوثائق الفنية |

### نتائج منخفضة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية |
|---|----------|---------------|---------|
| 5 | تدريب غير مكتمل | AT-2 | استكمال برنامج التدريب |

## تقييم الامتثال

| المجال | نسبة الامتثال | التقييم |
|--------|--------------|---------|
| التحكم في الوصول | 65% | يحتاج تحسين |
| حماية البيانات | 78% | مقبول |
| إدارة الحوادث | 70% | يحتاج تحسين |
| التوعية والتدريب | 75% | مقبول |

## خطة العمل

| # | الإجراء | المسؤول | الموعد النهائي | الأولوية |
|---|--------|---------|---------------|----------|
| 1 | تفعيل MFA | فريق تقنية المعلومات | خلال 30 يوم | عالية |
| 2 | تحديث السياسات | أمن المعلومات | خلال 60 يوم | عالية |
| 3 | تحديث الأنظمة | فريق البنية التحتية | خلال 45 يوم | متوسطة |
| 4 | استكمال التدريب | الموارد البشرية | خلال 90 يوم | متوسطة |

---
**تاريخ التقرير:** [سيتم إضافته]
**التدقيق القادم:** خلال 6 أشهر"""
    else:
        return """# Audit Report

## Executive Summary
This audit was conducted to assess the organization's compliance with adopted regulatory frameworks. The report covers the period from [Start Date] to [End Date].

**Overall Result:** Partial Compliance (72%)

## Audit Scope
- Review of policies and procedures
- Assessment of technical controls
- Examination of access logs
- Interviews with key personnel

## Audit Methodology
1. Evidence and documentation collection
2. Gap analysis
3. Control testing
4. Risk assessment
5. Recommendations development

## Findings & Observations

### High-Risk Findings
| # | Observation | Affected Control | Recommendation |
|---|-------------|-----------------|----------------|
| 1 | MFA not enabled for sensitive systems | AC-2 | Immediate MFA implementation |
| 2 | Weak password policies | IA-5 | Update password requirements |

### Medium-Risk Findings
| # | Observation | Affected Control | Recommendation |
|---|-------------|-----------------|----------------|
| 3 | Delayed system updates | SI-2 | Implement regular update schedule |
| 4 | Documentation gaps | PL-1 | Update technical documentation |

### Low-Risk Findings
| # | Observation | Affected Control | Recommendation |
|---|-------------|-----------------|----------------|
| 5 | Incomplete training | AT-2 | Complete training program |

## Compliance Assessment

| Domain | Compliance Rate | Assessment |
|--------|----------------|------------|
| Access Control | 65% | Needs Improvement |
| Data Protection | 78% | Acceptable |
| Incident Management | 70% | Needs Improvement |
| Awareness & Training | 75% | Acceptable |

## Action Plan

| # | Action | Owner | Deadline | Priority |
|---|--------|-------|----------|----------|
| 1 | Enable MFA | IT Team | Within 30 days | High |
| 2 | Update policies | InfoSec | Within 60 days | High |
| 3 | System updates | Infrastructure | Within 45 days | Medium |
| 4 | Complete training | HR | Within 90 days | Medium |

---
**Report Date:** [To be added]
**Next Audit:** Within 6 months"""

def generate_risk_simulation(language='en'):
    """Generate risk analysis simulation content."""
    if language == 'ar':
        return """# تحليل المخاطر

## ملخص تقييم الخطر

| العنصر | القيمة |
|--------|-------|
| فئة الخطر | أمن المعلومات |
| الأصل المتأثر | البنية التحتية الحرجة |
| مستوى الخطر | **عالي** |
| درجة الخطر | 8.5/10 |

## تحليل التهديد
التهديد المحدد يمثل خطراً كبيراً على سرية وسلامة البيانات. يمكن أن ينتج عن هجمات خارجية أو تهديدات داخلية.

### مصادر التهديد المحتملة:
- مهاجمون خارجيون (APT)
- تهديدات داخلية
- أخطاء بشرية
- فشل تقني

## تحليل الأثر

| نوع الأثر | الوصف | المستوى |
|----------|-------|---------|
| مالي | خسائر محتملة تتراوح بين 1-5 مليون ريال | عالي |
| تشغيلي | توقف الخدمات لمدة 24-72 ساعة | عالي |
| سمعة | تأثير سلبي على ثقة العملاء | متوسط |
| قانوني | غرامات تنظيمية محتملة | متوسط |

## تقييم الاحتمالية

| العامل | التقييم |
|--------|---------|
| تاريخ الحوادث السابقة | متوسط |
| تعقيد الهجوم | منخفض |
| توفر أدوات الاستغلال | عالي |
| **الاحتمالية الإجمالية** | **مرتفعة (75%)** |

## الضوابط الموصى بها

### ضوابط وقائية:
1. **تفعيل المصادقة متعددة العوامل**
   - الأولوية: عالية
   - الجدول الزمني: فوري
   - التكلفة المقدرة: 50,000 ريال

2. **تحديث أنظمة الكشف عن التهديدات**
   - الأولوية: عالية
   - الجدول الزمني: 30 يوم
   - التكلفة المقدرة: 200,000 ريال

3. **تدريب الموظفين على التوعية الأمنية**
   - الأولوية: متوسطة
   - الجدول الزمني: 60 يوم
   - التكلفة المقدرة: 30,000 ريال

### ضوابط كاشفة:
1. تفعيل مراقبة SIEM على مدار الساعة
2. تنبيهات آلية للأنشطة المشبوهة
3. مراجعة دورية لسجلات الوصول

### ضوابط تصحيحية:
1. خطة استجابة للحوادث محدثة
2. نسخ احتياطية يومية
3. إجراءات استعادة الكوارث

## الخطر المتبقي

| السيناريو | قبل الضوابط | بعد الضوابط |
|----------|------------|------------|
| مستوى الخطر | عالي (8.5) | متوسط (4.2) |
| الاحتمالية | 75% | 25% |
| الأثر المالي | 5 مليون | 1 مليون |

## التوصيات النهائية
1. تنفيذ الضوابط الموصى بها خلال 90 يوماً
2. إجراء اختبار اختراق بعد تطبيق الضوابط
3. مراجعة تقييم المخاطر كل 6 أشهر

---
**تاريخ التقييم:** [سيتم إضافته]
**المراجعة القادمة:** خلال 6 أشهر"""
    else:
        return """# Risk Analysis

## Risk Assessment Summary

| Element | Value |
|---------|-------|
| Risk Category | Information Security |
| Affected Asset | Critical Infrastructure |
| Risk Level | **High** |
| Risk Score | 8.5/10 |

## Threat Analysis
The identified threat poses a significant risk to data confidentiality and integrity. It may result from external attacks or internal threats.

### Potential Threat Sources:
- External attackers (APT)
- Insider threats
- Human error
- Technical failure

## Impact Analysis

| Impact Type | Description | Level |
|-------------|-------------|-------|
| Financial | Potential losses of $1-5 million | High |
| Operational | Service disruption for 24-72 hours | High |
| Reputational | Negative impact on customer trust | Medium |
| Legal | Potential regulatory fines | Medium |

## Likelihood Assessment

| Factor | Assessment |
|--------|------------|
| Historical incident data | Medium |
| Attack complexity | Low |
| Availability of exploit tools | High |
| **Overall Likelihood** | **High (75%)** |

## Recommended Controls

### Preventive Controls:
1. **Enable Multi-Factor Authentication**
   - Priority: High
   - Timeline: Immediate
   - Estimated Cost: $15,000

2. **Update Threat Detection Systems**
   - Priority: High
   - Timeline: 30 days
   - Estimated Cost: $50,000

3. **Employee Security Awareness Training**
   - Priority: Medium
   - Timeline: 60 days
   - Estimated Cost: $10,000

### Detective Controls:
1. Enable 24/7 SIEM monitoring
2. Automated alerts for suspicious activities
3. Periodic access log reviews

### Corrective Controls:
1. Updated incident response plan
2. Daily backups
3. Disaster recovery procedures

## Residual Risk

| Scenario | Before Controls | After Controls |
|----------|-----------------|----------------|
| Risk Level | High (8.5) | Medium (4.2) |
| Likelihood | 75% | 25% |
| Financial Impact | $5M | $1M |

## Final Recommendations
1. Implement recommended controls within 90 days
2. Conduct penetration testing after control implementation
3. Review risk assessment every 6 months

---
**Assessment Date:** [To be added]
**Next Review:** Within 6 months"""

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
    
    conn.close()
    
    return render_template('profile.html',
                          txt=txt, lang=lang, config=config,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          user=user,
                          domain_stats=domain_stats,
                          total_docs=total_docs,
                          ai_available=check_ai_available(),
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
    frameworks = DOMAIN_FRAMEWORKS.get(domain_code, [])
    
    # Get domain-specific technologies
    lang_key = 'ar' if lang == 'ar' else 'en'
    technologies = DOMAIN_TECHNOLOGIES.get(domain_code, {}).get(lang_key, {})
    
    # Get risk categories with scenarios
    risk_data = RISK_CATEGORIES.get(domain_code, {}).get(lang_key, {})
    
    # Get user's remaining usage FOR THIS DOMAIN
    usage_info = get_remaining_usage(session['user_id'], domain_name)
    
    return render_template('domain.html',
                          txt=txt,
                          lang=lang,
                          config=config,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          ai_available=check_ai_available(),
                          domain_name=domain_name,
                          domain_code=domain_code,
                          frameworks=frameworks,
                          technologies=technologies,
                          risk_categories=risk_data,
                          usage_info=usage_info,
                          usage_limits=USAGE_LIMITS)

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
                          has_data=has_data)

@app.route('/api/analytics/benchmark/<sector>')
@login_required
def api_get_benchmark(sector):
    """Get benchmark comparison for a sector."""
    user_id = session['user_id']
    comparison = get_benchmark_comparison(user_id, sector)
    if comparison:
        return jsonify({'success': True, 'data': comparison})
    return jsonify({'success': False, 'error': 'Sector not found'}), 404

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
            
            prompt = f"""أنت مستشار خبير ومعتمد في الحوكمة والمخاطر والامتثال (GRC) مع خبرة واسعة في المملكة العربية السعودية ودول الخليج.

مهمتك: إنشاء وثيقة استراتيجية شاملة واحترافية في مجال **{domain_desc}** بتنسيق Markdown.

⚠️ تنبيه مهم جداً: هذه الاستراتيجية يجب أن تكون مخصصة ومركزة بالكامل على مجال "{domain}" فقط. لا تخلط مع مجالات أخرى.

تعليمات صارمة:
1. لا تستخدم أي تواريخ محددة (مثل 2024، 2025). استخدم أطر زمنية نسبية فقط (خلال 6 أشهر، السنة الأولى).
2. لا تستخدم أي أسماء أشخاص وهمية.
3. ركز جميع الأهداف والمبادرات والمخاطر على مجال {domain} تحديداً.
4. استخدم مصطلحات عربية احترافية خاصة بمجال {domain}.
5. ⚠️ لا تفترض أي قيم أو نسب أو درجات حالية للمنظمة. القيم الحالية يجب أن تكون "يُحدد من قبل المنظمة" أو "يتطلب تقييم ميداني". فقط القيم المستهدفة يمكن تحديدها مع تقديم مبرر واضح يستند إلى معايير الصناعة أو أفضل الممارسات.
6. كل نسبة مئوية أو رقم أو تقييم يجب أن يكون مدعوماً بمرجع واضح (معيار دولي، أفضل ممارسات، أو منطق تحليلي).

معلومات المنظمة:
- اسم المنظمة: {data.get('org_name', 'المنظمة')}
- القطاع: {data.get('sector', 'حكومي')}
- **المجال المستهدف: {domain}**
- حجم المنظمة: {data.get('size', 'متوسط')}
- نطاق الميزانية: {data.get('budget', '1-5 مليون ريال')}
- الأطر التنظيمية المستهدفة: {frameworks_list}
- الهيكل التنظيمي الحالي: {org_structure}
- التقنيات والأدوات المطبقة: {tech_list}
- مستوى النضج الحالي: {maturity}
- التحديات الرئيسية: {data.get('challenges', 'غير محدد')}

اكتب 6 أقسام منفصلة ومفصلة خاصة بمجال {domain}. استخدم [SECTION] كفاصل بين كل قسم.

قواعد التنسيق الصارمة - يجب اتباعها بالضبط:
1. ابدأ كل قسم رئيسي بـ ## (مثال: ## 1. الرؤية والأهداف)
2. استخدم ### لكل عنوان فرعي وقبل كل جدول
3. كل جدول يجب أن يسبقه عنوان بـ ###
4. استخدم النقاط (•) للمبادرات والتوصيات
5. قدم محتوى غني ومفصل في كل قسم

اتبع هذا التنسيق بالضبط:

## 1. الرؤية والأهداف

**الرؤية الاستراتيجية:**
[فقرة شاملة تصف الرؤية طويلة المدى للمنظمة في مجال الأمن السيبراني والحوكمة، مع ربطها برؤية المملكة 2030]

**المبررات الاستراتيجية:**
[فقرة توضح أهمية هذه الاستراتيجية والدوافع الرئيسية]

### الأهداف الاستراتيجية:
| # | الهدف الاستراتيجي | المؤشر المستهدف | الإطار الزمني | الارتباط بالإطار التنظيمي |
|---|------------------|----------------|---------------|--------------------------|
| 1 | [هدف محدد وقابل للقياس] | [مؤشر كمي واضح] | خلال X شهر | [رمز الضابط] |
| 2 | [هدف محدد وقابل للقياس] | [مؤشر كمي واضح] | خلال X شهر | [رمز الضابط] |
(6-8 أهداف استراتيجية شاملة)

[SECTION]

## 2. تحليل الفجوات

**منهجية التقييم:**
[فقرة توضح منهجية تحليل الفجوات المستخدمة]

### الفجوات المحددة:
| # | الفجوة | الوصف التفصيلي | الأثر المحتمل | الأولوية | الضابط المرتبط |
|---|--------|----------------|--------------|----------|---------------|
| 1 | [اسم الفجوة] | [وصف شامل للفجوة وأسبابها] | [الأثر على المنظمة] | عالية/متوسطة | [رمز الضابط] |
(5-6 فجوات رئيسية)

### ملخص التحليل:
[فقرة تلخص نتائج تحليل الفجوات والتوصيات الأولية]

[SECTION]

## 3. الركائز الاستراتيجية

### الركيزة 1: الحوكمة والقيادة
**الهدف:** تعزيز إطار الحوكمة المؤسسية للأمن السيبراني
• تطوير هيكل حوكمة واضح مع تحديد الأدوار والمسؤوليات
• إنشاء لجنة توجيهية للأمن السيبراني على مستوى الإدارة العليا
• تطوير سياسات وإجراءات شاملة ومتوافقة مع الأطر التنظيمية

### الركيزة 2: إدارة المخاطر
**الهدف:** تطبيق إطار متكامل لإدارة مخاطر الأمن السيبراني
• تنفيذ منهجية تقييم المخاطر بشكل دوري
• تطوير سجل مخاطر مركزي وآليات المراقبة المستمرة
• تعزيز قدرات الاستجابة للحوادث وإدارة الأزمات

### الركيزة 3: التقنية والبنية التحتية
**الهدف:** تحديث وتعزيز البنية التحتية الأمنية
• نشر حلول أمنية متقدمة (SIEM, EDR, NDR)
• تعزيز حماية الهوية والوصول (IAM, PAM, MFA)
• تطبيق أدوات الكشف والاستجابة الآلية

### الركيزة 4: الكفاءات والثقافة
**الهدف:** بناء ثقافة أمنية مستدامة وتطوير الكفاءات
• تنفيذ برنامج توعية وتدريب شامل للموظفين
• تطوير المهارات التقنية لفريق الأمن السيبراني
• استقطاب الكفاءات المتخصصة في المجالات الحرجة

[SECTION]

## 4. خارطة الطريق

### المرحلة 1: التأسيس (0-6 أشهر)
| # | النشاط | المسؤول | الموعد | المخرجات |
|---|--------|---------|--------|----------|
| 1 | [نشاط محدد] | [الجهة المسؤولة] | شهر X | [المخرج المتوقع] |
(4-5 أنشطة)

### المرحلة 2: البناء (6-12 شهر)
| # | النشاط | المسؤول | الموعد | المخرجات |
|---|--------|---------|--------|----------|
| 1 | [نشاط محدد] | [الجهة المسؤولة] | شهر X | [المخرج المتوقع] |
(4-5 أنشطة)

### المرحلة 3: التحسين والنضج (12-24 شهر)
| # | النشاط | المسؤول | الموعد | المخرجات |
|---|--------|---------|--------|----------|
| 1 | [نشاط محدد] | [الجهة المسؤولة] | شهر X | [المخرج المتوقع] |
(4-5 أنشطة)

[SECTION]

## 5. مؤشرات الأداء الرئيسية

**إطار القياس:**
[فقرة توضح منهجية قياس الأداء والمتابعة]

⚠️ تعليمات مهمة جداً لمؤشرات الأداء:
- عمود "القيمة الحالية" يجب أن يكون "يُحدد من قبل المنظمة" أو "يتطلب تقييم" - لا تفترض أي قيم حالية لأنها تعتمد على بيانات المنظمة الفعلية
- عمود "القيمة المستهدفة" يجب أن يكون واقعياً ومبرراً ومدعوماً بمعايير الصناعة أو أفضل الممارسات
- لا تختلق أي نسب أو أرقام أو درجات وهمية
- كل قيمة مستهدفة يجب أن تكون مدعومة بسبب واضح (مثل: "95% وفقاً لمعيار ISO 27001" أو "99.9% حسب معايير SLA المعتمدة")

### مؤشرات الأداء:
| # | المؤشر | الوصف | القيمة الحالية | القيمة المستهدفة | المبرر | الإطار الزمني | مصدر البيانات |
|---|--------|-------|---------------|-----------------|--------|---------------|--------------|
| 1 | [اسم المؤشر] | [وصف موجز] | يُحدد من قبل المنظمة | [قيمة مبررة] | [سبب اختيار القيمة المستهدفة] | خلال X شهر | [المصدر] |
(10-12 مؤشر أداء شامل)

[SECTION]

## 6. تقييم الثقة والمخاطر

**درجة الثقة:** [X]% 

⚠️ يجب أن تكون درجة الثقة مبنية على تحليل واقعي لعوامل محددة مثل: مستوى النضج الحالي، توفر الموارد، الدعم الإداري، وتعقيد التنفيذ. قدم تبريراً واضحاً لكل عامل.

**تبرير التقييم:**
[فقرة مفصلة توضح أساس تقييم درجة الثقة مع ذكر العوامل المحددة وتأثير كل عامل على الدرجة]

### المخاطر الاستراتيجية الرئيسية:
| # | الخطر | الوصف | الاحتمالية | الأثر | استراتيجية التخفيف |
|---|-------|-------|-----------|-------|-------------------|
| 1 | [الخطر] | عالية/متوسطة/منخفضة | عالي/متوسط/منخفض | [الإجراء] |
(4-5 مخاطر)"""
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
            
            prompt = f"""You are a GRC expert specializing in **{domain_desc}**.

Generate a professional strategy document in Markdown format that is SPECIFICALLY focused on the **{domain}** domain.

⚠️ CRITICAL: This strategy must be entirely focused on {domain}. Do NOT mix with other domains.

IMPORTANT RULES:
1. Current year is 2026. Use FUTURE dates (2027, 2028) or RELATIVE timeframes (Year 1, within 12 months).
2. Do NOT use any person names.
3. ALL objectives, initiatives, gaps, and risks must be specific to {domain}.
4. ⚠️ NEVER assume or fabricate current organizational values, scores, or percentages. Current values MUST be "To be assessed by organization" or "Requires baseline assessment". Only TARGET values may be specified, and each MUST be justified with a clear rationale based on industry standards or best practices.
5. Every percentage, score, or numeric value you produce must be supported by a clear reference (international standard, industry benchmark, or analytical reasoning).

Organization Info:
- Name: {data.get('org_name', 'Organization')}
- Sector: {data.get('sector', 'General')}
- **Target Domain: {domain}**
- Size: {data.get('size', 'Medium')}
- Budget: {data.get('budget', '1M-5M')}
- Frameworks: {frameworks_list}
- Current Structure: {org_structure}
- Technologies: {tech_list}
- Maturity: {maturity}
- Challenges: {data.get('challenges', 'Not specified')}

Write 6 separate sections specific to {domain}. Use [SECTION] as separator between each.

STRICT FORMATTING RULES - FOLLOW EXACTLY:
1. Use ## for main section headings ONLY
2. Use ### for subheadings BEFORE every table
3. Every table MUST be preceded by a ### heading
4. Use bullet points (•) for initiatives under pillars ONLY

Follow this EXACT format:

## 1. Vision & Objectives

**Vision:**
[One paragraph describing the strategic vision]

### Strategic Objectives:
| # | Objective | Target Metric | Timeframe |
|---|-----------|---------------|-----------|
| 1 | [Objective] | [Metric] | Within X months |
| 2 | [Objective] | [Metric] | Within X months |
(5-7 objectives)

[SECTION]

## 2. Gap Analysis

### Identified Gaps:
| # | Gap | Description | Priority |
|---|-----|-------------|----------|
| 1 | [Gap name] | [Detailed description] | High |
(4-5 gaps)

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

### Phase 1 (0-6 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | [Activity] | [Owner] | Month X |

### Phase 2 (6-12 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | [Activity] | [Owner] | Month X |

### Phase 3 (12-24 months)
| # | Activity | Owner | Timeline |
|---|----------|-------|----------|
| 1 | [Activity] | [Owner] | Month X |

[SECTION]

## 5. Key Performance Indicators

⚠️ CRITICAL RULES FOR KPIs:
- "Current Value" column MUST be "To be assessed by organization" or "Requires baseline assessment" - NEVER assume or fabricate current values since they depend on actual organizational data
- "Target Value" column MUST be realistic, justified, and supported by industry standards or best practices
- DO NOT invent any percentages, scores, or numbers without clear justification
- Every target value MUST include a clear rationale (e.g. "99.9% per industry SLA standards" or "95% aligned with ISO 27001 requirements")

### KPIs:
| # | KPI | Current Value | Target Value | Justification | Timeframe |
|---|-----|---------------|--------------|---------------|-----------|
| 1 | [KPI] | To be assessed | [Justified value] | [Why this target - cite standard or best practice] | Within X months |
(8-10 KPIs)

[SECTION]

## 6. Confidence Assessment & Risks

**Confidence Score:** [X]%

⚠️ The confidence score MUST be based on realistic analysis of specific factors such as: current maturity level, resource availability, executive support, and implementation complexity. Provide detailed justification for each factor.

**Score Justification:**
[Detailed paragraph explaining the basis for the confidence score, citing specific factors and their individual impact on the score]

### Key Risks:
| # | Risk | Likelihood | Impact | Mitigation Plan |
|---|------|------------|--------|-----------------|
| 1 | [Risk] | High/Medium/Low | High/Medium/Low | [Action] |
(4-5 risks)"""

        content = generate_ai_content(prompt, lang)
        
        import re  # Import at function level to ensure availability
        
        # Parse sections - split by separator
        parts = []
        
        if '[SECTION]' in content:
            parts = content.split('[SECTION]')
        elif '\n---\n' in content:
            parts = content.split('\n---\n')
        elif '---' in content:
            parts = content.split('---')
        else:
            parts = [content]
        
        # Clean parts
        parts = [p.strip() for p in parts if p.strip()]
        
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
            
            # Arabic section numbers (check original first_line, not lowercased)
            if 'الرؤية' in first_line or '1.' in first_line and 'الأهداف' in text[:200]:
                return 'vision'
            if 'تحليل الفجوات' in first_line or ('2.' in first_line and 'الفجوات' in text[:200]):
                return 'gaps'
            if 'الركائز' in first_line or ('3.' in first_line and 'الركائز' in text[:200]):
                return 'pillars'
            if 'خارطة' in first_line or ('4.' in first_line and 'المرحلة' in text[:300]):
                return 'roadmap'
            if 'مؤشرات' in first_line or ('5.' in first_line and 'مؤشر' in text[:200]):
                return 'kpis'
            if 'تقييم الثقة' in first_line or ('6.' in first_line and 'الثقة' in text[:200]):
                return 'confidence'
            
            # Fallback to keyword matching in full text
            keyword_scores = {
                'vision': ['vision', 'objective', 'mission', 'الرؤية', 'الأهداف', 'الاستراتيجية'],
                'gaps': ['gap analysis', 'identified gaps', 'الفجوة', 'الفجوات', 'تحليل'],
                'pillars': ['pillar', 'initiative', 'الركائز', 'المبادرات', 'الركيزة'],
                'roadmap': ['phase 1', 'roadmap', 'timeline', 'implementation', 'المرحلة', 'خارطة الطريق'],
                'kpis': ['kpi', 'key performance', 'indicator', 'مؤشر', 'مؤشرات الأداء'],
                'confidence': ['confidence score', 'confidence assessment', 'الثقة', 'تقييم الثقة', 'المخاطر الرئيسية']
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
        
        # If we couldn't identify sections, fall back to order-based assignment
        if len(assigned) < 3:
            print(f"DEBUG: Falling back to order-based assignment (only {len(assigned)} sections identified)", flush=True)
            section_order = ['vision', 'gaps', 'pillars', 'roadmap', 'kpis', 'confidence']
            for i, part in enumerate(parts[:6]):
                if i < len(section_order):
                    sections[section_order[i]] = part.strip()
                    print(f"DEBUG: Assigned part {i} to {section_order[i]}", flush=True)
        
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
            prompt = f"""أنشئ وثيقة سياسة {data.get('policy_name', 'أمن المعلومات')} احترافية بتنسيق Markdown بناءً على {data.get('framework', 'ISO 27001')}.

تعليمات صارمة ومهمة جداً:
1. لا تستخدم أي تواريخ محددة مطلقاً (مثل 2024، 2025، يناير، فبراير، إلخ)
2. لا تستخدم أي أسماء أشخاص
3. استخدم فقط عبارات نسبية مثل: "سنوياً"، "كل 90 يوم"، "خلال سنة"
4. للتواريخ استخدم: [سيتم إضافته عند الاعتماد]

استخدم التنسيق التالي:
# عنوان السياسة

## 1. الغرض
وصف الغرض من السياسة

## 2. النطاق
تنطبق هذه السياسة على:
- قائمة بالأطراف المعنية

## 3. بنود السياسة
### 3.1 العنوان الفرعي
- البنود

## 4. الأدوار والمسؤوليات
| الدور | المسؤوليات |
|-------|-----------|
| المسمى | الوصف |

## 5. متطلبات الامتثال
- المتطلبات

## 6. المراجعة والتحديث
- إجراءات المراجعة

## 7. العقوبات
- العقوبات على عدم الالتزام

---
**تاريخ الإصدار:** [سيتم إضافته عند الاعتماد]
**رقم الإصدار:** 1.0
**المالك:** [القسم المسؤول]"""
        else:
            prompt = f"""Generate a professional {data.get('policy_name', 'Information Security')} Policy document in Markdown format based on {data.get('framework', 'ISO 27001')}.

STRICT AND IMPORTANT INSTRUCTIONS:
1. Do NOT use any specific dates (like 2024, 2025, January, February, etc.)
2. Do NOT use any person names
3. Use ONLY relative timeframes like: "Annually", "Every 90 days", "Within 1 year"
4. For dates use: [To be added upon approval]

Use the following format:
# Policy Title

## 1. Purpose
Description of policy purpose

## 2. Scope
This policy applies to:
- List of stakeholders

## 3. Policy Statements
### 3.1 Subheading
- Policy items

## 4. Roles & Responsibilities
| Role | Responsibilities |
|------|-----------------|
| Title | Description |

## 5. Compliance Requirements
- Requirements

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
            prompt = f"""حلل سيناريو الخطر التالي بتنسيق Markdown احترافي:
الفئة: {data.get('category', 'عام')}
الأصل: {data.get('asset', 'النظام')}
التهديد: {data.get('threat', 'وصول غير مصرح')}

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
| فئة الخطر | [الفئة] |
| الأصل المتأثر | [الأصل] |
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
### ضوابط وقائية
1. الضابط - الأولوية - التكلفة

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
            prompt = f"""Analyze this risk scenario in professional Markdown format:
Category: {data.get('category', 'General')}
Asset: {data.get('asset', 'System')}
Threat: {data.get('threat', 'Unauthorized Access')}

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
| Risk Category | [Category] |
| Affected Asset | [Asset] |
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
### Preventive Controls
1. Control - Priority - Cost

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
        framework = request.form.get('framework', 'ISO 27001')
        audit_scope = request.form.get('audit_scope', 'full')
        
        # Handle file upload
        evidence_files = request.files.getlist('evidence')
        evidence_info = []
        for f in evidence_files:
            if f and f.filename:
                evidence_info.append(f.filename)
        
        prompt = f"""Generate a comprehensive audit report in professional Markdown format for:
Framework: {framework}
Scope: {audit_scope}
Domain: {domain}
Evidence Documents: {', '.join(evidence_info) if evidence_info else 'No evidence provided'}

STRICT AND IMPORTANT INSTRUCTIONS:
1. Do NOT use any specific dates (like 2024, 2025, January, February, etc.)
2. Do NOT use any person names or auditor names
3. Use ONLY relative timeframes like: "Within 30 days", "Within 60 days", "Within 90 days"
4. For dates use: [To be added]
5. For audit period use: [Audit Period]

Use the following format:

# Audit Report

## Executive Summary
Brief overview of audit results with overall compliance percentage

## Audit Scope
- List of areas covered

## Audit Methodology
1. Numbered methodology steps

## Findings & Observations

### High-Risk Findings
| # | Observation | Affected Control | Recommendation |
|---|-------------|-----------------|----------------|
| 1 | Finding | Control ID | Action |

### Medium-Risk Findings
| # | Observation | Affected Control | Recommendation |
|---|-------------|-----------------|----------------|

### Low-Risk Findings
| # | Observation | Affected Control | Recommendation |
|---|-------------|-----------------|----------------|

## Compliance Assessment
| Domain | Compliance Rate | Assessment |
|--------|----------------|------------|
| Area | XX% | Status |

## Action Plan
| # | Action | Owner | Deadline | Priority |
|---|--------|-------|----------|----------|
| 1 | Action | Team | Date | High/Medium/Low |

---
**Report Date:** [To be added]
**Next Audit:** Within 6 months"""

        if lang == 'ar':
            prompt = f"""أنشئ تقرير تدقيق شامل بتنسيق Markdown احترافي لـ:
الإطار: {framework}
النطاق: {audit_scope}
المجال: {domain}
وثائق الإثبات: {', '.join(evidence_info) if evidence_info else 'لم يتم تقديم أدلة'}

تعليمات صارمة ومهمة جداً:
1. لا تستخدم أي تواريخ محددة مطلقاً (مثل 2024، 2025، يناير، فبراير، إلخ)
2. لا تستخدم أي أسماء أشخاص أو مدققين
3. استخدم فقط عبارات نسبية مثل: "خلال 30 يوم"، "خلال 60 يوم"، "خلال 90 يوم"
4. للتواريخ استخدم: [سيتم إضافته]
5. لفترة التدقيق استخدم: [فترة التدقيق]

استخدم التنسيق التالي:

# تقرير التدقيق

## الملخص التنفيذي
نظرة عامة موجزة على نتائج التدقيق مع نسبة الامتثال الإجمالية

## نطاق التدقيق
- قائمة بالمجالات المشمولة

## منهجية التدقيق
1. خطوات المنهجية مرقمة

## النتائج والملاحظات

### نتائج عالية الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية |
|---|----------|---------------|---------|
| 1 | الملاحظة | رمز الضابط | الإجراء |

### نتائج متوسطة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية |
|---|----------|---------------|---------|

### نتائج منخفضة الخطورة
| # | الملاحظة | الضابط المتأثر | التوصية |
|---|----------|---------------|---------|

## تقييم الامتثال
| المجال | نسبة الامتثال | التقييم |
|--------|--------------|---------|
| المجال | XX% | الحالة |

## خطة العمل
| # | الإجراء | المسؤول | الموعد النهائي | الأولوية |
|---|--------|---------|---------------|----------|
| 1 | الإجراء | الفريق | التاريخ | عالية/متوسطة/منخفضة |

---
**تاريخ التقرير:** [سيتم إضافته]
**التدقيق القادم:** خلال 6 أشهر"""

        content = generate_ai_content(prompt, lang)
        
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
            
            # Reverse columns for Arabic RTL
            if is_arabic:
                table_data = [row[::-1] for row in table_data]
            
            num_cols = len(table_data[0])
            table = doc.add_table(rows=len(table_data), cols=num_cols)
            try:
                table.style = 'Table Grid'
            except Exception:
                pass  # Style not available, use default
            
            # Set table RTL direction
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
                        run = p.add_run(raw_text + ' •')
                        set_rtl_paragraph(p)
                        p.paragraph_format.right_indent = Cm(1)
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
                        run = p.add_run(raw_text + '  .' + num)
                        set_rtl_paragraph(p)
                        p.paragraph_format.right_indent = Cm(1)
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
                def reshape(text):
                    return text
                arabic_reshaper = type('obj', (object,), {'reshape': reshape})()
        
        # Calculate available text width for manual line wrapping
        page_width = A4[0]
        text_width = page_width - 3*cm  # 1.5cm margin each side
        
        def process_arabic(text, font_name_for_wrap=None, font_size_for_wrap=11, extra_indent=0):
            """Process Arabic text for correct display in PDF.
            
            Strategy: reshape → manual word-wrap → get_display per line → join with <br/>
            This prevents the jumbled word order that happens when get_display is applied
            to an entire paragraph and then ReportLab re-wraps it.
            """
            if is_arabic and text:
                try:
                    text = str(text).strip()
                    if not text:
                        return text
                    
                    from reportlab.pdfbase.pdfmetrics import stringWidth
                    wrap_font = font_name_for_wrap or arabic_font_name
                    # Use full available width — let ReportLab handle final layout
                    # We wrap generously so our line breaks match what ReportLab would do
                    wrap_width = text_width - extra_indent
                    
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
                            # This line is full — apply get_display and save
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
                    
                    # For narrow cells, wrap per-line
                    words = reshaped.split(' ')
                    lines = []
                    current_line_words = []
                    current_width = 0
                    space_width = stringWidth(' ', arabic_font_name, font_size)
                    cell_width = col_width - 12  # subtract padding
                    
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
                    
                    # Calculate column widths - give more space for Arabic text
                    available_width = doc.width
                    if col_count >= 7:
                        narrow_col = 0.4 * inch
                        remaining = available_width - narrow_col
                        other_cols = remaining / (col_count - 1)
                        if is_arabic:
                            col_widths = [other_cols] * (col_count - 1) + [narrow_col]
                        else:
                            col_widths = [narrow_col] + [other_cols] * (col_count - 1)
                    elif col_count >= 4:
                        narrow_col = 0.45 * inch
                        remaining = available_width - narrow_col
                        other_cols = remaining / (col_count - 1)
                        if is_arabic:
                            col_widths = [other_cols] * (col_count - 1) + [narrow_col]
                        else:
                            col_widths = [narrow_col] + [other_cols] * (col_count - 1)
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
def api_generate_excel():
    """Generate Excel file from data."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    import io
    
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

# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard with statistics."""
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
# MAIN
# ============================================================================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
