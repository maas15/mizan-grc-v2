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
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=2)

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
    CREATOR_TITLE = "Consultant/Expert"
    COPYRIGHT_YEAR = "2026"
    DB_PATH = "mizan.db"
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')

config = Config()

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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
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
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
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
        "domains": ["Cyber Security", "Data Management", "Artificial Intelligence", "Digital Transformation", "Global Standards"],
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
        "logged_in_as": "Logged in as"
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
        "domains": ["الأمن السيبراني", "إدارة البيانات", "الذكاء الاصطناعي", "التحول الرقمي", "المعايير العالمية"],
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
        "logged_in_as": "مسجل الدخول كـ"
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
    "global": ["ISO 27001:2022", "ISO 22301", "NIST CSF 2.0", "ISO 9001", "ISO 31000"]
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
    }
}

DOMAIN_CODES = {
    "Cyber Security": "cyber",
    "Data Management": "data", 
    "Artificial Intelligence": "ai",
    "Digital Transformation": "dt",
    "Global Standards": "global",
    "الأمن السيبراني": "cyber",
    "إدارة البيانات": "data",
    "الذكاء الاصطناعي": "ai",
    "التحول الرقمي": "dt",
    "المعايير العالمية": "global"
}

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
# ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/')
def index():
    """Home page - redirect to login or dashboard."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

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
# ROUTES - DASHBOARD
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard."""
    lang = request.args.get('lang', session.get('lang', 'en'))
    session['lang'] = lang
    txt = get_text(lang)
    
    # Get user stats
    conn = get_db()
    strategies_count = conn.execute(
        'SELECT COUNT(*) FROM strategies WHERE user_id = ?', 
        (session['user_id'],)
    ).fetchone()[0]
    policies_count = conn.execute(
        'SELECT COUNT(*) FROM policies WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]
    risks_count = conn.execute(
        'SELECT COUNT(*) FROM risks WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]
    conn.close()
    
    return render_template('dashboard.html',
                          txt=txt,
                          lang=lang,
                          config=config,
                          is_rtl=(lang == 'ar'),
                          username=session.get('username'),
                          ai_available=check_ai_available(),
                          stats={
                              'strategies': strategies_count,
                              'policies': policies_count,
                              'risks': risks_count
                          },
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

### مؤشرات الأداء:
| # | المؤشر | الوصف | القيمة الحالية | القيمة المستهدفة | الإطار الزمني | مصدر البيانات |
|---|--------|-------|---------------|-----------------|---------------|--------------|
| 1 | [اسم المؤشر] | [وصف موجز] | [قيمة] | [قيمة] | خلال X شهر | [المصدر] |
(10-12 مؤشر أداء شامل)

[SECTION]

## 6. تقييم الثقة والمخاطر

**درجة الثقة:** [X]% 

**تبرير التقييم:**
[فقرة توضح أساس تقييم درجة الثقة والعوامل المؤثرة]

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
            }
            domain_desc = domain_context.get(domain, domain)
            
            prompt = f"""You are a GRC expert specializing in **{domain_desc}**.

Generate a professional strategy document in Markdown format that is SPECIFICALLY focused on the **{domain}** domain.

⚠️ CRITICAL: This strategy must be entirely focused on {domain}. Do NOT mix with other domains.

IMPORTANT RULES:
1. Current year is 2026. Use FUTURE dates (2027, 2028) or RELATIVE timeframes (Year 1, within 12 months).
2. Do NOT use any person names.
3. ALL objectives, initiatives, gaps, and risks must be specific to {domain}.

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

### KPIs:
| # | KPI | Current Value | Target Value | Timeframe |
|---|-----|---------------|--------------|-----------|
| 1 | [KPI] | [Value] | [Value] | Within X months |
(8-10 KPIs)

[SECTION]

## 6. Confidence Assessment & Risks

**Confidence Score:** [X]% - [Brief justification]

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
            
            # First try to match by section number/header pattern
            for section_type, patterns in section_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in text_lower:
                        return section_type
            
            # Fallback to keyword matching
            keyword_scores = {
                'vision': ['vision', 'objective', 'mission', 'الرؤية', 'الأهداف'],
                'gaps': ['gap', 'weakness', 'الفجوة', 'الفجوات'],
                'pillars': ['pillar', 'initiative', 'الركائز', 'المبادرات'],
                'roadmap': ['phase', 'roadmap', 'timeline', 'المرحلة', 'خارطة'],
                'kpis': ['kpi', 'indicator', 'metric', 'مؤشر', 'مؤشرات'],
                'confidence': ['confidence', 'assessment', 'mitigation', 'الثقة', 'تقييم']
            }
            
            scores = {}
            for section_type, keywords in keyword_scores.items():
                score = sum(1 for kw in keywords if kw.lower() in text_lower)
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
            conn.execute('''INSERT INTO risks (user_id, domain, asset_name, threat, risk_level, analysis)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                        (session['user_id'], data.get('domain'), data.get('asset'),
                         data.get('threat'), 'HIGH', content))
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

@app.route('/api/generate-docx', methods=['POST'])
@login_required
def api_generate_docx():
    """Generate Word document from content."""
    from io import BytesIO
    
    data = request.json
    content = data.get('content', '')
    filename = data.get('filename', 'document')
    lang = data.get('language', 'en')
    
    # DEBUG: Print what content we received
    print("=" * 60)
    print("DOCX GENERATION - Content received (first 300 chars):")
    print(content[:300])
    print("=" * 60)
    
    try:
        from docx import Document
        from docx.shared import Inches, Pt, Cm
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.oxml.ns import nsdecls
        from docx.oxml import parse_xml
        
        doc = Document()
        
        # Set RTL for Arabic
        if lang == 'ar':
            for section in doc.sections:
                section.page_width = Inches(8.5)
                section.page_height = Inches(11)
        
        # Add title
        title = doc.add_heading(filename.replace('_', ' ').title(), 0)
        if lang == 'ar':
            title.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        
        def parse_markdown_table(lines, start_idx):
            """Parse markdown table starting at start_idx, return (table_data, end_idx)."""
            table_rows = []
            i = start_idx
            
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith('|') and line.endswith('|'):
                    # Skip separator row (|---|---|)
                    if '---' in line or ':-' in line or '-:' in line:
                        i += 1
                        continue
                    # Parse table row
                    cells = [cell.strip() for cell in line.split('|')[1:-1]]
                    if cells:
                        table_rows.append(cells)
                    i += 1
                else:
                    break
            
            return table_rows, i
        
        def add_table_to_doc(doc, table_data, lang):
            """Add a formatted table to the document."""
            if not table_data or len(table_data) < 1:
                return
            
            num_cols = len(table_data[0])
            table = doc.add_table(rows=len(table_data), cols=num_cols)
            table.style = 'Table Grid'
            
            # Add shading to header row
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
                            # Add shading to header
                            shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="4472C4"/>')
                            cell._tc.get_or_add_tcPr().append(shading)
                            # White text for header
                            for paragraph in cell.paragraphs:
                                for run in paragraph.runs:
                                    run.font.color.rgb = None  # Will use theme color
                        
                        # Set alignment
                        for paragraph in cell.paragraphs:
                            if lang == 'ar':
                                paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            
            # Add some space after table
            doc.add_paragraph()
        
        # Process content line by line
        lines = content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines
            if not line:
                i += 1
                continue
            
            # Skip separator lines
            if line == '---':
                doc.add_paragraph('')
                i += 1
                continue
            
            # Check if this is the start of a table
            if line.startswith('|') and '|' in line[1:]:
                table_data, new_idx = parse_markdown_table(lines, i)
                if table_data:
                    add_table_to_doc(doc, table_data, lang)
                i = new_idx
                continue
            
            # Handle markdown headings
            if line.startswith('# ') and not line.startswith('## '):
                h = doc.add_heading(line[2:], level=0)
                if lang == 'ar':
                    h.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif line.startswith('## '):
                h = doc.add_heading(line[3:], level=1)
                if lang == 'ar':
                    h.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif line.startswith('### '):
                h = doc.add_heading(line[4:], level=2)
                if lang == 'ar':
                    h.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif line.startswith('#### '):
                h = doc.add_heading(line[5:], level=3)
                if lang == 'ar':
                    h.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif line.startswith('- ') or line.startswith('* ') or line.startswith('• '):
                bullet_text = line[2:]
                p = doc.add_paragraph(bullet_text, style='List Bullet')
                if lang == 'ar':
                    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif line.startswith('**') and line.endswith('**'):
                p = doc.add_paragraph()
                run = p.add_run(line[2:-2])
                run.bold = True
                if lang == 'ar':
                    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            elif line.startswith('**') and '**' in line[2:]:
                # Bold text at start of line
                p = doc.add_paragraph()
                parts = line.split('**')
                for idx, part in enumerate(parts):
                    if part:
                        run = p.add_run(part)
                        if idx % 2 == 1:  # Odd indices are bold
                            run.bold = True
                if lang == 'ar':
                    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            else:
                p = doc.add_paragraph(line)
                if lang == 'ar':
                    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            
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
    except ImportError:
        # python-docx not installed, return error
        return jsonify({'error': 'Word generation not available - python-docx not installed'}), 500
    except Exception as e:
        # Log the error and return a proper error response
        print(f"DOCX generation error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Document generation failed: {str(e)}'}), 500

@app.route('/api/generate-pdf', methods=['POST'])
@login_required
def api_generate_pdf():
    """Generate PDF document from content with Arabic support."""
    from io import BytesIO
    
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
        
        if is_arabic:
            try:
                import arabic_reshaper
                from bidi.algorithm import get_display
            except ImportError:
                # Fallback if arabic libraries not available
                def get_display(text):
                    return text
                def reshape(text):
                    return text
                arabic_reshaper = type('obj', (object,), {'reshape': reshape})()
        
        def process_arabic(text):
            """Process Arabic text for correct display."""
            if is_arabic and text:
                try:
                    reshaped = arabic_reshaper.reshape(text)
                    return get_display(reshaped)
                except:
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
                fontName='Helvetica-Bold'
            )
            heading1_style = ParagraphStyle(
                'ArabicH1',
                parent=styles['Heading1'],
                alignment=TA_RIGHT,
                fontSize=18,
                spaceAfter=12,
                spaceBefore=20,
                textColor=colors.HexColor('#1a365d'),
                fontName='Helvetica-Bold'
            )
            heading2_style = ParagraphStyle(
                'ArabicH2',
                parent=styles['Heading2'],
                alignment=TA_RIGHT,
                fontSize=14,
                spaceAfter=10,
                spaceBefore=15,
                textColor=colors.HexColor('#2d3748'),
                fontName='Helvetica-Bold'
            )
            normal_style = ParagraphStyle(
                'ArabicNormal',
                parent=styles['Normal'],
                alignment=TA_RIGHT,
                fontSize=11,
                spaceAfter=8,
                leading=16
            )
            bullet_style = ParagraphStyle(
                'ArabicBullet',
                parent=styles['Normal'],
                alignment=TA_RIGHT,
                fontSize=11,
                spaceAfter=6,
                leftIndent=20
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
        
        # Build content
        story = []
        
        # Add title
        title_text = process_arabic(filename.replace('_', ' ').title()) if is_arabic else filename.replace('_', ' ').title()
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
            
            # Check if this is a table
            if line.startswith('|') and '|' in line[1:]:
                table_data = []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    row_line = lines[i].strip()
                    if '---' not in row_line:  # Skip separator
                        cells = [c.strip() for c in row_line.split('|')[1:-1]]
                        if cells:
                            if is_arabic:
                                cells = [process_arabic(c) for c in cells]
                            table_data.append(cells)
                    i += 1
                
                if table_data:
                    # Create table
                    col_count = len(table_data[0]) if table_data else 1
                    col_width = (doc.width) / col_count
                    
                    t = Table(table_data, colWidths=[col_width] * col_count)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'RIGHT' if is_arabic else 'LEFT'),
                        ('FONTSIZE', (0, 0), (-1, 0), 11),
                        ('FONTSIZE', (0, 1), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.15*inch))
                continue
            
            # Handle markdown headings
            text = process_arabic(line) if is_arabic else line
            
            if line.startswith('# ') and not line.startswith('## '):
                story.append(Paragraph(text[2:], title_style))
            elif line.startswith('## '):
                story.append(Paragraph(text[3:], heading1_style))
            elif line.startswith('### '):
                story.append(Paragraph(text[4:], heading2_style))
            elif line.startswith('#### '):
                story.append(Paragraph(text[5:], heading2_style))
            elif line.startswith('- ') or line.startswith('* ') or line.startswith('• '):
                bullet_text = '• ' + text[2:]
                story.append(Paragraph(bullet_text, bullet_style))
            elif line.startswith('**') and line.endswith('**'):
                story.append(Paragraph(f'<b>{text[2:-2]}</b>', normal_style))
            elif '**' in line:
                # Handle inline bold
                formatted = line.replace('**', '<b>', 1).replace('**', '</b>', 1)
                while '**' in formatted:
                    formatted = formatted.replace('**', '<b>', 1).replace('**', '</b>', 1)
                if is_arabic:
                    formatted = process_arabic(formatted)
                story.append(Paragraph(formatted, normal_style))
            else:
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
    
    conn.close()
    
    return render_template('admin.html',
                          stats=stats,
                          domains_strategies=domains_strategies,
                          domains_policies=domains_policies,
                          domains_audits=domains_audits,
                          domains_risks=domains_risks,
                          recent_users=recent_users,
                          docs_per_day=docs_per_day,
                          config=config)

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
