/**
 * Mizan GRC - Main JavaScript
 * Enterprise Governance, Risk & Compliance Platform
 * Created by: Eng. Mohammad Abbas Alsaadon
 */

// ============================================================================
// UNIFIED THEME TOGGLE — Single source of truth
// Uses data-theme attribute on <html> + localStorage persistence.
// base.html has an inline IIFE that sets the initial theme from localStorage
// BEFORE the page renders (prevents FOUC).  This file provides the runtime
// toggle and ensures the icon matches on DOMContentLoaded.
// domain.html, profile.html, and every other template inherit via
//   {% extends "base.html" %}
// They must NEVER re-define toggleTheme().
// ============================================================================

function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    // Add transition class for smooth theme change across ALL elements
    // including sidebar, cards, inputs — everything transitions together
    html.classList.add('theme-transitioning');

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('mizan-theme', newTheme);

    // Update every toggle button icon on the page
    document.querySelectorAll('.theme-toggle i').forEach(function (icon) {
        icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    });

    // Update mobile browser theme-color meta tag
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) {
        metaTheme.setAttribute('content', newTheme === 'dark' ? '#0f172a' : '#f8fafc');
    }

    // Fire custom event so any page-specific JS can react
    window.dispatchEvent(new CustomEvent('mizan-theme-changed', {
        detail: { theme: newTheme, previous: currentTheme }
    }));

    // Remove transition class after animations complete
    setTimeout(function () {
        html.classList.remove('theme-transitioning');
    }, 400);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
const Utils = {
    show: (element) => {
        if (element) element.classList.remove('hidden');
    },
    hide: (element) => {
        if (element) element.classList.add('hidden');
    },
    toggle: (element) => {
        if (element) element.classList.toggle('hidden');
    },
    formatDate: (date) => {
        return new Date(date).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    },
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// ============================================================================
// API HELPER
// ============================================================================
const API = {
    async fetch(url, options = {}) {
        try {
            const response = await fetch(url, {
                ...options,
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
            // Handle session expiry gracefully
            if (response.status === 401) {
                const data = await response.json().catch(() => ({}));
                if (data.session_expired) {
                    Toast.warning('Session expired. Redirecting to login...');
                    setTimeout(() => { window.location.href = '/login'; }, 1500);
                    throw new Error('Session expired');
                }
            }
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },
    async post(url, data) {
        return this.fetch(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },
    async get(url) {
        return this.fetch(url);
    }
};

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================
const Toast = {
    container: null,

    init() {
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                display: flex;
                flex-direction: column;
                gap: 10px;
            `;
            document.body.appendChild(this.container);
        }
    },

    show(message, type = 'info', duration = 3000) {
        this.init();

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.style.cssText = `
            padding: 14px 20px;
            border-radius: 8px;
            color: white;
            font-size: 14px;
            animation: slideIn 0.3s ease;
            display: flex;
            align-items: center;
            gap: 10px;
            max-width: 350px;
        `;

        const colors = {
            success: 'linear-gradient(135deg, #38ef7d, #11998e)',
            error: 'linear-gradient(135deg, #f5576c, #f093fb)',
            warning: 'linear-gradient(135deg, #f5af19, #f12711)',
            info: 'linear-gradient(135deg, #667eea, #764ba2)'
        };

        const icons = {
            success: '\u2713',
            error: '\u2715',
            warning: '\u26A0',
            info: '\u2139'
        };

        toast.style.background = colors[type] || colors.info;
        toast.innerHTML = `<span>${icons[type] || icons.info}</span> ${message}`;

        this.container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    },

    success(message) { this.show(message, 'success'); },
    error(message) { this.show(message, 'error'); },
    warning(message) { this.show(message, 'warning'); },
    info(message) { this.show(message, 'info'); }
};

// Toast + theme transition animation styles
const dynamicStyles = document.createElement('style');
dynamicStyles.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    /* Smooth theme transition — applied briefly during toggleTheme() */
    .theme-transitioning,
    .theme-transitioning *,
    .theme-transitioning *::before,
    .theme-transitioning *::after {
        transition: background-color 0.3s ease,
                    color 0.3s ease,
                    border-color 0.3s ease,
                    box-shadow 0.3s ease !important;
    }
`;
document.head.appendChild(dynamicStyles);

// ============================================================================
// FORM VALIDATION
// ============================================================================
const FormValidator = {
    validate(form) {
        const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
        let isValid = true;

        inputs.forEach(input => {
            if (!input.value.trim()) {
                isValid = false;
                this.showError(input, 'This field is required');
            } else {
                this.clearError(input);
            }
        });

        return isValid;
    },

    showError(input, message) {
        input.style.borderColor = '#f5576c';
        let errorEl = input.nextElementSibling;
        if (!errorEl || !errorEl.classList.contains('error-message')) {
            errorEl = document.createElement('span');
            errorEl.className = 'error-message';
            errorEl.style.cssText = 'color: #f5576c; font-size: 12px; margin-top: 4px; display: block;';
            input.parentNode.appendChild(errorEl);
        }
        errorEl.textContent = message;
    },

    clearError(input) {
        input.style.borderColor = '';
        const errorEl = input.parentNode.querySelector('.error-message');
        if (errorEl) errorEl.remove();
    }
};

// ============================================================================
// MIZAN PIPE — Frontend notification for auto-extracted items
// ============================================================================
const MizanPipe = {
    /**
     * Show notification after strategy generation if items were auto-extracted
     * @param {Object} pipeResult - { risks_added, initiatives_added, kpis_added, gaps_added, roadmap_added }
     */
    notify(pipeResult) {
        if (!pipeResult) return;
        const parts = [];
        if (pipeResult.risks_added > 0) {
            parts.push(pipeResult.risks_added + ' risk(s) \u2192 Risk Register');
        }
        if (pipeResult.initiatives_added > 0) {
            parts.push(pipeResult.initiatives_added + ' initiative(s) \u2192 Tasks');
        }
        if (pipeResult.kpis_added > 0) {
            parts.push(pipeResult.kpis_added + ' KPI(s) \u2192 Tasks');
        }
        if (pipeResult.gaps_added > 0) {
            parts.push(pipeResult.gaps_added + ' gap(s) \u2192 Tasks');
        }
        if (pipeResult.roadmap_added > 0) {
            parts.push(pipeResult.roadmap_added + ' project(s) \u2192 Tasks');
        }
        if (parts.length > 0) {
            Toast.success('Mizan Pipe: Auto-extracted ' + parts.join(', '));
        }
    }
};

// ============================================================================
// PROGRESS INDICATOR  —  type-aware, shown only for AI generation
// ============================================================================
const Progress = {
    /**
     * Stage definitions per document type.
     * Each entry: { steps: [...], timings: [pct at which each stage activates] }
     */
    _config: {
        strategy: {
            steps: ['Initializing Strategy', 'Performing Gap Analysis', 'Designing Roadmap', 'Finalizing Document'],
            steps_ar: ['تهيئة الاستراتيجية', 'تحليل الفجوات', 'تصميم خارطة الطريق', 'إنهاء الوثيقة'],
            timings: [0, 20, 55, 82]
        },
        audit: {
            steps: ['Mapping Controls', 'Analyzing Evidence', 'Calculating Risk Levels', 'Compiling Findings'],
            steps_ar: ['رسم خريطة الضوابط', 'تحليل الأدلة', 'احتساب مستويات المخاطر', 'تجميع النتائج'],
            timings: [0, 18, 50, 78]
        },
        policy: {
            steps: ['Defining Roles', 'Structuring Controls', 'Finalizing Language'],
            steps_ar: ['تحديد الأدوار', 'هيكلة الضوابط', 'صياغة اللغة النهائية'],
            timings: [0, 35, 70]
        },
        procedure: {
            steps: ['Defining Roles', 'Structuring Controls', 'Finalizing Language'],
            steps_ar: ['تحديد الأدوار', 'هيكلة الضوابط', 'صياغة اللغة النهائية'],
            timings: [0, 35, 70]
        },
        risk: {
            steps: ['Assessing Threat Landscape', 'Scoring Likelihood & Impact', 'Building Mitigation Plan', 'Finalizing Register'],
            steps_ar: ['تقييم بيئة التهديدات', 'احتساب الاحتمالية والأثر', 'بناء خطة المعالجة', 'إنهاء السجل'],
            timings: [0, 22, 58, 84]
        },
        default: {
            steps: ['Analysing requirements', 'Building structure', 'Writing content', 'Quality review', 'Finalising'],
            steps_ar: ['تحليل المتطلبات', 'بناء الهيكل', 'كتابة المحتوى', 'التدقيق والمراجعة', 'الاكتمال'],
            timings: [0, 15, 40, 70, 88]
        }
    },

    _interval: null,

    /**
     * Show the AI progress overlay for a specific document type.
     * @param {string} docType  'strategy'|'audit'|'policy'|'procedure'|'risk'|null
     * @param {boolean} isRtl   true when UI is Arabic
     */
    show(docType, isRtl) {
        const el = document.getElementById('loading');
        if (!el) return;

        const cfg = this._config[docType] || this._config.default;
        const steps = isRtl ? cfg.steps_ar : cfg.steps;
        const timings = cfg.timings;

        // Render stage list
        const stageList = document.getElementById('progress-stages');
        if (stageList) {
            stageList.innerHTML = steps.map((s, i) =>
                `<li data-stage="${i}"${i === 0 ? ' class="active"' : ''}><span class="stage-dot"></span>${s}</li>`
            ).join('');
        }

        // Reset bar
        const fill = document.getElementById('progress-bar-fill');
        const pct  = document.getElementById('progress-percent');
        if (fill) { fill.style.animation = 'none'; fill.offsetHeight; fill.style.animation = ''; }
        if (pct)  pct.textContent = '0%';

        el.classList.add('active');

        // Simulate progress
        let prog = 0;
        let stageIdx = 0;
        if (this._interval) clearInterval(this._interval);
        this._interval = setInterval(() => {
            if (prog < 92) {
                prog += (prog < 30 ? 2 : prog < 60 ? 1.2 : 0.5);
                if (pct) pct.textContent = Math.round(prog) + '%';
                const stages = stageList ? stageList.querySelectorAll('li') : [];
                for (let si = timings.length - 1; si >= 0; si--) {
                    if (prog >= timings[si]) { stageIdx = si; break; }
                }
                stages.forEach((s, i) => {
                    s.classList.remove('active', 'done');
                    if (i < stageIdx) s.classList.add('done');
                    else if (i === stageIdx) s.classList.add('active');
                });
            }
        }, 350);
    },

    hide() {
        if (this._interval) { clearInterval(this._interval); this._interval = null; }
        const el = document.getElementById('loading');
        if (!el) return;
        const fill = document.getElementById('progress-bar-fill');
        const pct  = document.getElementById('progress-percent');
        if (fill) fill.style.width = '100%';
        if (pct)  pct.textContent = '100%';
        // Mark all done
        const stageList = document.getElementById('progress-stages');
        if (stageList) stageList.querySelectorAll('li').forEach(s => {
            s.classList.remove('active'); s.classList.add('done');
        });
        setTimeout(() => { el.classList.remove('active'); }, 400);
    }
};

// ============================================================================
// EXPORTS
// ============================================================================
window.Utils = Utils;
window.API = API;
window.Toast = Toast;
window.FormValidator = FormValidator;
window.MizanPipe = MizanPipe;
window.toggleTheme = toggleTheme;
window.Progress = Progress;

// ============================================================================
// DOM READY — single handler (no duplicates)
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
    console.log('Mizan GRC initialized');

    // Sync theme icon with current state (theme itself was set by base.html inline IIFE)
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    document.querySelectorAll('.theme-toggle i').forEach(function (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    });

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
});
