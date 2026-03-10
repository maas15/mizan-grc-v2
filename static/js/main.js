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
// GRC MARKDOWN PREPROCESSOR
// Fixes the #1 cause of broken previews: AI outputs Markdown tables without
// the blank lines that marked.js requires to parse them as GFM tables.
// Also repairs merged headings like "## 1. Section Title SubLabel:".
//
// Called automatically via the marked.parse monkey-patch in DOMContentLoaded
// — no changes needed in domain.html or any other template.
// ============================================================================

/**
 * removeMidTableSeparators(md)
 *
 * State-machine pass that removes duplicate |---|---| rows inside tables.
 * The AI frequently repeats the separator row every 2-3 data rows.
 * marked.js ends the table at the first mid-table separator, making all
 * subsequent rows render as raw pipe text.
 *
 * Rule: within a table block, keep ONLY the first separator row (which
 * follows the header). Drop every subsequent separator row.
 * A table block ends when a blank line or non-pipe line is encountered.
 */
function removeMidTableSeparators(md) {
    var lines = md.split('\n');
    var out = [];
    var sawSep = false;  // have we seen the first separator in this table?

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var t = line.trim();
        var isPipe = t.charAt(0) === '|';
        var isSep  = isPipe && /---/.test(t) && /^\|[\s\-:|]+\|/.test(t);

        if (!isPipe) {
            // blank line or non-table content — reset table state
            sawSep = false;
            out.push(line);
            continue;
        }

        if (isSep) {
            if (sawSep) {
                // duplicate mid-table separator — drop it
                continue;
            }
            sawSep = true;  // first separator in this table — keep it
        }

        out.push(line);
    }
    return out.join('\n');
}

/**
 * preprocessGRCMarkdown(md)
 *
 * Normalises raw AI markdown before passing to marked.parse() so that
 * tables always render as HTML tables instead of raw pipe text.
 *
 * Rules applied (in order):
 *  A.  Remove duplicate mid-table separator rows (state machine)
 *  B.  Split heading (any level) from inline pipe table on same line
 *  C.  Split metadata rows packed on one line (| | **Key** | Value | | **Key** |...)
 *  D.  Split two numbered data rows packed on same line (| 1 |...| | 2 |...)
 *  E.  Split plain-text line from embedded pipe table (impl guide headings)
 *  F.  Trim leading whitespace from rows created by splitting
 *  G.  Ensure blank line BEFORE every table row
 *  H.  Ensure blank line AFTER the last row of every table block
 *  I.  Split AI-merged heading+sublabel where body text follows on same line
 *  J.  Split AI-merged heading+sublabel where sublabel is at end of line
 *  K.  Collapse 4+ consecutive newlines to 3
 *
 * @param   {string} md  Raw markdown from AI
 * @returns {string}     Cleaned markdown ready for marked.parse()
 */
function preprocessGRCMarkdown(md) {
    if (!md || typeof md !== 'string') return md || '';

    // ── 1. Normalise line endings ──────────────────────────────────────────
    md = md.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    // ── A. Remove duplicate mid-table separator rows ───────────────────────
    md = removeMidTableSeparators(md);

    // ── B. Split heading from inline pipe table on same line ──────────────
    // "# Title | | | | **Key** | Value |" → heading then table on next line
    md = md.replace(/(#{1,4}[^|\n]+?)\s*(\|\s*[|\s]*\|)/g, '$1\n\n$2');

    // ── C. Split metadata rows packed on one line ─────────────────────────
    // "| | | | **Document Type** | Value | | **Domain** | Value |"
    md = md.replace(/(\|)(\s*\|\s*\*\*[A-Z\u0600-\u06FF])/g, '$1\n$2');

    // ── D. Split two numbered data rows packed on same line ───────────────
    // "| 1 | content | | 2 | content |"
    md = md.replace(/(\|)(\s*\|\s*\d+\s*\|)/g, '$1\n$2');

    // ── E. Split plain-text line from embedded pipe table ─────────────────
    // "Gap #1 Implementation Guide: ... Immediate Actions : | Step | Action | Owner |"
    // Any non-heading, non-pipe line that ends with 3+ piped cells gets split.
    md = md.replace(
        /^([^|#\n][^\n]+?)\s*(\|(?:[^|\n]+\|){2,}[^\n]*\|?\s*)$/gm,
        function (match, text, table) {
            // Only split if table part has at least 2 '|' separators (3+ cells)
            if ((table.match(/\|/g) || []).length >= 3) {
                return text.trimRight() + '\n\n' + table.trim();
            }
            return match;
        }
    );

    // ── F. Trim leading whitespace from rows created by splitting ─────────
    md = md.replace(/^[ \t]+(\|)/gm, '$1');

    // ── G0. Remove orphan row-counter lines: "| 1" (pipe + digit only, no trailing pipe) ──
    // These are bare number lines the AI emits between table rows. Rule G would
    // insert a blank line after them (the digit is not | or \n), breaking the table.
    md = md.replace(/^\|\s*\d+\s*$/gm, '');

    // ── G1. Strip dangling " | N" at end of table rows that lack a closing | ────
    // AI emits: "| 1 | content | content | | 2" — the " | 2" is the next row counter
    // appended to the previous row. Strip it so the row ends cleanly with |.
    md = md.replace(/(\|[^\n]*\|)\s*\|\s*\d+\s*$/gm, '$1');

    // ── G. Ensure blank line before any table row ─────────────────────────
    // [^\n|] excludes pipe so this never fires between consecutive table rows
    md = md.replace(/([^\n|])\n(\|)/g, '$1\n\n$2');

    // ── H. Ensure blank line after the last row of a table block ──────────
    md = md.replace(/(\|[^\n]*\n)(?!\n)(?!\|)([^\n])/g, '$1\n$2');

    // ── I. Split merged heading + sublabel + BODY TEXT on same line ───────
    // "## 1. Vision & Objectives Vision: The Organization aspires..."
    md = md.replace(
        /(#{2,4}\s+(?:\d+\.\s+)?[^\n]+?)\s+([A-Z][a-zA-Z]{2,20}:)\s+([^\n]{30,})/g,
        function (match, heading, label, body) {
            var titleTokens = heading.replace(/^#+\s*/, '').split(/\s+/).length;
            if (titleTokens < 3) return match;
            return heading + '\n\n**' + label + '**\n' + body;
        }
    );

    // ── J. Split merged heading + sublabel at line end ────────────────────
    // "## 1. Vision & Objectives Vision:\n"
    md = md.replace(
        /(#{2,4}\s+(?:\d+\.\s+)?[^\n]+?)\s+([A-Z][a-zA-Z]{2,20}:)([ \t]*)(?=\n)/g,
        function (match, heading, label) {
            var titleTokens = heading.replace(/^#+\s*/, '').split(/\s+/).length;
            if (titleTokens < 3) return match;
            return heading + '\n\n**' + label + '**';
        }
    );

    // ── K. Collapse excessive blank lines (>3 consecutive newlines → 3) ───
    md = md.replace(/\n{4,}/g, '\n\n\n');

    return md;
}

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
window.preprocessGRCMarkdown = preprocessGRCMarkdown;

// ============================================================================
// DOM READY — single handler (no duplicates)
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
    console.log('Mizan GRC initialized');

    // ── Sync theme icon with current state ──────────────────────────────────
    // (theme itself was set by base.html inline IIFE to prevent FOUC)
    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    document.querySelectorAll('.theme-toggle i').forEach(function (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    });

    // ── Smooth scrolling for anchor links ───────────────────────────────────
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // ── Monkey-patch marked.parse to auto-run preprocessGRCMarkdown ─────────
    //
    // Why here (DOMContentLoaded) and not at module load time?
    //   main.js loads from base.html (early in <head>).
    //   marked.min.js is loaded by individual templates (domain.html line 614)
    //   AFTER base.html scripts. By DOMContentLoaded, all synchronous scripts
    //   have run, so marked is guaranteed to exist.
    //
    // Effect: every call to marked.parse() anywhere in domain.html now
    // automatically preprocesses the markdown first — zero changes needed
    // to domain.html, history.html, or any other template.
    // ────────────────────────────────────────────────────────────────────────
    if (typeof marked !== 'undefined' && typeof marked.parse === 'function') {
        var _origMarkedParse = marked.parse.bind(marked);
        marked.parse = function (src, options) {
            return _origMarkedParse(preprocessGRCMarkdown(src || ''), options);
        };
        console.log('Mizan GRC: marked.parse patched — GRC table preprocessing active');
    }
});
