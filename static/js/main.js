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
 * splitPhaseLabelFromRows(md)
 *
 * MUST run BEFORE removeMidTableSeparators (step A).
 *
 * Root-cause fix for the "merged phase sub-tables" defect:
 *
 * The AI sometimes embeds the next phase label inside the Deliverable cell
 * of the last data row of the current phase, with no blank line separator:
 *
 *   "| Action | Owner | Deliverable | **Short-Term Goals:** |"
 *   "| Step | Action | Owner | Deliverable |"      ← next sub-table header
 *   "|------|--------|-------|-------------|"
 *
 * Without this fix, removeMidTableSeparators sees one continuous pipe block
 * and drops the second separator as a "duplicate", merging all three phase
 * sub-tables into one giant broken table.
 *
 * Fix: detect any pipe row whose last cell contains a phase label, strip the
 * label from the cell, and emit it as a standalone line with blank-line
 * separators around it. This gives removeMidTableSeparators the non-pipe gap
 * it needs to reset and keep the next separator.
 */
function splitPhaseLabelFromRows(md) {
    // Matches **Phase Label** text anywhere inside a pipe row
    var PHASE_CELL_RE = /\*\*(Immediate Actions?|Short[ -]?Term Goals?|Medium[ -]?Term Goals?|Long[ -]?Term Goals?|الإجراءات الفورية|أهداف[^*\n]*قصيرة|أهداف[^*\n]*متوسطة)[^*\n]*\*\*/i;

    var lines = md.split('\n');
    var out   = [];

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var t    = line.trim();

        if (!t.startsWith('|')) {
            out.push(line);
            continue;
        }

        var m = PHASE_CELL_RE.exec(t);
        if (!m) {
            out.push(line);
            continue;
        }

        // Found a phase label inside a pipe row.
        // Find the last '|' before the label and cut there.
        var labelStart = t.indexOf(m[0]);
        var before     = t.substring(0, labelStart);
        var lastPipe   = before.lastIndexOf('|');

        if (lastPipe > 0 && before.split('|').length > 2) {
            // Clean row = everything up to and including the last | before the label
            var cleanRow = before.substring(0, lastPipe + 1).trim();
            out.push(cleanRow);     // data row without the label
            out.push('');           // blank line → resets removeMidTableSeparators
            out.push(m[0]);         // **Phase Label** as its own line
        } else {
            out.push(line);
        }
    }

    return out.join('\n');
}

/**
 * fixImplGuideTables(md)
 *
 * Context-free fix for Step|Action|Owner|Deliverable tables.
 * Runs AFTER removeMidTableSeparators and blank-line insertion so each
 * phase sub-table is already a clean, separated block.
 *
 * Fixes:
 * (a) 3-col header missing Deliverable  →  add it + rebuild separator
 * (b) Data row has 3 cells (step number omitted)  →  prepend empty step cell
 * (c) Data row has 4 cells but cell[0] is not a step number AND cell[3] is
 *     a phase label (label leaked into Deliverable col)  →  strip label, prepend empty step
 */
function fixImplGuideTables(md) {
    var PHASE_CELL_RE = /^(\*\*)?(Immediate Actions?|Short[ -]?Term Goals?|Medium[ -]?Term Goals?|Long[ -]?Term Goals?)/i;

    var lines       = md.split('\n');
    var out         = [];
    var inTable     = false;
    var sawSep      = false;
    var hdrCols     = 0;
    var isImplTable = false;  // true when header is Step|Action|Owner|Deliverable

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var t    = line.trim();

        // Non-pipe / blank: reset table tracking
        if (!t || !t.startsWith('|')) {
            inTable     = false;
            sawSep      = false;
            hdrCols     = 0;
            isImplTable = false;
            out.push(line);
            continue;
        }

        // Parse cells
        var parts = t.split('|');
        var cells = parts.slice(1).map(function (c) { return c.trim(); });
        if (cells.length > 0 && cells[cells.length - 1] === '') cells.pop();

        var isSep = cells.length > 0 && cells.every(function (c) { return /^[-:\s]*$/.test(c); });

        // ── Header row ──────────────────────────────────────────────────────
        if (!inTable) {
            inTable = true;

            if (!isSep) {
                var hasStep   = cells.some(function (c) { return /^(step|الخطوة|خطوة)$/i.test(c); });
                var hasAction = cells.some(function (c) { return /^(action|الإجراء|إجراء)$/i.test(c); });
                var hasOwner  = cells.some(function (c) { return /^(owner|المسؤول|مسؤول)$/i.test(c); });
                var hasDeliv  = cells.some(function (c) { return /^(deliverable|المخرج|المخرجات|output)/i.test(c); });

                isImplTable = hasStep && hasAction && hasOwner;

                if (isImplTable && !hasDeliv && cells.length === 3) {
                    // Add missing Deliverable column
                    line  = '| Step | Action | Owner | Deliverable |';
                    cells = ['Step', 'Action', 'Owner', 'Deliverable'];
                }
            }

            hdrCols = cells.length;
            out.push(line);
            continue;
        }

        // ── Separator row ────────────────────────────────────────────────────
        if (isSep) {
            sawSep = true;
            if (isImplTable && hdrCols > 0 && cells.length !== hdrCols) {
                line = '| ' + (new Array(hdrCols).fill('---').join(' | ')) + ' |';
            }
            out.push(line);
            continue;
        }

        // ── Data row ─────────────────────────────────────────────────────────
        if (isImplTable && sawSep && hdrCols === 4) {
            var stepIsNum = /^\d+$/.test(cells[0]);

            if (cells.length === 3) {
                // Step number omitted → prepend empty step cell
                line = '|  | ' + cells.join(' | ') + ' |';

            } else if (cells.length === 4 && !stepIsNum && PHASE_CELL_RE.test(cells[3])) {
                // Step number omitted AND phase label leaked into Deliverable cell.
                // Strip the label (it was already extracted as a standalone line by
                // splitPhaseLabelFromRows, so we can just drop it here) and prepend
                // an empty step cell.
                line = '|  | ' + cells.slice(0, 3).join(' | ') + ' |';
            }
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
 *  A0. Extract phase labels from pipe-row cells (BEFORE removeMidTableSeparators)
 *  A.  Remove duplicate mid-table separator rows (state machine)
 *  B.  Split heading (any level) from inline pipe table on same line
 *  C.  Split metadata rows packed on one line (| | **Key** | Value | | **Key** |...)
 *  D.  Split two numbered data rows packed on same line (| 1 |...| | 2 |...)
 *  E.  Split plain-text line from embedded pipe table (impl guide headings)
 *  F.  Trim leading whitespace from rows created by splitting
 *  G.  Ensure blank line BEFORE every table row
 *  H.  Ensure blank line AFTER the last row of every table block
 *  L.  Fix gap impl-guide tables: column alignment + missing step cells
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

    // ── A0. Extract phase labels embedded in table cells ─────────────────
    // MUST run before step A so removeMidTableSeparators sees the blank-line
    // gap between phase sub-tables and keeps each sub-table's separator.
    md = splitPhaseLabelFromRows(md);

    // ── A. Remove duplicate mid-table separator rows ───────────────────────
    md = removeMidTableSeparators(md);

    // ── B. Split heading from inline pipe table on same line ──────────────
    // Handles both empty-cell and text-content tables merged onto heading line.
    // "#### Gap #N Guide: ... Immediate Actions : | Step | Action | Owner |"
    md = md.replace(
        /(#{1,4}[^|\n]+?)\s+(\|[^\n]+)/g,
        function (match, heading, table) {
            return (table.match(/\|/g) || []).length >= 2
                ? heading.trimRight() + '\n\n' + table.trim()
                : match;
        }
    );

    // ── C. Split metadata rows packed on one line ─────────────────────────
    // "| | | | **Document Type** | Value | | **Domain** | Value |"
    // CRITICAL: use [^\S\n]* (non-newline whitespace) instead of \s* so the
    // pattern never crosses newline boundaries. The old \s* matched the trailing
    // newline of each row, firing on every consecutive "| **Bold" row and
    // inserting blank lines that shattered the entire metadata table.
    md = md.replace(/(\|)([^\S\n]*\|[^\S\n]*\*\*[A-Z\u0600-\u06FF])/g, '$1\n$2');

    // ── D. Split two numbered data rows packed on same line ───────────────
    // "| 1 | content | | 2 | content |"
    // CRITICAL: [^\S\n]* (non-newline whitespace) instead of \s* — the old \s*
    // crossed newline boundaries, firing on the last | of a separator row +
    // the \n| 1 | start of the next line, inserting spurious blank lines that
    // shattered fixImplGuideTables' continuous table-state tracking.
    // Capture trailing spaces into group 1 so group 2 starts with | (no leading
    // space), preventing step E from misidentifying group 2 as "text before table"
    // which would then cause step G0 to delete the orphaned "| digit" line.
    md = md.replace(/(\|[^\S\n]*)(\|[^\S\n]*\d+[^\S\n]*\|)/g, '$1\n$2');

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

    // ── L. Fix gap impl-guide table column defects ────────────────────────
    // Runs after H so each phase sub-table is already a clean separated block.
    md = fixImplGuideTables(md);

    // ── I. Split merged heading + sublabel + BODY TEXT on same line ───────
    // "## 1. Vision & Objectives Vision: The Organization aspires..."
    // GUARD: skip words that are part of section titles (Guide, Framework, etc.)
    var SECTION_TITLE_WORDS = /^(guide|framework|management|program|plan|report|overview|assessment|summary|review|analysis|strategy|policy|procedure|structure|system|initiative|approach|process|implementation|governance|compliance|operations|architecture):/i;
    md = md.replace(
        /(#{2,4}\s+(?:\d+\.\s+)?[^\n]+?)\s+([A-Z][a-zA-Z]{2,20}:)\s+([^\n]{30,})/g,
        function (match, heading, label, body) {
            if (SECTION_TITLE_WORDS.test(label)) return match;  // e.g. "Guide:", "Framework:"
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
            if (SECTION_TITLE_WORDS.test(label)) return match;
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
