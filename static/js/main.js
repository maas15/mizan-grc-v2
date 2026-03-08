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
// EXPORTS
// ============================================================================
window.Utils = Utils;
window.API = API;
window.Toast = Toast;
window.FormValidator = FormValidator;
window.MizanPipe = MizanPipe;
window.toggleTheme = toggleTheme;

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
