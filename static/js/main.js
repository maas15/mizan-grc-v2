/**
 * Mizan GRC - Main JavaScript
 * Enterprise Governance, Risk & Compliance Platform
 * Created by: Eng. Mohammad Abbas Alsaadon
 */

// Utility Functions
const Utils = {
    // Show element
    show: (element) => {
        if (element) element.classList.remove('hidden');
    },
    
    // Hide element
    hide: (element) => {
        if (element) element.classList.add('hidden');
    },
    
    // Toggle element
    toggle: (element) => {
        if (element) element.classList.toggle('hidden');
    },
    
    // Format date
    formatDate: (date) => {
        return new Date(date).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    },
    
    // Debounce function
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

// API Helper — CSRF token auto-injected via base.html global fetch override
// This object provides structured error handling on top of the override.
const API = {
    // Read CSRF token from meta tag (set by base.html)
    get csrfToken() {
        var meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute('content') : '';
    },

    // Base fetch with error handling + CSRF header
    async fetch(url, options = {}) {
        try {
            // Build headers — always include CSRF for mutating requests
            const method = (options.method || 'GET').toUpperCase();
            const headers = Object.assign({}, options.headers || {});
            if (method !== 'GET' && method !== 'HEAD') {
                headers['X-CSRFToken'] = this.csrfToken;
                // Only set Content-Type for non-FormData bodies
                if (!(options.body instanceof FormData)) {
                    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
                }
            }

            const response = await fetch(url, {
                ...options,
                headers: headers
            });
            
            if (response.status === 403) {
                console.error('CSRF validation failed — reloading page');
                window.location.reload();
                throw new Error('CSRF token expired');
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
    
    // POST request (JSON body)
    async post(url, data) {
        return this.fetch(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },
    
    // POST request (FormData body — for file uploads)
    async postForm(url, formData) {
        return this.fetch(url, {
            method: 'POST',
            body: formData
            // Content-Type deliberately omitted — browser sets multipart boundary
        });
    },

    // PUT request
    async put(url, data) {
        return this.fetch(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    // DELETE request
    async del(url) {
        return this.fetch(url, {
            method: 'DELETE'
        });
    },

    // GET request
    async get(url) {
        return this.fetch(url);
    }
};

// Toast Notifications
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
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
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

// Add CSS for toast animations
const toastStyles = document.createElement('style');
toastStyles.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(toastStyles);

// Form Validation
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

// Export utilities
window.Utils = Utils;
window.API = API;
window.Toast = Toast;
window.FormValidator = FormValidator;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('Mizan GRC initialized');
    
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
});
