// ============================================
// DISPATCH - Modern UI Enhancements
// ============================================

// Toast Notification System
class ToastManager {
    constructor() {
        this.container = null;
        this.createContainer();
    }

    createContainer() {
        if (!document.querySelector('.toast-container')) {
            const container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
            this.container = container;
        } else {
            this.container = document.querySelector('.toast-container');
        }
    }

    show(message, type = 'info', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        toast.innerHTML = `
            <div class="toast-message">${this.escapeHtml(message)}</div>
            <button class="toast-close">&times;</button>
        `;

        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => {
            this.removeToast(toast);
        });

        this.container.appendChild(toast);

        setTimeout(() => {
            this.removeToast(toast);
        }, duration);
        
        toast.style.animation = 'slideInRight 0.3s ease';
    }

    removeToast(toast) {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 300);
    }

    success(message, duration = 5000) {
        this.show(message, 'success', duration);
    }

    error(message, duration = 5000) {
        this.show(message, 'error', duration);
    }

    info(message, duration = 5000) {
        this.show(message, 'info', duration);
    }

    warning(message, duration = 5000) {
        this.show(message, 'warning', duration);
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize toast
const toast = new ToastManager();

// Theme Manager
class ThemeManager {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'light';
        this.init();
    }

    init() {
        this.applyTheme(this.theme);
        this.setupToggle();
    }

    applyTheme(theme) {
        document.body.className = theme;
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        const toggle = document.getElementById('themeToggle');
        if (toggle) {
            toggle.checked = theme === 'dark';
        }
        
        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
    }

    toggle() {
        const newTheme = this.theme === 'light' ? 'dark' : 'light';
        this.theme = newTheme;
        this.applyTheme(newTheme);
        
        fetch('/profile/change-theme', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'theme=' + newTheme
        }).catch(err => console.error('Theme sync failed:', err));
    }

    setupToggle() {
        const toggle = document.getElementById('themeToggle');
        if (toggle) {
            toggle.addEventListener('change', () => this.toggle());
        }
    }
}

// Initialize theme manager
const themeManager = new ThemeManager();

// Loading Spinner Manager
class LoadingManager {
    static show(element) {
        if (!element) return null;
        
        const originalContent = element.innerHTML;
        const originalWidth = element.style.width;
        
        element.style.width = element.offsetWidth + 'px';
        element.innerHTML = '<span class="spinner" style="width: 20px; height: 20px;"></span>';
        element.disabled = true;
        element.setAttribute('data-original', originalContent);
        element.setAttribute('data-original-width', originalWidth);
        
        return () => {
            element.innerHTML = element.getAttribute('data-original');
            element.disabled = false;
            element.style.width = element.getAttribute('data-original-width');
            element.removeAttribute('data-original');
            element.removeAttribute('data-original-width');
        };
    }
}

// Skeleton Loader
class SkeletonLoader {
    static show(element, type = 'card') {
        if (!element) return;
        
        const skeletons = {
            card: `
                <div class="skeleton-card">
                    <div class="skeleton-title skeleton"></div>
                    <div class="skeleton-text skeleton"></div>
                    <div class="skeleton-text skeleton" style="width: 80%;"></div>
                </div>
            `,
            list: `
                <div class="skeleton-list">
                    <div class="skeleton-text skeleton"></div>
                    <div class="skeleton-text skeleton" style="width: 90%;"></div>
                    <div class="skeleton-text skeleton" style="width: 85%;"></div>
                </div>
            `,
            chat: `
                <div class="skeleton-message">
                    <div class="skeleton-text skeleton" style="width: 60%;"></div>
                </div>
                <div class="skeleton-message" style="margin-left: auto;">
                    <div class="skeleton-text skeleton" style="width: 40%;"></div>
                </div>
            `
        };
        
        element.innerHTML = skeletons[type] || skeletons.card;
    }
    
    static hide(element, content) {
        if (!element) return;
        element.innerHTML = content || '';
    }
}

// Utility Functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + units[i];
}

function formatExpiryTime(expiresAt) {
    const expiryTime = new Date(expiresAt);
    const now = new Date();
    const diff = expiryTime - now;

    if (diff <= 0) return 'Expired';

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    if (days > 0) return days + 'd ' + hours + 'h';
    if (hours > 0) return hours + 'h ' + minutes + 'm';
    return minutes + 'm';
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        toast.success('Copied to clipboard');
    }).catch(() => {
        toast.error('Failed to copy');
    });
}

function debounce(func, wait) {
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

// Mobile Menu Handler
document.addEventListener('DOMContentLoaded', function() {
    const burgerMenu = document.getElementById('burgerMenu');
    const sidebarMenu = document.getElementById('sidebarMenu');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    if (burgerMenu && sidebarMenu && sidebarOverlay) {
        burgerMenu.addEventListener('click', () => {
            sidebarMenu.classList.add('open');
            sidebarOverlay.classList.add('active');
            document.body.style.overflow = 'hidden';
        });

        sidebarOverlay.addEventListener('click', () => {
            sidebarMenu.classList.remove('open');
            sidebarOverlay.classList.remove('active');
            document.body.style.overflow = '';
        });

        const sidebarLinks = sidebarMenu.querySelectorAll('a');
        sidebarLinks.forEach(link => {
            link.addEventListener('click', () => {
                sidebarMenu.classList.remove('open');
                sidebarOverlay.classList.remove('active');
                document.body.style.overflow = '';
            });
        });
    }
    
    // Add smooth scroll to all anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href !== '#' && href !== '') {
                const target = document.querySelector(href);
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    });
    
    // Add animation on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animation = 'fadeInUp 0.6s ease forwards';
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    document.querySelectorAll('.feature, .stat-card, .user-card, .file-card').forEach(el => {
        el.style.opacity = '0';
        observer.observe(el);
    });
});

// Export for use in other scripts
window.toast = toast;
window.ThemeManager = ThemeManager;
window.LoadingManager = LoadingManager;
window.SkeletonLoader = SkeletonLoader;
window.formatFileSize = formatFileSize;
window.formatExpiryTime = formatExpiryTime;
window.copyToClipboard = copyToClipboard;
window.debounce = debounce;
