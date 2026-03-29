// Toast notification system
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
            <div class="toast-message">${escapeHtml(message)}</div>
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
    }

    removeToast(toast) {
        toast.classList.add('fade-out');
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
}

const toast = new ToastManager();

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Loading spinner
function showLoading(element) {
    const originalContent = element.innerHTML;
    const spinner = '<span class="spinner"></span>';
    element.innerHTML = spinner;
    element.disabled = true;
    element.setAttribute('data-original', originalContent);
    return () => {
        element.innerHTML = element.getAttribute('data-original');
        element.disabled = false;
        element.removeAttribute('data-original');
    };
}

// Skeleton loader
function showSkeleton(element, type = 'card') {
    if (type === 'card') {
        element.innerHTML = `
            <div class="skeleton-card">
                <div class="skeleton-title skeleton"></div>
                <div class="skeleton-text skeleton"></div>
                <div class="skeleton-text skeleton"></div>
            </div>
        `;
    } else if (type === 'list') {
        element.innerHTML = `
            <div class="skeleton-card">
                <div class="skeleton-text skeleton"></div>
                <div class="skeleton-text skeleton" style="width: 80%;"></div>
            </div>
            <div class="skeleton-card">
                <div class="skeleton-text skeleton"></div>
                <div class="skeleton-text skeleton" style="width: 80%;"></div>
            </div>
        `;
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// Format expiry time
function formatExpiryTime(expiresAt) {
    const expiryTime = new Date(expiresAt);
    const now = new Date();
    const diff = expiryTime - now;

    if (diff <= 0) return 'Expired';

    const hours = Math.floor(diff / 3600000);
    const minutes = Math.floor((diff % 3600000) / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);

    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

// Theme handling
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.body.className = savedTheme;
    }

    const burgerMenu = document.getElementById('burgerMenu');
    const sidebarMenu = document.getElementById('sidebarMenu');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    if (burgerMenu && sidebarMenu && sidebarOverlay) {
        burgerMenu.addEventListener('click', function() {
            sidebarMenu.classList.add('open');
            sidebarOverlay.classList.add('active');
            document.body.style.overflow = 'hidden';
        });

        sidebarOverlay.addEventListener('click', function() {
            sidebarMenu.classList.remove('open');
            sidebarOverlay.classList.remove('active');
            document.body.style.overflow = '';
        });

        const sidebarLinks = sidebarMenu.querySelectorAll('a');
        sidebarLinks.forEach(link => {
            link.addEventListener('click', function() {
                sidebarMenu.classList.remove('open');
                sidebarOverlay.classList.remove('active');
                document.body.style.overflow = '';
            });
        });
    }
});

function toggleTheme() {
    const currentTheme = document.body.className;
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.body.className = newTheme;
    localStorage.setItem('theme', newTheme);
}

// Export for use in other scripts
window.toast = toast;
window.showLoading = showLoading;
window.showSkeleton = showSkeleton;
window.formatFileSize = formatFileSize;
window.formatExpiryTime = formatExpiryTime;
