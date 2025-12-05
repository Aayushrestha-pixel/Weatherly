// Weatherly - Minimal Design JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('🌤️ Weatherly Minimal loaded');
    
    initNavbar();
    initAnimations();
    initFormValidation();
    initTaskInteractions();
    initWeatherUpdates();
});

// ============================================
// NAVBAR - Scroll Effect
// ============================================

function initNavbar() {
    const navbar = document.querySelector('.navbar-custom');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
}

// ============================================
// ANIMATIONS - Intersection Observer
// ============================================

function initAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    document.querySelectorAll('.animate-fade-in, .animate-slide-up').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
        observer.observe(el);
    });
}

// ============================================
// FORM VALIDATION
// ============================================

function initFormValidation() {
    const taskForm = document.getElementById('addTaskForm');
    if (taskForm) {
        taskForm.addEventListener('submit', function(e) {
            const taskInput = document.getElementById('task_name');
            const submitBtn = document.getElementById('submitTaskBtn');
            
            if (taskInput.value.trim().length < 3) {
                e.preventDefault();
                showToast('⚠️ Please enter at least 3 characters', 'warning');
                taskInput.focus();
                return false;
            }
            
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
            showToast('🤖 AI is analyzing your task...', 'info');
        });
    }

    const taskInput = document.getElementById('task_name');
    if (taskInput) {
        taskInput.addEventListener('input', function() {
            const length = this.value.length;
            const formText = this.nextElementSibling;
            
            if (length > 0) {
                formText.innerHTML = `<i class="fas fa-check-circle"></i> ${length} characters`;
                formText.style.color = 'var(--success)';
            } else {
                formText.innerHTML = '<i class="fas fa-info-circle"></i> AI will analyze this task';
                formText.style.color = 'var(--text-secondary)';
            }
        });
    }
}

// ============================================
// TASK INTERACTIONS
// ============================================

function initTaskInteractions() {
    const tasks = document.querySelectorAll('.task-item');
    tasks.forEach(task => {
        task.addEventListener('mouseenter', function() {
            this.style.transform = 'translateX(8px)';
        });
        
        task.addEventListener('mouseleave', function() {
            this.style.transform = 'translateX(0)';
        });
    });

    const deleteLinks = document.querySelectorAll('.task-actions a[href*="delete_task"]');
    deleteLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const taskName = this.closest('.task-item').querySelector('.task-title').textContent;
            
            if (confirm(`Delete "${taskName}"?`)) {
                showToast('🗑️ Task deleted', 'info');
                setTimeout(() => {
                    window.location.href = this.href;
                }, 500);
            }
        });
    });
}

// ============================================
// WEATHER UPDATES
// ============================================

function initWeatherUpdates() {
    const weatherCard = document.querySelector('.weather-card');
    if (weatherCard) {
        weatherCard.style.animation = 'fadeIn 0.8s ease';
    }

    const locationForm = document.getElementById('locationForm');
    if (locationForm) {
        locationForm.addEventListener('submit', function() {
            showToast('📍 Updating location...', 'info');
        });
    }
}

// ============================================
// TOAST NOTIFICATIONS
// ============================================

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    toast.innerHTML = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

// ============================================
// KEYBOARD SHORTCUTS
// ============================================

document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const taskInput = document.getElementById('task_name');
        if (taskInput) {
            taskInput.focus();
            showToast('✨ Quick add task', 'info');
        }
    }
});

// Auto-hide alerts after 3 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert-auto-hide');
    
    alerts.forEach(alert => {
        // Add fade-out animation
        setTimeout(() => {
            alert.style.transition = 'all 0.3s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-20px)';
            
            setTimeout(() => {
                const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
                bsAlert.close();
            }, 300);
        }, 3000);
    });
});