// Smooth animations and interactions
document.addEventListener('DOMContentLoaded', function() {
    // Add fade-in animation
    const cards = document.querySelectorAll('.glass-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        setTimeout(() => {
            card.style.transition = 'all 0.6s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 100 * (index + 1));
    });

    // Copy functionality with feedback
    window.copyToken = function(token) {
        navigator.clipboard.writeText(token).then(() => {
            const btn = document.querySelector('.copy-btn');
            const originalText = btn.innerHTML;
            btn.innerHTML = '✅ Copied!';
            setTimeout(() => {
                btn.innerHTML = originalText;
            }, 2000);
        }).catch(() => {
            // Fallback
            const textarea = document.createElement('textarea');
            textarea.value = token;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert('Token copied to clipboard!');
        });
    };

    // Add hover effects to buttons
    document.querySelectorAll('.action-buttons a, .btn-primary, .btn-logout').forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
        });
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
});

// Console warning
console.log('%c👺 Fucked By thedigamber', 'font-size: 24px; font-weight: bold; color: #ff6b6b;');
console.log('%cNever share your token.pickle file with anyone!', 'font-size: 14px; color: #ffd93d;');
console.log('%cMade with ❤️ by thedigamber', 'font-size: 12px; color: #6c5ce7;');
