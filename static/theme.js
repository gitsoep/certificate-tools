/**
 * Global Theme Management System
 * Manages light/dark theme switching across all pages
 */

(function() {
    'use strict';

    // Apply saved theme on page load
    document.addEventListener('DOMContentLoaded', function() {
        const savedTheme = localStorage.getItem('globalTheme');
        if (savedTheme === 'dark') {
            applyDarkTheme();
        }
    });

    // Listen to global theme changes from sidebar
    window.addEventListener('themeChanged', function(e) {
        if (e.detail.isDark) {
            applyDarkTheme();
        } else {
            applyLightTheme();
        }
    });

    function applyDarkTheme() {
        const container = document.getElementById('main-container');
        const title = document.getElementById('page-title');
        const subtitle = document.getElementById('page-subtitle');
        
        // Update main container
        if (container) {
            // Preserve max-w-* classes while updating theme colors
            const maxWidthClass = Array.from(container.classList).find(c => c.startsWith('max-w-'));
            const baseClasses = `${maxWidthClass || 'max-w-4xl'} bg-neutral-900 shadow-2xl p-8 md:p-12`;
            container.className = container.className.includes('rounded-lg') 
                ? baseClasses + ' rounded-lg' 
                : baseClasses;
        }
        
        // Update title and subtitle
        if (title) {
            const sizeClasses = Array.from(title.classList).filter(c => c.startsWith('text-') && (c.includes('xl') || c.includes('lg') || c.includes('4xl') || c.includes('5xl'))).join(' ');
            title.className = `${sizeClasses} font-bold text-orange-400 mb-4`;
        }
        if (subtitle) {
            const sizeClasses = Array.from(subtitle.classList).filter(c => c.startsWith('text-') && (c.includes('xl') || c.includes('lg'))).join(' ');
            subtitle.className = `${sizeClasses} text-gray-300 mb-8`;
        }
        
        // Update all headings
        document.querySelectorAll('h2, h3').forEach(heading => {
            heading.className = heading.className.replace('text-gray-800', 'text-orange-400');
        });
        
        // Update all labels
        document.querySelectorAll('label').forEach(label => {
            if (!label.classList.contains('inline-flex') && !label.classList.contains('inline-block')) {
                label.className = label.className.replace('text-gray-700', 'text-gray-300');
            }
        });
        
        // Update all inputs and textareas
        document.querySelectorAll('input[type="text"], input[type="email"], input[type="number"], input[type="password"], textarea, select').forEach(input => {
            input.className = input.className
                .replace('border-gray-300', 'border-neutral-600')
                .replace('bg-white', 'bg-neutral-800')
                .replace('text-gray-900', 'text-gray-100');
            if (!input.className.includes('text-gray-100') && !input.hasAttribute('readonly') && input.type !== 'file') {
                input.classList.add('text-gray-100');
            }
        });
        
        // Update readonly textareas
        document.querySelectorAll('textarea[readonly]').forEach(ta => {
            ta.className = ta.className
                .replace('bg-white', 'bg-neutral-800')
                .replace('border-gray-300', 'border-neutral-600');
            if (!ta.className.includes('text-gray-100')) {
                ta.classList.add('text-gray-100');
            }
        });
        
        // Update regular inputs (non-file)
        document.querySelectorAll('input').forEach(input => {
            if (input.type !== 'file' && input.type !== 'radio' && input.type !== 'checkbox') {
                input.className = input.className
                    .replace('border-gray-300', 'border-neutral-600')
                    .replace('bg-white', 'bg-neutral-800');
                if (!input.className.includes('text-gray-100')) {
                    input.classList.add('text-gray-100');
                }
            }
        });
        
        // Update background boxes
        document.querySelectorAll('.bg-gray-50').forEach(div => {
            div.className = div.className
                .replace('bg-gray-50', 'bg-neutral-800')
                .replace('border-gray-200', 'border-neutral-600');
        });
        
        // Update paragraphs and list items
        document.querySelectorAll('p, li').forEach(el => {
            el.className = el.className.replace('text-gray-700', 'text-gray-300');
        });
        
        // Update strong elements
        document.querySelectorAll('strong').forEach(el => {
            el.className = el.className.replace('text-gray-900', 'text-orange-300');
        });
        
        // Update any remaining text-gray-900 elements
        document.querySelectorAll('.text-gray-900').forEach(el => {
            el.className = el.className.replace('text-gray-900', 'text-gray-100');
        });
        
        // Update info banners
        document.querySelectorAll('.bg-blue-50').forEach(div => {
            div.className = div.className.replace('bg-blue-50', 'bg-blue-900');
        });
        
        document.querySelectorAll('.text-blue-800').forEach(el => {
            el.className = el.className.replace('text-blue-800', 'text-blue-200');
        });
    }

    function applyLightTheme() {
        const container = document.getElementById('main-container');
        const title = document.getElementById('page-title');
        const subtitle = document.getElementById('page-subtitle');
        
        // Update main container
        if (container) {
            const maxWidthClass = Array.from(container.classList).find(c => c.startsWith('max-w-'));
            const baseClasses = `${maxWidthClass || 'max-w-4xl'} bg-white shadow-2xl p-8 md:p-12`;
            container.className = container.className.includes('rounded-lg') 
                ? baseClasses + ' rounded-lg' 
                : baseClasses;
        }
        
        // Update title and subtitle
        if (title) {
            const sizeClasses = Array.from(title.classList).filter(c => c.startsWith('text-') && (c.includes('xl') || c.includes('lg') || c.includes('4xl') || c.includes('5xl'))).join(' ');
            title.className = `${sizeClasses} font-bold text-gray-800 mb-4`;
        }
        if (subtitle) {
            const sizeClasses = Array.from(subtitle.classList).filter(c => c.startsWith('text-') && (c.includes('xl') || c.includes('lg'))).join(' ');
            subtitle.className = `${sizeClasses} text-gray-600 mb-8`;
        }
        
        // Update all headings
        document.querySelectorAll('h2, h3').forEach(heading => {
            heading.className = heading.className.replace('text-orange-400', 'text-gray-800');
        });
        
        // Update all labels
        document.querySelectorAll('label').forEach(label => {
            if (!label.classList.contains('inline-flex') && !label.classList.contains('inline-block')) {
                label.className = label.className.replace('text-gray-300', 'text-gray-700');
            }
        });
        
        // Update all inputs and textareas
        document.querySelectorAll('input[type="text"], input[type="email"], input[type="number"], input[type="password"], textarea, select').forEach(input => {
            input.className = input.className
                .replace('border-neutral-600', 'border-gray-300')
                .replace('bg-neutral-800', 'bg-white')
                .replace('text-gray-100', 'text-gray-900');
        });
        
        // Update readonly textareas
        document.querySelectorAll('textarea[readonly]').forEach(ta => {
            ta.className = ta.className
                .replace('bg-neutral-800', 'bg-white')
                .replace('border-neutral-600', 'border-gray-300')
                .replace('text-gray-100', 'text-gray-900');
        });
        
        // Update regular inputs
        document.querySelectorAll('input').forEach(input => {
            if (input.type !== 'file' && input.type !== 'radio' && input.type !== 'checkbox') {
                input.className = input.className
                    .replace('border-neutral-600', 'border-gray-300')
                    .replace('bg-neutral-800', 'bg-white')
                    .replace('text-gray-100', 'text-gray-900');
            }
        });
        
        // Update background boxes
        document.querySelectorAll('.bg-neutral-800').forEach(div => {
            if (div.classList.contains('border-neutral-600')) {
                div.className = div.className
                    .replace('bg-neutral-800', 'bg-gray-50')
                    .replace('border-neutral-600', 'border-gray-200');
            }
        });
        
        // Update paragraphs and list items
        document.querySelectorAll('p, li').forEach(el => {
            el.className = el.className.replace('text-gray-300', 'text-gray-700');
        });
        
        // Update strong elements
        document.querySelectorAll('strong').forEach(el => {
            el.className = el.className.replace('text-orange-300', 'text-gray-900');
        });
        
        // Restore any text-gray-100 back to text-gray-900
        document.querySelectorAll('.text-gray-100').forEach(el => {
            if (!el.tagName.match(/INPUT|TEXTAREA|SELECT/)) {
                el.className = el.className.replace('text-gray-100', 'text-gray-900');
            }
        });
        
        // Update info banners
        document.querySelectorAll('.bg-blue-900').forEach(div => {
            div.className = div.className.replace('bg-blue-900', 'bg-blue-50');
        });
        
        document.querySelectorAll('.text-blue-200').forEach(el => {
            el.className = el.className.replace('text-blue-200', 'text-blue-800');
        });
    }

    // Make functions available globally if needed
    window.applyDarkTheme = applyDarkTheme;
    window.applyLightTheme = applyLightTheme;
})();
