/**
 * Theme System - Cyberpunk (dark-only)
 * Retained for backward compatibility with non-migrated pages.
 * New pages using base.html do not need this file.
 */

(function() {
    'use strict';

    // Force dark theme
    localStorage.setItem('globalTheme', 'dark');

    document.addEventListener('DOMContentLoaded', function() {
        applyDarkTheme();
    });

    window.addEventListener('themeChanged', function(e) {
        applyDarkTheme();
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
        // No-op: cyberpunk is always dark
        applyDarkTheme();
    }

    // Make functions available globally if needed
    window.applyDarkTheme = applyDarkTheme;
    window.applyLightTheme = applyLightTheme;
})();
