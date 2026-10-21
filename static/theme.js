/**
 * Theme Manager
 *
 * To add a new theme:
 *   1. Add a CSS block in styles.css:
 *      [data-theme="<id>"] main, [data-theme="<id>"] .theme-content { ... }
 *   2. Append an entry to THEMES below.
 *   3. Add the id to AVAILABLE_THEMES in app/config.py (so DEFAULT_THEME accepts it).
 */
(function () {
    'use strict';

    var THEMES = [
        { id: 'midnight', label: 'Midnight', icon: '\u{1F319}' },
        { id: 'light',  label: 'Light',    icon: '\u{2600}\u{FE0F}' },
        { id: 'dark',     label: 'Dark',     icon: '\u{1F311}' },
        { id: 'split',    label: 'Split',    icon: '\u{25D1}' },
        { id: 'neon',     label: 'Neon',     icon: '\u{1F4A1}' },
        { id: 'mosadex',  label: 'Mosadex',  icon: '\u{2B2D}' },
        { id: 'mosadex-dark', label: 'Mosadex Dark', icon: '\u{2B2C}' }
    ];

    var STORAGE_KEY = 'certtools-theme';

    function getTheme() {
        return localStorage.getItem(STORAGE_KEY)
            || document.documentElement.getAttribute('data-default-theme')
            || 'split';
    }

    function applyTheme(id) {
        var theme = THEMES.find(function (t) { return t.id === id; }) || THEMES[0];
        document.documentElement.setAttribute('data-theme', theme.id);
        localStorage.setItem(STORAGE_KEY, theme.id);
        updatePicker(theme);
    }

    function cycleTheme() {
        var current = getTheme();
        var idx = THEMES.findIndex(function (t) { return t.id === current; });
        var next = THEMES[(idx + 1) % THEMES.length];
        applyTheme(next.id);
    }

    function updatePicker(theme) {
        var btn = document.getElementById('theme-toggle');
        if (!btn) return;
        var icon  = btn.querySelector('.theme-icon');
        var label = btn.querySelector('.theme-label');
        if (icon)  icon.textContent  = theme.icon;
        if (label) label.textContent = theme.label;

        var menu = document.getElementById('theme-menu');
        if (!menu) return;
        menu.querySelectorAll('[role="option"]').forEach(function (opt) {
            var selected = opt.getAttribute('data-theme-id') === theme.id;
            opt.setAttribute('aria-selected', selected ? 'true' : 'false');
        });
    }

    /* --- Dropdown --- */
    function buildMenu(menu) {
        menu.innerHTML = '';
        THEMES.forEach(function (t) {
            var li = document.createElement('li');
            li.id = 'theme-opt-' + t.id;
            li.setAttribute('role', 'option');
            li.setAttribute('data-theme-id', t.id);
            li.className = 'theme-option';

            var icon = document.createElement('span');
            icon.className = 'theme-option-icon';
            icon.textContent = t.icon;
            var label = document.createElement('span');
            label.className = 'theme-option-label';
            label.textContent = t.label;
            var check = document.createElement('span');
            check.className = 'theme-option-check';
            check.setAttribute('aria-hidden', 'true');
            check.textContent = '\u2713';

            li.appendChild(icon);
            li.appendChild(label);
            li.appendChild(check);
            menu.appendChild(li);
        });
    }

    function initPicker() {
        var btn  = document.getElementById('theme-toggle');
        var menu = document.getElementById('theme-menu');
        if (!btn || !menu) return;

        buildMenu(menu);
        var options = function () { return Array.prototype.slice.call(menu.querySelectorAll('[role="option"]')); };
        var activeIdx = -1;

        function setActive(idx) {
            var opts = options();
            if (!opts.length) return;
            activeIdx = (idx + opts.length) % opts.length;
            opts.forEach(function (o, i) { o.classList.toggle('is-active', i === activeIdx); });
            menu.setAttribute('aria-activedescendant', opts[activeIdx].id);
            opts[activeIdx].scrollIntoView({ block: 'nearest' });
        }

        function open() {
            menu.hidden = false;
            btn.setAttribute('aria-expanded', 'true');
            var current = THEMES.findIndex(function (t) { return t.id === getTheme(); });
            setActive(current < 0 ? 0 : current);
            menu.focus();
        }

        function close(returnFocus) {
            if (menu.hidden) return;
            menu.hidden = true;
            btn.setAttribute('aria-expanded', 'false');
            menu.removeAttribute('aria-activedescendant');
            if (returnFocus) btn.focus();
        }

        function choose(idx) {
            var opt = options()[idx];
            if (!opt) return;
            applyTheme(opt.getAttribute('data-theme-id'));
            close(true);
        }

        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            if (menu.hidden) { open(); } else { close(false); }
        });

        btn.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                e.preventDefault();
                open();
            }
        });

        menu.addEventListener('click', function (e) {
            var opt = e.target.closest('[role="option"]');
            if (opt) choose(options().indexOf(opt));
        });

        menu.addEventListener('mousemove', function (e) {
            var opt = e.target.closest('[role="option"]');
            if (opt) setActive(options().indexOf(opt));
        });

        menu.addEventListener('keydown', function (e) {
            switch (e.key) {
                case 'ArrowDown': e.preventDefault(); setActive(activeIdx + 1); break;
                case 'ArrowUp':   e.preventDefault(); setActive(activeIdx - 1); break;
                case 'Home':      e.preventDefault(); setActive(0); break;
                case 'End':       e.preventDefault(); setActive(options().length - 1); break;
                case 'Enter':
                case ' ':         e.preventDefault(); choose(activeIdx); break;
                case 'Escape':    e.preventDefault(); close(true); break;
                case 'Tab':       close(false); break;
            }
        });

        document.addEventListener('click', function (e) {
            if (!document.getElementById('theme-picker').contains(e.target)) close(false);
        });
    }

    /* Set attribute immediately (backup for the inline <head> script) */
    document.documentElement.setAttribute('data-theme', getTheme());

    document.addEventListener('DOMContentLoaded', function () {
        initPicker();
        var theme = THEMES.find(function (t) { return t.id === getTheme(); }) || THEMES[0];
        updatePicker(theme);
    });

    /* Public API */
    window.themeManager = {
        apply: applyTheme,
        cycle: cycleTheme,
        get:   getTheme,
        list:  function () { return THEMES.slice(); }
    };

    /* Backward-compat stubs for old (non-migrated) pages */
    window.applyDarkTheme  = function () {};
    window.applyLightTheme = function () {};
})();
