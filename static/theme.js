/**
 * Theme Manager
 *
 * To add a new theme:
 *   1. Add a CSS block in styles.css:
 *      [data-theme="<id>"] main, [data-theme="<id>"] .theme-content { ... }
 *   2. Append an entry to THEMES below.
 */
(function () {
    'use strict';

    var THEMES = [
        { id: 'midnight', label: 'Midnight', icon: '\u{1F319}' },
        { id: 'light',  label: 'Light',    icon: '\u{2600}\u{FE0F}' },
        { id: 'dark',     label: 'Dark',     icon: '\u{1F311}' },
        { id: 'split',    label: 'Split',    icon: '\u{25D1}' },
        { id: 'neon',     label: 'Neon',     icon: '\u{1F4A1}' }
    ];

    var STORAGE_KEY = 'certtools-theme';

    function getTheme() {
        return localStorage.getItem(STORAGE_KEY) || 'split';
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
    }

    /* Set attribute immediately (backup for the inline <head> script) */
    document.documentElement.setAttribute('data-theme', getTheme());

    document.addEventListener('DOMContentLoaded', function () {
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
