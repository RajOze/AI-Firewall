/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'surface-container': '#111625',
        'surface-container-low': '#0d121f',
        'surface-container-high': '#161c2e',
        'surface-container-highest': '#1e263c',
        'outline-variant': '#334155',
        'outline': '#64748b',
        'primary': '#3b82f6',
        'secondary': '#6366f1',
        'on-surface': '#f8fafc',
        'on-surface-variant': '#cbd5e1',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
