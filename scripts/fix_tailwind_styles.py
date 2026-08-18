from pathlib import Path

files = {}

# 1. frontend/postcss.config.js
files['frontend/postcss.config.js'] = '''export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
'''

# 2. frontend/tailwind.config.js
files['frontend/tailwind.config.js'] = '''/** @type {import('tailwindcss').Config} */
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
'''

# 3. frontend/src/index.css
files['frontend/src/index.css'] = '''@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  body {
    background-color: #0b0f19;
    color: #f1f5f9;
    margin: 0;
    padding: 0;
    overflow-x: hidden;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  }
}
'''

for rel_path, content in files.items():
    p = Path(rel_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8')
    print(f'Successfully restored styling: {rel_path}')
