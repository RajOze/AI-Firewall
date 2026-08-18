from pathlib import Path
import os

# 1. Delete conflicting postcss.config.js
postcss_file = Path("frontend/postcss.config.js")
if postcss_file.exists():
    os.remove(postcss_file)
    print("✅ Removed conflicting frontend/postcss.config.js")

# 2. Ensure frontend/vite.config.ts uses @tailwindcss/vite
vite_config = '''import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
});
'''
Path("frontend/vite.config.ts").write_text(vite_config, encoding="utf-8")
print("✅ Updated frontend/vite.config.ts")

# 3. Ensure frontend/src/index.css uses Tailwind v4 directive
index_css = '''@import "tailwindcss";

body {
  background-color: #0b0f19;
  color: #f1f5f9;
  margin: 0;
  padding: 0;
  overflow-x: hidden;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
'''
Path("frontend/src/index.css").write_text(index_css, encoding="utf-8")
print("✅ Updated frontend/src/index.css")
