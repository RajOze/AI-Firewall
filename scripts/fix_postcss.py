from pathlib import Path

# 1. Update frontend/postcss.config.js to use ONLY tailwindcss
postcss_config = '''export default {
  plugins: {
    tailwindcss: {},
  },
};
'''
Path("frontend/postcss.config.js").write_text(postcss_config, encoding="utf-8")
print("Successfully updated postcss.config.js without autoprefixer")
