/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0f0f0f",
        foreground: "#ffffff",
        card: "#1a1a1a",
        "card-dark": "#141414",
        border: "#2a2a2a",
        primary: "#3b82f6",
        "primary-dark": "#2563eb",
        success: "#10b981",
        warning: "#f59e0b",
        critical: "#ef4444",
        "text-secondary": "#9ca3af",
      },
    },
  },
  plugins: [],
};
