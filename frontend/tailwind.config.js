/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#07080c",
          900: "#0c0d14",
          800: "#12141d",
          700: "#1a1d2a",
        },
        accent: {
          violet: "#8b6cff",
          indigo: "#6366f1",
          glow: "#a78bfa",
        },
      },
      boxShadow: {
        glow: "0 0 40px rgba(139, 108, 255, 0.18)",
        card: "0 18px 50px rgba(0, 0, 0, 0.35)",
      },
      fontFamily: {
        sans: ["Sora", "Segoe UI", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
