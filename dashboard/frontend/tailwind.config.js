/** @type {import('tailwindcss').Config} */

// Every colour is a CSS variable holding an RGB triplet, so the same utility
// resolves correctly in light and dark, and opacity modifiers (`bg-fail/10`)
// keep working. Tokens are defined for both themes in src/index.css.
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: token("ink"),
        surface: token("surface"),
        elevated: token("elevated"),
        hairline: token("hairline"),
        "hairline-strong": token("hairline-strong"),
        txt: token("txt"),
        dim: token("dim"),
        faint: token("faint"),
        accent: token("accent"),
        crit: token("crit"),
        high: token("high"),
        med: token("med"),
        low: token("low"),
        pass: token("pass"),
        fail: token("fail"),
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
