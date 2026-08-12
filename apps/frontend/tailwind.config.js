/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      colors: {
        navy: {
          950: '#080c18',
          900: '#0d1226',
          800: '#111827',
          700: '#1a2540',
          600: '#1e2d4a',
        },
        cognidroid: {
          cyan: '#06b6d4',
          blue: '#3b82f6',
        },
      },
      animation: {
        'fade-in-up': 'fadeInUp 0.4s ease forwards',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scan': 'scan 2s linear infinite',
      },
      keyframes: {
        fadeInUp: {
          from: { opacity: '0', transform: 'translateY(16px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        scan: {
          '0%': { transform: 'translateY(-100%)', opacity: '0' },
          '50%': { opacity: '1' },
          '100%': { transform: 'translateY(200%)', opacity: '0' },
        },
      },
    },
  },
  plugins: [],
}
