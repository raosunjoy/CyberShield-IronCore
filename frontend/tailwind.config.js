/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Iron Man Color Palette
        arc: {
          blue: '#00D4FF',
          'blue-light': '#4FE4FF',
          'blue-dark': '#0099CC',
          glow: '#00FFFF',
        },
        gold: {
          DEFAULT: '#FFD700',
          light: '#FFED4E',
          dark: '#B8860B',
          metallic: '#D4AF37',
        },
        red: {
          ironman: '#DC143C',
          'ironman-light': '#FF6B6B',
          'ironman-dark': '#8B0000',
        },
        steel: {
          50: '#F8FAFC',
          100: '#F1F5F9',
          200: '#E2E8F0',
          300: '#CBD5E1',
          400: '#94A3B8',
          500: '#64748B',
          600: '#475569',
          700: '#334155',
          800: '#1E293B',
          900: '#0F172A',
          950: '#020817',
        },
        jarvis: {
          primary: '#00D4FF',
          secondary: '#0099CC',
          accent: '#FFD700',
          warning: '#FF6B35',
          danger: '#DC143C',
          success: '#00FF7F',
          background: '#0A0E1A',
          surface: '#1A202C',
          'surface-light': '#2D3748',
        },
        cyber: {
          neon: '#00FFFF',
          'neon-pink': '#FF10F0',
          'neon-green': '#39FF14',
          'neon-orange': '#FF8C00',
          'neon-purple': '#9D4EDD',
        },
      },
      fontFamily: {
        // Iron Man inspired fonts
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
        display: ['Orbitron', 'ui-sans-serif', 'system-ui'],
        jarvis: ['Exo 2', 'ui-sans-serif', 'system-ui'],
      },
      animation: {
        // Arc Reactor animations
        'arc-pulse': 'arc-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'arc-glow': 'arc-glow 3s ease-in-out infinite',
        'arc-spin': 'arc-spin 4s linear infinite',
        hologram: 'hologram 2s ease-in-out infinite alternate',
        glitch: 'glitch 0.5s linear infinite',
        'matrix-rain': 'matrix-rain 3s linear infinite',
        'threat-pulse': 'threat-pulse 1.5s ease-in-out infinite',
        'scan-line': 'scan-line 2s linear infinite',
        'power-up': 'power-up 0.8s ease-out',
        'jarvis-boot': 'jarvis-boot 3s ease-out',
        'hud-flicker': 'hud-flicker 0.1s ease-in-out infinite',
      },
      keyframes: {
        'arc-pulse': {
          '0%, 100%': {
            opacity: '1',
            boxShadow: '0 0 20px #00D4FF, 0 0 40px #00D4FF, 0 0 60px #00D4FF',
          },
          '50%': {
            opacity: '0.8',
            boxShadow: '0 0 10px #00D4FF, 0 0 20px #00D4FF, 0 0 30px #00D4FF',
          },
        },
        'arc-glow': {
          '0%, 100%': {
            filter: 'brightness(1) drop-shadow(0 0 20px #00D4FF)',
          },
          '50%': {
            filter: 'brightness(1.2) drop-shadow(0 0 40px #00D4FF)',
          },
        },
        'arc-spin': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        hologram: {
          '0%': {
            opacity: '0.8',
            transform: 'translateZ(0) scale(1)',
            filter: 'hue-rotate(0deg)',
          },
          '100%': {
            opacity: '1',
            transform: 'translateZ(10px) scale(1.02)',
            filter: 'hue-rotate(10deg)',
          },
        },
        glitch: {
          '0%, 100%': { transform: 'translate(0)' },
          '20%': { transform: 'translate(-2px, 2px)' },
          '40%': { transform: 'translate(-2px, -2px)' },
          '60%': { transform: 'translate(2px, 2px)' },
          '80%': { transform: 'translate(2px, -2px)' },
        },
        'matrix-rain': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'threat-pulse': {
          '0%, 100%': {
            boxShadow: '0 0 20px rgba(220, 20, 60, 0.8)',
            borderColor: 'rgba(220, 20, 60, 0.8)',
          },
          '50%': {
            boxShadow:
              '0 0 40px rgba(220, 20, 60, 1), 0 0 60px rgba(220, 20, 60, 0.8)',
            borderColor: 'rgba(220, 20, 60, 1)',
          },
        },
        'scan-line': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'power-up': {
          '0%': {
            opacity: '0',
            transform: 'scale(0.8) rotateY(-90deg)',
          },
          '50%': {
            opacity: '0.8',
            transform: 'scale(1.1) rotateY(0deg)',
          },
          '100%': {
            opacity: '1',
            transform: 'scale(1) rotateY(0deg)',
          },
        },
        'jarvis-boot': {
          '0%': {
            opacity: '0',
            transform: 'scale(0.9)',
            filter: 'blur(10px)',
          },
          '30%': {
            opacity: '0.6',
            transform: 'scale(1.05)',
            filter: 'blur(2px)',
          },
          '100%': {
            opacity: '1',
            transform: 'scale(1)',
            filter: 'blur(0px)',
          },
        },
        'hud-flicker': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.95' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
      boxShadow: {
        'arc-glow': '0 0 20px #00D4FF, inset 0 0 20px #00D4FF',
        'gold-glow': '0 0 20px #FFD700, inset 0 0 10px #FFD700',
        'threat-glow': '0 0 30px #DC143C, inset 0 0 15px #DC143C',
        'jarvis-glow': '0 0 40px rgba(0, 212, 255, 0.6)',
        hologram: '0 8px 32px rgba(0, 212, 255, 0.3)',
      },
      backgroundImage: {
        'arc-gradient':
          'radial-gradient(circle, #00D4FF 0%, #0099CC 50%, #003F5C 100%)',
        'gold-gradient': 'linear-gradient(135deg, #FFD700 0%, #B8860B 100%)',
        'jarvis-gradient':
          'linear-gradient(135deg, #0A0E1A 0%, #1A202C 50%, #2D3748 100%)',
        'hologram-gradient':
          'linear-gradient(45deg, transparent 30%, rgba(0, 212, 255, 0.1) 50%, transparent 70%)',
        'cyber-grid': `url("data:image/svg+xml,%3csvg width='40' height='40' xmlns='http://www.w3.org/2000/svg'%3e%3cdefs%3e%3cpattern id='grid' width='40' height='40' patternUnits='userSpaceOnUse'%3e%3cpath d='M 40 0 L 0 0 0 40' fill='none' stroke='%2300D4FF' stroke-width='0.5' opacity='0.3'/%3e%3c/pattern%3e%3c/defs%3e%3crect width='100%25' height='100%25' fill='url(%23grid)' /%3e%3c/svg%3e")`,
      },
      spacing: {
        18: '4.5rem',
        88: '22rem',
        128: '32rem',
      },
      borderRadius: {
        arc: '50%',
        hud: '0.75rem',
      },
      zIndex: {
        jarvis: '9999',
        hud: '1000',
        overlay: '999',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    // Custom Iron Man utilities
    function ({ addUtilities, theme }) {
      const newUtilities = {
        '.text-glow': {
          textShadow: `0 0 10px ${theme('colors.arc.blue')}, 0 0 20px ${theme('colors.arc.blue')}, 0 0 30px ${theme('colors.arc.blue')}`,
        },
        '.text-gold-glow': {
          textShadow: `0 0 10px ${theme('colors.gold.DEFAULT')}, 0 0 20px ${theme('colors.gold.DEFAULT')}`,
        },
        '.border-glow': {
          boxShadow: `0 0 10px ${theme('colors.arc.blue')}, inset 0 0 10px ${theme('colors.arc.blue')}`,
        },
        '.hologram-effect': {
          background:
            'linear-gradient(45deg, transparent 30%, rgba(0, 212, 255, 0.1) 50%, transparent 70%)',
          backgroundSize: '20px 20px',
          animation: 'hologram 2s ease-in-out infinite alternate',
        },
        '.jarvis-panel': {
          background: 'rgba(26, 32, 44, 0.9)',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(0, 212, 255, 0.3)',
          borderRadius: '0.75rem',
        },
        '.hud-element': {
          background: 'rgba(0, 0, 0, 0.8)',
          border: '1px solid #00D4FF',
          borderRadius: '0.5rem',
          backdropFilter: 'blur(5px)',
        },
      };
      addUtilities(newUtilities);
    },
  ],
};
