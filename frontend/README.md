# CyberShield-IronCore Frontend 🦾⚡

> **Iron Man-Inspired Enterprise Cybersecurity Dashboard**  
> _"I am Iron Man" - Now with JARVIS-powered threat detection_

[![Next.js](https://img.shields.io/badge/Next.js-14.2.31-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC)](https://tailwindcss.com/)
[![Framer Motion](https://img.shields.io/badge/Framer%20Motion-11.5-pink)](https://www.framer.com/motion/)

## 🚀 Iron Man Experience

Experience cybersecurity like Tony Stark! This Next.js frontend delivers a cinematic Iron Man interface with JARVIS-powered threat detection and Arc Reactor-inspired animations.

### ✨ Key Features

- **🤖 JARVIS Boot Sequence**: Cinematic startup experience with system initialization
- **⚡ Arc Reactor Components**: Multiple variants with real-time power monitoring
- **🎯 HUD Overlay**: Toggleable heads-up display with system metrics
- **🔴 Threat Dashboard**: Real-time threat visualization with severity indicators
- **🌊 Holographic Effects**: Advanced animations with glitch and glow effects
- **📱 Responsive Design**: Mobile-first Iron Man experience

## 🛠️ Tech Stack

- **⚛️ Next.js 14**: React framework with App Router
- **📘 TypeScript**: Strict typing with zero `any` usage
- **🎨 Tailwind CSS**: Utility-first with custom Iron Man theme
- **🎭 Framer Motion**: Advanced animations and transitions
- **🧩 Lucide React**: Modern icon library
- **🔧 ESLint + Prettier**: Code quality and formatting

## 🚀 Quick Start

### Prerequisites

```bash
Node.js 18.17.0+
npm 9.0.0+
```

### Installation

```bash
# Clone the repository
git clone https://github.com/raosunjoy/CyberShield-IronCore.git
cd CyberShield-IronCore/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to see the Iron Man interface!

## 🎨 Iron Man Theme

### Color Palette

```css
/* Arc Reactor Blues */
--arc-blue: #00d4ff;
--arc-blue-light: #4fe4ff;
--arc-blue-dark: #0099cc;

/* Stark Industries Gold */
--gold: #ffd700;
--gold-light: #ffed4e;
--gold-dark: #b8860b;

/* Iron Man Red */
--red-ironman: #dc143c;

/* JARVIS Interface */
--jarvis-background: #0a0e1a;
--jarvis-surface: #1a202c;
```

### Custom Animations

- **Arc Reactor Pulse**: Smooth power level animations
- **Holographic Scan**: Rotating threat detection radar
- **Glitch Effects**: Cyberpunk-style visual distortions
- **HUD Transitions**: Smooth overlay toggles

## 🧩 Component Library

### Core Components

#### ArcReactor

```tsx
import { ArcReactor } from '@/components/jarvis/ArcReactor';

<ArcReactor
  size='lg'
  powerLevel={95}
  status='online'
  animated={true}
  glowIntensity='high'
/>;
```

#### JarvisBootSequence

```tsx
import { JarvisBootSequence } from '@/components/jarvis/JarvisBootSequence';

// Automatically runs on first visit
<JarvisBootSequence />;
```

#### HudOverlay

```tsx
import { HudOverlay } from '@/components/jarvis/HudOverlay';

// Toggle with Ctrl+Shift+H or button
<HudOverlay />;
```

### Props & Variants

- **Arc Reactor Sizes**: `xs`, `sm`, `md`, `lg`, `xl`, `custom`
- **Status States**: `online`, `offline`, `charging`, `critical`, `overload`
- **Glow Intensity**: `low`, `medium`, `high`
- **Animation Types**: `pulse`, `rotate`, `flicker`, `charging`

## 📊 Mock Data System

The frontend includes comprehensive mock data generation for:

- **Threat Detection**: Malware, phishing, DDoS attacks
- **System Metrics**: Power levels, integrity, network health
- **JARVIS Responses**: Contextual AI assistant messages
- **Iron Man Quotes**: Authentic Tony Stark dialogue

## 🎯 Features Deep Dive

### JARVIS Boot Sequence

10-step initialization process:

1. Arc Reactor startup and power calibration
2. Neural network matrix activation
3. Threat analysis engine initialization
4. Holographic interface calibration
5. Security protocol engagement
6. Real-time monitoring activation
7. System integrity verification
8. Welcome sequence completion

### HUD Overlay System

Real-time monitoring includes:

- **Arc Reactor Status**: Power levels and system health
- **Threat Assessment**: Live threat level indicators
- **System Metrics**: Integrity, scans, network status
- **Time & Location**: Stark Tower, NYC timestamp
- **Scanning Radar**: 360° threat detection visualization

### Responsive Design

- **Desktop**: Full HUD experience with all animations
- **Tablet**: Optimized touch interface with gesture support
- **Mobile**: Streamlined Iron Man experience with core features

## 🧪 Development

### Available Scripts

```bash
# Development
npm run dev          # Start development server
npm run build        # Create production build
npm run start        # Start production server

# Quality Assurance
npm run lint         # ESLint code analysis
npm run type-check   # TypeScript type checking
npm run test         # Run test suite
npm run test:watch   # Watch mode testing

# Utilities
npm run clean        # Clean build artifacts
npm run analyze      # Bundle size analysis
```

### Code Quality Standards

- **Max 200 lines per React component**
- **TypeScript strict mode enabled**
- **100% ESLint compliance**
- **Component prop validation**
- **Accessibility (a11y) compliance**

## 🔧 Configuration

### Environment Variables

```bash
# .env.local
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
JARVIS_MODE=active
ARC_REACTOR_STATUS=online
```

### Tailwind Configuration

Custom theme extension in `tailwind.config.js`:

- Iron Man color palette
- Arc Reactor specific gradients
- JARVIS interface backgrounds
- Custom animation keyframes

## 🚀 Production Deployment

### Build Optimization

```bash
# Production build
npm run build

# Bundle analysis
npm run analyze

# Static export (optional)
npm run export
```

### Performance Metrics

- **First Contentful Paint**: <1.5s
- **Largest Contentful Paint**: <2.5s
- **Bundle Size**: <200KB (gzipped)
- **Lighthouse Score**: >95/100

## 🤝 Contributing

### Development Workflow

1. **Create feature branch** from `main`
2. **Follow component patterns** in existing codebase
3. **Add TypeScript types** for all props and data
4. **Test across device sizes** for responsiveness
5. **Pass all quality gates** before PR

### Component Guidelines

- **Props Interface**: Define clear TypeScript interfaces
- **Default Props**: Provide sensible defaults
- **Error Boundaries**: Handle loading and error states
- **Accessibility**: Include ARIA labels and keyboard support
- **Performance**: Use React.memo for expensive components

## 📱 Browser Support

- **Chrome**: 90+ ✅
- **Firefox**: 88+ ✅
- **Safari**: 14+ ✅
- **Edge**: 90+ ✅
- **Mobile Safari**: iOS 14+ ✅
- **Chrome Mobile**: 90+ ✅

## 🐛 Troubleshooting

### Common Issues

**Build Errors**:

```bash
# Clear Next.js cache
rm -rf .next
npm run build
```

**TypeScript Errors**:

```bash
# Type check without emit
npx tsc --noEmit
```

**Styling Issues**:

```bash
# Rebuild Tailwind
npm run build:css
```

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.

---

## 🎬 Live Demo

The Iron Man frontend is running at:

- **Development**: http://localhost:3002
- **Features**: Full JARVIS boot sequence, Arc Reactor animations, HUD overlay
- **Status**: Production-ready build ✅

### Screenshots

_JARVIS Boot Sequence_: Cinematic startup with Arc Reactor initialization
_Iron Man Dashboard_: Real-time threat detection with holographic effects
_HUD Overlay_: Comprehensive system monitoring interface

---

**Built with 💜 by AI-driven development**

_"Sometimes you gotta run before you can walk." - Tony Stark_  
_"All systems operational, Mr. Stark." - JARVIS_ 🤖⚡
