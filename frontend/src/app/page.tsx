'use client';

import { useState, useEffect } from 'react';

export default function TestPage() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div
        style={{
          minHeight: '100vh',
          backgroundColor: '#000000',
          color: '#00FF41',
          fontFamily: 'monospace',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div style={{ textAlign: 'center' }}>
          <h1
            style={{
              fontSize: '4rem',
              fontWeight: 'bold',
              marginBottom: '1rem',
            }}
          >
            CYBERSHIELD TEST
          </h1>
          <p style={{ fontSize: '1.5rem', marginBottom: '2rem' }}>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: '#000000',
        color: '#00FF41',
        fontFamily: 'monospace',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div style={{ textAlign: 'center', padding: '2rem' }}>
        <h1
          style={{
            fontSize: '4rem',
            fontWeight: 'bold',
            marginBottom: '1rem',
            textShadow: '0 0 10px #00FF41',
          }}
        >
          CYBERSHIELD TEST
        </h1>
        <p
          style={{
            fontSize: '1.5rem',
            marginBottom: '2rem',
            color: '#00FF41',
          }}
        >
          ✅ BLACK BACKGROUND + GREEN TEXT = WORKING!
        </p>
        <div
          style={{
            fontSize: '3rem',
            animation: 'pulse 2s infinite',
            marginBottom: '2rem',
          }}
        >
          🔥 CYBER WAR ROOM 🔥
        </div>
        <a
          href='/cyber'
          target='_blank'
          style={{
            backgroundColor: '#00FF41',
            color: '#000000',
            padding: '1rem 2rem',
            borderRadius: '8px',
            fontWeight: 'bold',
            textDecoration: 'none',
            display: 'inline-block',
            fontSize: '1.2rem',
            cursor: 'pointer',
            border: 'none',
            boxShadow: '0 0 20px #00FF41',
          }}
          onMouseOver={e => {
            (e.target as HTMLElement).style.backgroundColor = '#40FF71';
          }}
          onMouseOut={e => {
            (e.target as HTMLElement).style.backgroundColor = '#00FF41';
          }}
        >
          ENTER CYBER WAR ROOM
        </a>
      </div>

      <style jsx>{`
        @keyframes pulse {
          0%,
          100% {
            opacity: 1;
          }
          50% {
            opacity: 0.5;
          }
        }
      `}</style>
    </div>
  );
}
