import { useId } from 'react';

interface FgLogoProps {
  size?: number;
  className?: string;
}

/**
 * Monogram logo FG (Farrel Ghozy) bergaya modern minimalis.
 */
export function FgLogo({ size = 48, className = '' }: FgLogoProps) {
  const uid = useId();
  const bgId = `fg-bg-${uid}`;
  const glowId = `fg-glow-${uid}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Logo FG Farrel Ghozy"
      className={className}
    >
      <defs>
        <linearGradient id={bgId} x1="6" y1="4" x2="58" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0F172A" />
          <stop offset="100%" stopColor="#1E293B" />
        </linearGradient>
        <radialGradient
          id={glowId}
          cx="0"
          cy="0"
          r="1"
          gradientUnits="userSpaceOnUse"
          gradientTransform="translate(14 10) rotate(45) scale(52)"
        >
          <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.22" />
          <stop offset="100%" stopColor="#38BDF8" stopOpacity="0" />
        </radialGradient>
      </defs>

      <rect x="2" y="2" width="60" height="60" rx="16" fill={`url(#${bgId})`} />
      <rect x="2" y="2" width="60" height="60" rx="16" fill={`url(#${glowId})`} />
      <rect
        x="2.75"
        y="2.75"
        width="58.5"
        height="58.5"
        rx="15.25"
        stroke="#FFFFFF"
        strokeOpacity="0.14"
        strokeWidth="1.5"
      />

      {/* Monogram F */}
      <path
        d="M15.5 42V22H27M15.5 32H24.5"
        stroke="#F8FAFC"
        strokeWidth="4.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Monogram G */}
      <path
        d="M47.8 25.8C46.5 23.2 44.2 22 41.3 22C37.1 22 34.5 25.5 34.5 32C34.5 38.5 37.1 42 41.5 42C45.3 42 48.5 39.4 48.5 35.2V32.2H42"
        stroke="#F8FAFC"
        strokeWidth="4.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
