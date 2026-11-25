import 'dotenv/config';

/**
 * Mengonversi durasi ringkas seperti "15m", "7d", "1h", atau "30s" menjadi detik.
 */
export function parseDurationToSeconds(value: string, varName: string): number {
  const match = value.trim().match(/^(\d+)([smhd])$/);
  if (!match) {
    throw new Error(
      `Format ${varName} tidak valid ("${value}"). Gunakan angka + satuan s/m/h/d, misalnya "15m" atau "7d".`,
    );
  }

  const amount = Number(match[1]);
  const unit = match[2];
  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
  };

  const multiplier = multipliers[unit!];
  if (!multiplier || amount <= 0) {
    throw new Error(`Nilai ${varName} harus lebih besar dari 0.`);
  }

  return amount * multiplier;
}

function requireNonEmptyEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Environment variable ${name} wajib diisi di file .env`);
  }
  return value;
}

function requireSecret(name: string): string {
  const value = requireNonEmptyEnv(name);
  if (value.length < 32) {
    throw new Error(`${name} harus memiliki panjang minimal 32 karakter.`);
  }
  return value;
}

const accessSecret = requireSecret('JWT_ACCESS_SECRET');
const refreshSecret = requireSecret('JWT_REFRESH_SECRET');

if (accessSecret === refreshSecret) {
  throw new Error('JWT_ACCESS_SECRET dan JWT_REFRESH_SECRET tidak boleh sama.');
}

const accessTtl = process.env.JWT_ACCESS_TTL?.trim() || '15m';
const refreshTtl = process.env.JWT_REFRESH_TTL?.trim() || '7d';

export const env = {
  port: Number(process.env.PORT ?? 3001),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  isProduction: process.env.NODE_ENV === 'production',
  frontendOrigin: process.env.FRONTEND_ORIGIN?.trim() || 'http://localhost:5173',
  databaseUrl: requireNonEmptyEnv('DATABASE_URL'),
  jwtAccessSecret: accessSecret,
  jwtRefreshSecret: refreshSecret,
  jwtAccessTtl: accessTtl,
  jwtRefreshTtl: refreshTtl,
  jwtAccessTtlSeconds: parseDurationToSeconds(accessTtl, 'JWT_ACCESS_TTL'),
  jwtRefreshTtlSeconds: parseDurationToSeconds(refreshTtl, 'JWT_REFRESH_TTL'),
} as const;
