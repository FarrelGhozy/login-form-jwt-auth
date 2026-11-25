import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import { env } from '../config/env';
import type { Role } from './rbac';

const JWT_ISSUER = 'login-form-api';
const JWT_AUDIENCE = 'login-form-web';
const ACCESS_SECRET_KEY = new TextEncoder().encode(env.jwtAccessSecret);
const REFRESH_SECRET_KEY = new TextEncoder().encode(env.jwtRefreshSecret);

export interface AccessTokenClaims {
  sub: string;
  email: string;
  name: string;
  role: Role;
  jti: string;
  iat: number;
  exp: number;
  type: 'access';
}

export interface RefreshTokenClaims {
  sub: string;
  familyId: string;
  jti: string;
  iat: number;
  exp: number;
  type: 'refresh';
}

export class JwtVerificationError extends Error {
  constructor(
    public readonly code: 'TOKEN_EXPIRED' | 'TOKEN_INVALID',
    message: string,
  ) {
    super(message);
    this.name = 'JwtVerificationError';
  }
}

export async function signAccessToken(user: {
  id: string;
  email: string;
  name: string;
  role: Role;
}): Promise<{ token: string; jti: string; iat: number; exp: number }> {
  const jti = crypto.randomUUID();
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expSeconds = nowSeconds + env.jwtAccessTtlSeconds;

  const token = await new SignJWT({
    email: user.email,
    name: user.name,
    role: user.role,
    type: 'access',
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setSubject(user.id)
    .setJti(jti)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expSeconds)
    .sign(ACCESS_SECRET_KEY);

  return { token, jti, iat: nowSeconds, exp: expSeconds };
}

export async function signRefreshToken(params: {
  userId: string;
  familyId: string;
}): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const jti = crypto.randomUUID();
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expSeconds = nowSeconds + env.jwtRefreshTtlSeconds;

  const token = await new SignJWT({
    familyId: params.familyId,
    type: 'refresh',
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setSubject(params.userId)
    .setJti(jti)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expSeconds)
    .sign(REFRESH_SECRET_KEY);

  return {
    token,
    jti,
    expiresAt: new Date(expSeconds * 1000),
  };
}

export async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  try {
    const { payload } = await jwtVerify(token, ACCESS_SECRET_KEY, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (
      payload.type !== 'access' ||
      typeof payload.sub !== 'string' ||
      typeof payload.email !== 'string' ||
      typeof payload.name !== 'string' ||
      (payload.role !== 'user' && payload.role !== 'admin') ||
      typeof payload.jti !== 'string' ||
      typeof payload.iat !== 'number' ||
      typeof payload.exp !== 'number'
    ) {
      throw new JwtVerificationError('TOKEN_INVALID', 'Struktur klaim access token tidak valid.');
    }

    return {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      role: payload.role,
      jti: payload.jti,
      iat: payload.iat,
      exp: payload.exp,
      type: 'access',
    };
  } catch (err) {
    if (err instanceof JwtVerificationError) {
      throw err;
    }
    if (err instanceof joseErrors.JWTExpired) {
      throw new JwtVerificationError('TOKEN_EXPIRED', 'Access token sudah kedaluwarsa.');
    }
    throw new JwtVerificationError('TOKEN_INVALID', 'Access token tidak valid.');
  }
}

export async function verifyRefreshToken(token: string): Promise<RefreshTokenClaims> {
  try {
    const { payload } = await jwtVerify(token, REFRESH_SECRET_KEY, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    if (
      payload.type !== 'refresh' ||
      typeof payload.sub !== 'string' ||
      typeof payload.familyId !== 'string' ||
      typeof payload.jti !== 'string' ||
      typeof payload.iat !== 'number' ||
      typeof payload.exp !== 'number'
    ) {
      throw new JwtVerificationError('TOKEN_INVALID', 'Struktur klaim refresh token tidak valid.');
    }

    return {
      sub: payload.sub,
      familyId: payload.familyId,
      jti: payload.jti,
      iat: payload.iat,
      exp: payload.exp,
      type: 'refresh',
    };
  } catch (err) {
    if (err instanceof JwtVerificationError) {
      throw err;
    }
    if (err instanceof joseErrors.JWTExpired) {
      throw new JwtVerificationError('TOKEN_EXPIRED', 'Refresh token sudah kedaluwarsa.');
    }
    throw new JwtVerificationError('TOKEN_INVALID', 'Refresh token tidak valid.');
  }
}
