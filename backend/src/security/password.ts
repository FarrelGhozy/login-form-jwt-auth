/**
 * Utilitas hashing password (Argon2id) dan hashing token (SHA-256).
 */

export async function hashPassword(plainPassword: string): Promise<string> {
  return Bun.password.hash(plainPassword, {
    algorithm: 'argon2id',
    memoryCost: 19456,
    timeCost: 2,
  });
}

export async function verifyPassword(plainPassword: string, passwordHash: string): Promise<boolean> {
  return Bun.password.verify(plainPassword, passwordHash);
}

/**
 * Meng-hash raw refresh token sebelum disimpan ke database sehingga token mentah
 * tidak pernah tersimpan plaintext di PostgreSQL.
 */
export function hashToken(rawToken: string): string {
  return new Bun.CryptoHasher('sha256').update(rawToken).digest('hex');
}
