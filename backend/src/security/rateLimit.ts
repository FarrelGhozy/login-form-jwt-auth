/**
 * Sliding-window in-memory rate limiter untuk melindungi endpoint login
 * dan registrasi dari percobaan brute-force beruntun.
 */

interface BucketEntry {
  timestamps: number[];
}

export class SlidingWindowRateLimiter {
  private readonly store = new Map<string, BucketEntry>();

  constructor(
    private readonly maxAttempts: number,
    private readonly windowMs: number,
  ) {}

  consume(key: string): { allowed: boolean; retryAfterSeconds: number; remaining: number } {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const entry = this.store.get(key);
    const active = entry ? entry.timestamps.filter((ts) => ts > cutoff) : [];

    if (active.length >= this.maxAttempts) {
      const oldest = active[0]!;
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1000));
      this.store.set(key, { timestamps: active });
      return { allowed: false, retryAfterSeconds, remaining: 0 };
    }

    active.push(now);
    this.store.set(key, { timestamps: active });
    return {
      allowed: true,
      retryAfterSeconds: 0,
      remaining: Math.max(0, this.maxAttempts - active.length),
    };
  }

  reset(key: string): void {
    this.store.delete(key);
  }

  clearAll(): void {
    this.store.clear();
  }
}

export const loginRateLimiter = new SlidingWindowRateLimiter(10, 60_000);
