import type {
  AdminPanelResponse,
  ApiErrorBody,
  AuthResponse,
  AuthUser,
  JwtMeta,
} from '../types/auth';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

let inMemoryAccessToken: string | null = null;
let inflightRefresh: Promise<AuthResponse | null> | null = null;

export function getAccessToken(): string | null {
  return inMemoryAccessToken;
}

export function setAccessToken(token: string | null): void {
  inMemoryAccessToken = token;
}

async function parseErrorResponse(res: Response): Promise<ApiError> {
  try {
    const body = (await res.json()) as ApiErrorBody;
    return new ApiError(
      res.status,
      body.error?.code ?? 'REQUEST_FAILED',
      body.error?.message ?? `Permintaan gagal dengan status ${res.status}.`,
    );
  } catch {
    return new ApiError(
      res.status,
      'REQUEST_FAILED',
      `Permintaan gagal dengan status ${res.status}.`,
    );
  }
}

export async function refreshSessionRequest(): Promise<AuthResponse | null> {
  if (inflightRefresh) {
    return inflightRefresh;
  }

  inflightRefresh = (async () => {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include',
    });

    if (!res.ok) {
      inMemoryAccessToken = null;
      return null;
    }

    const data = (await res.json()) as AuthResponse;
    inMemoryAccessToken = data.accessToken;
    return data;
  })();

  try {
    return await inflightRefresh;
  } finally {
    inflightRefresh = null;
  }
}

async function authorizedFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const perform = (token: string | null) => {
    const headers = new Headers(init.headers);
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    return fetch(path, {
      ...init,
      headers,
      credentials: 'include',
    });
  };

  let res = await perform(inMemoryAccessToken);

  if (res.status === 401) {
    const cloned = res.clone();
    const err = await parseErrorResponse(cloned);
    if (err.code === 'TOKEN_EXPIRED' || err.code === 'UNAUTHORIZED') {
      const refreshed = await refreshSessionRequest();
      if (refreshed) {
        res = await perform(refreshed.accessToken);
      }
    }
  }

  if (!res.ok) {
    throw await parseErrorResponse(res);
  }

  return (await res.json()) as T;
}

export async function loginRequest(payload: {
  email: string;
  password: string;
}): Promise<AuthResponse> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw await parseErrorResponse(res);
  }

  const data = (await res.json()) as AuthResponse;
  inMemoryAccessToken = data.accessToken;
  return data;
}

export async function registerRequest(payload: {
  name: string;
  email: string;
  password: string;
}): Promise<AuthResponse> {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    throw await parseErrorResponse(res);
  }

  const data = (await res.json()) as AuthResponse;
  inMemoryAccessToken = data.accessToken;
  return data;
}

export async function logoutRequest(): Promise<void> {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
  } finally {
    inMemoryAccessToken = null;
  }
}

export async function fetchMeRequest(): Promise<{
  user: AuthUser;
  jwt: JwtMeta;
}> {
  return authorizedFetch('/api/me');
}

export async function fetchAdminPanelRequest(): Promise<AdminPanelResponse> {
  return authorizedFetch('/api/admin/panel');
}
