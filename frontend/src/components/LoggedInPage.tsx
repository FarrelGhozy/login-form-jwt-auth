import { useState } from 'react';
import { LogOut, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ApiError, fetchAdminPanelRequest } from '../lib/api';
import type { AdminPanelResponse } from '../types/auth';
import { FgLogo } from './FgLogo';

type AdminCheckState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'allowed'; statusCode: number; payload: AdminPanelResponse }
  | { kind: 'denied'; statusCode: number; code: string; message: string };

export function LoggedInPage() {
  const { user, jwtMeta, refreshSession, logout } = useAuth();
  const [adminCheck, setAdminCheck] = useState<AdminCheckState>({ kind: 'idle' });
  const [refreshStatus, setRefreshStatus] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  async function handleCheckAdminAccess() {
    setAdminCheck({ kind: 'loading' });
    try {
      const payload = await fetchAdminPanelRequest();
      setAdminCheck({
        kind: 'allowed',
        statusCode: 200,
        payload,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setAdminCheck({
          kind: 'denied',
          statusCode: err.status,
          code: err.code,
          message: err.message,
        });
      } else {
        setAdminCheck({
          kind: 'denied',
          statusCode: 500,
          code: 'NETWORK_ERROR',
          message: 'Gagal memanggil endpoint /api/admin/panel.',
        });
      }
    }
  }

  async function handleRefreshJwt() {
    setRefreshing(true);
    setRefreshStatus(null);
    try {
      const previousJti = jwtMeta?.jti;
      const updated = await refreshSession();
      if (updated) {
        setRefreshStatus(
          previousJti && previousJti !== updated.jwt.jti
            ? `JWT dirotasi (${updated.jwt.jti.slice(0, 8)}...)`
            : 'JWT diperbarui.',
        );
      }
    } finally {
      setRefreshing(false);
    }
  }

  const expiryText = jwtMeta
    ? new Date(jwtMeta.exp * 1000).toLocaleTimeString('id-ID', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '-';

  return (
    <main className="min-h-screen bg-white text-slate-900 flex flex-col items-center justify-center px-6 py-12">
      <div className="w-full max-w-lg text-center">
        {/* Tampilan utama sesuai permintaan: halaman putih bersih bertuliskan "Anda sudah login" */}
        <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-slate-900">
          Anda sudah login
        </h1>

        {/* Info singkat akun & JWT aktif */}
        {user && (
          <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-sm text-slate-500">
            <span>{user.email}</span>
            <span aria-hidden="true">•</span>
            <span
              className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${
                user.role === 'admin'
                  ? 'bg-slate-900 text-white'
                  : 'bg-slate-100 text-slate-700'
              }`}
            >
              {user.role}
            </span>
            {jwtMeta && (
              <>
                <span aria-hidden="true">•</span>
                <span className="font-mono text-xs text-slate-400">
                  jti:{jwtMeta.jti.slice(0, 8)} (exp {expiryText})
                </span>
              </>
            )}
          </div>
        )}

        {/* Kontrol minimalis untuk Authorization, Refresh JWT, dan Logout */}
        <div className="mt-7 flex flex-wrap items-center justify-center gap-2.5">
          <button
            type="button"
            onClick={handleCheckAdminAccess}
            disabled={adminCheck.kind === 'loading'}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-60"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            {adminCheck.kind === 'loading' ? 'Memeriksa...' : 'Uji Akses Admin'}
          </button>

          <button
            type="button"
            onClick={handleRefreshJwt}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-60"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh JWT
          </button>

          <button
            type="button"
            onClick={logout}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-medium text-slate-700 transition hover:border-red-200 hover:bg-red-50 hover:text-red-700"
          >
            <LogOut className="h-3.5 w-3.5" />
            Logout
          </button>
        </div>

        {refreshStatus && (
          <p className="mt-3 text-xs text-slate-500">{refreshStatus}</p>
        )}

        {/* Hasil uji Authorization (hanya tampil setelah tombol diklik) */}
        {adminCheck.kind === 'allowed' && (
          <div className="mt-6 rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 text-left text-xs text-emerald-900">
            <div className="flex items-center gap-2 font-semibold">
              <ShieldCheck className="h-4 w-4 text-emerald-600" />
              <span>
                {adminCheck.statusCode} OK — {adminCheck.payload.message}
              </span>
            </div>
            {adminCheck.payload.recentAuditLogs.length > 0 && (
              <div className="mt-2.5 border-t border-emerald-200/70 pt-2">
                <p className="mb-1 font-medium text-emerald-800">Audit Log Terbaru:</p>
                <ul className="space-y-1 font-mono text-[11px] text-emerald-800">
                  {adminCheck.payload.recentAuditLogs.map((log) => (
                    <li key={log.id}>
                      [{log.action}] {log.email}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {adminCheck.kind === 'denied' && (
          <div className="mt-6 rounded-xl border border-amber-200 bg-amber-50/80 p-4 text-left text-xs text-amber-900">
            <div className="flex items-center gap-2 font-semibold">
              <ShieldAlert className="h-4 w-4 text-amber-600" />
              <span>
                {adminCheck.statusCode} {adminCheck.code}
              </span>
            </div>
            <p className="mt-1 text-amber-800">{adminCheck.message}</p>
          </div>
        )}
      </div>

      <footer className="mt-12 flex items-center justify-center gap-2 text-xs text-slate-400">
        <FgLogo size={18} />
        <span>Dibuat oleh Farrel Ghozy</span>
      </footer>
    </main>
  );
}
