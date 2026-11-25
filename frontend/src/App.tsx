import { AuthCard } from './components/AuthCard';
import { LoggedInPage } from './components/LoggedInPage';
import { AuthProvider, useAuth } from './context/AuthContext';

function AppContent() {
  const { status } = useAuth();

  if (status === 'loading') {
    return (
      <main className="min-h-screen bg-white flex items-center justify-center">
        <p className="text-sm text-slate-400">Memeriksa sesi...</p>
      </main>
    );
  }

  return status === 'authenticated' ? <LoggedInPage /> : <AuthCard />;
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
