import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  out: './drizzle',
  schema: './src/db/schema.ts',
  dialect: 'postgresql',
  // Kelola hanya schema public agar aman jika diarahkan ke database Supabase
  schemaFilter: ['public'],
  dbCredentials: {
    url: (process.env.DIRECT_URL ?? process.env.DATABASE_URL)!,
  },
});
