import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { env } from '../config/env';

// prepare: false aman untuk direct Postgres maupun Supabase transaction pooler
const client = postgres(env.databaseUrl, { prepare: false });

export const db = drizzle({ client });
export { client };
