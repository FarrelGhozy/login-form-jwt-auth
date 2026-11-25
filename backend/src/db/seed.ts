import { eq } from 'drizzle-orm';
import { db } from '../db';
import { users } from '../db/schema';
import { hashPassword } from '../security/password';
import type { Role } from '../security/rbac';

const DEMO_USERS: ReadonlyArray<{
  name: string;
  email: string;
  password: string;
  role: Role;
}> = [
  {
    name: 'Admin Demo',
    email: 'admin@demo.local',
    password: 'Admin123!',
    role: 'admin',
  },
  {
    name: 'User Demo',
    email: 'user@demo.local',
    password: 'User123!',
    role: 'user',
  },
];

export async function seedDemoUsers(): Promise<void> {
  for (const account of DEMO_USERS) {
    const existing = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, account.email))
      .limit(1);

    const passwordHash = await hashPassword(account.password);

    if (existing.length === 0) {
      await db.insert(users).values({
        name: account.name,
        email: account.email,
        passwordHash,
        role: account.role,
        isActive: true,
      });
    } else {
      await db
        .update(users)
        .set({
          name: account.name,
          passwordHash,
          role: account.role,
          isActive: true,
          updatedAt: new Date(),
        })
        .where(eq(users.email, account.email));
    }
  }
}

if (import.meta.main) {
  await seedDemoUsers();
  console.log('Seed akun demo selesai:');
  console.log('- Admin: admin@demo.local / Admin123! (role: admin)');
  console.log('- User : user@demo.local  / User123!  (role: user)');
  process.exit(0);
}
