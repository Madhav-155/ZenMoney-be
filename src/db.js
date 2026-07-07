const { Pool } = require('pg');
require('dotenv').config();

const connectionString = process.env.LOCAL_DB_URL;

if (!connectionString) {
  console.error("Error: LOCAL_DB_URL environment variable is not defined.");
  process.exit(1);
}

const pool = new Pool({
  connectionString,
});

const initializeDatabase = async () => {
  const client = await pool.connect();
  try {
    console.log("Connecting to database and initializing schemas...");

    // Enable pgcrypto extension for UUID generation
    await client.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

    // Create public.users table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    // Create public profiles table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.profiles (
        id UUID NOT NULL PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
        username TEXT,
        display_name TEXT,
        avatar_url TEXT,
        ui_mode TEXT NOT NULL DEFAULT 'standard' CHECK (ui_mode IN ('standard', 'easy')),
        monthly_budget NUMERIC NOT NULL DEFAULT 30000,
        report_timezone TEXT NOT NULL DEFAULT 'UTC',
        reports_enabled BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // Create unique index on username if not exists
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS profiles_username_idx ON public.profiles (LOWER(username));
    `);

    // Create groups table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.groups (
        id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
        name TEXT NOT NULL,
        created_by UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // Create group members table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.group_members (
        id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
        group_id UUID NOT NULL REFERENCES public.groups(id) ON DELETE CASCADE,
        user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        balance NUMERIC NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE(group_id, user_id)
      );
    `);

    // Create transactions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.transactions (
        id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        amount NUMERIC NOT NULL,
        vendor TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Uncategorized',
        source TEXT NOT NULL DEFAULT 'Cash' CHECK (source IN ('UPI', 'CC', 'Cash', 'Bank')),
        is_recurring BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        group_id UUID REFERENCES public.groups(id) ON DELETE SET NULL
      );
    `);

    // Create subscriptions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.subscriptions (
        id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        service_name TEXT NOT NULL,
        cost NUMERIC NOT NULL,
        next_billing_date DATE NOT NULL,
        trial_end_date DATE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // Create report threads table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.report_threads (
        id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        month_start DATE NOT NULL,
        thread_message_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (user_id, month_start)
      );
    `);

    // Create report runs table
    await client.query(`
      CREATE TABLE IF NOT EXISTS public.report_runs (
        id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        report_type TEXT NOT NULL CHECK (report_type IN ('weekly', 'monthly')),
        period_start DATE NOT NULL,
        period_end DATE NOT NULL,
        message_id TEXT NOT NULL,
        thread_message_id TEXT NOT NULL,
        sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (user_id, report_type, period_start, period_end)
      );
    `);

    console.log("Database initialized successfully!");
  } catch (err) {
    console.error("Database initialization failed:", err);
    throw err;
  } finally {
    client.release();
  }
};

module.exports = {
  pool,
  query: (text, params) => pool.query(text, params),
  initializeDatabase
};
