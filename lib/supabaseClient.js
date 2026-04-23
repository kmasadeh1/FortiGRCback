import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

/**
 * Validates that required Supabase env vars are present.
 * Called lazily at request time (not module load time) so that
 * `next build` doesn't crash when .env.local is absent.
 */
function ensureEnvVars() {
  if (!supabaseUrl || !supabaseAnonKey) {
    throw new Error(
      "Missing Supabase environment variables. " +
        "Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in .env.local"
    );
  }
}

/** @type {import("@supabase/supabase-js").SupabaseClient | null} */
let _supabase = null;

/**
 * Anonymous Supabase client (singleton, lazily created).
 * Used for auth operations (signup, login) where no user token exists yet.
 */
export function getSupabase() {
  if (!_supabase) {
    ensureEnvVars();
    _supabase = createClient(supabaseUrl, supabaseAnonKey);
  }
  return _supabase;
}

// Keep the named export for backward compatibility — it resolves to null
// at module-load time if env vars are missing, so prefer getSupabase() instead.
export const supabase = supabaseUrl && supabaseAnonKey
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

/**
 * Creates a Supabase client scoped to a specific user's JWT.
 *
 * Supabase uses the JWT's `sub` claim as `auth.uid()` in RLS policies,
 * so all queries through this client are automatically scoped to the user's data.
 *
 * @param {string} accessToken — The user's Supabase access_token (JWT)
 * @returns {import("@supabase/supabase-js").SupabaseClient}
 */
export function createAuthenticatedClient(accessToken) {
  ensureEnvVars();
  return createClient(supabaseUrl, supabaseAnonKey, {
    global: {
      headers: { Authorization: `Bearer ${accessToken}` },
    },
  });
}
