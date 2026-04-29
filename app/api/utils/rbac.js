/**
 * Role hierarchy — higher number = more permissions.
 * 'super_admin' sits above 'Admin' and passes every permission gate.
 *
 * DB values are matched case-insensitively so 'Super_Admin', 'SUPER_ADMIN',
 * and 'super_admin' all resolve correctly.
 */
const ROLE_HIERARCHY = {
  'super_admin': 4, // highest — full access to everything
  'admin':       3,
  'risk manager': 2,
  'auditor':     1,
  'user':        1, // default role assigned at signup — same floor as auditor/viewer
  'viewer':      0,
};

/**
 * Returns true when the authenticated user's role is >= requiredRole.
 *
 * @param {object} client      — RLS-scoped Supabase client
 * @param {string} userId      — auth user UUID
 * @param {string} requiredRole — minimum role name (case-insensitive)
 */
export async function checkRbac(client, userId, requiredRole) {
  const { data, error } = await client
    .from('profiles')
    .select('role')
    .eq('id', userId)
    .single();

  if (error || !data) {
    console.error('RBAC Check Error: Could not fetch user profile', error);
    return false;
  }

  // Normalise to lowercase so DB casing ('Admin', 'ADMIN', 'admin') all match
  const userRoleNorm     = (data.role || 'viewer').toLowerCase();
  const requiredRoleNorm = (requiredRole || 'viewer').toLowerCase();

  const userLevel     = ROLE_HIERARCHY[userRoleNorm]     ?? 0;
  const requiredLevel = ROLE_HIERARCHY[requiredRoleNorm] ?? 0;

  return userLevel >= requiredLevel;
}

