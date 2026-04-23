export async function checkRbac(client, userId, requiredRole) {
  const roleHierarchy = {
    'Admin': 3,
    'Risk Manager': 2,
    'Auditor': 1,
    'Viewer': 0
  };

  const { data, error } = await client
    .from('profiles')
    .select('role')
    .eq('id', userId)
    .single();

  if (error || !data) {
    console.error("RBAC Check Error: Could not fetch user profile", error);
    return false;
  }

  const userRole = data.role || 'Viewer';
  const userLevel = roleHierarchy[userRole] !== undefined ? roleHierarchy[userRole] : 0;
  const requiredLevel = roleHierarchy[requiredRole] !== undefined ? roleHierarchy[requiredRole] : 0;

  return userLevel >= requiredLevel;
}
