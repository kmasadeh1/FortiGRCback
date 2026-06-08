import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';

export async function GET() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

    const { data: profile } = await supabase
      .from('profiles')
      .select('role')
      .eq('id', user.id)
      .single();

    const role = profile?.role || 'user';
    const notifications = [];
    const today = new Date();

    // 1. WAIVER STATUS NOTIFICATIONS (for regular users)
    // Show when their waiver was approved or denied
    if (role === 'user') {
      const { data: myWaivers } = await supabase
        .from('risk_exceptions')
        .select('id, status, expiration_date, justification, risks(title)')
        .eq('requested_by', user.id)
        .in('status', ['Approved', 'Denied']);

      (myWaivers || []).forEach(w => {
        notifications.push({
          id: `waiver-${w.id}`,
          type: w.status === 'Approved' ? 'success' : 'error',
          icon: w.status === 'Approved' ? 'fa-circle-check' : 'fa-circle-xmark',
          title: `Waiver ${w.status}`,
          message: `Your waiver for "${w.risks?.title || 'Unknown Risk'}" was ${w.status.toLowerCase()}`,
          link: '/risks',
        });
      });
    }

    // 2. EXPIRING WAIVER NOTIFICATIONS (for all roles)
    // Show waivers expiring within 7 days
    const in7Days = new Date();
    in7Days.setDate(today.getDate() + 7);

    let waiverQuery = supabase
      .from('risk_exceptions')
      .select('id, expiration_date, risks(title)')
      .eq('status', 'Approved')
      .lte('expiration_date', in7Days.toISOString().split('T')[0])
      .gte('expiration_date', today.toISOString().split('T')[0]);

    if (role === 'user') waiverQuery = waiverQuery.eq('requested_by', user.id);

    const { data: expiringWaivers } = await waiverQuery;

    (expiringWaivers || []).forEach(w => {
      const expDate = new Date(w.expiration_date);
      const daysLeft = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));
      notifications.push({
        id: `expiring-${w.id}`,
        type: 'warning',
        icon: 'fa-clock',
        title: 'Waiver Expiring Soon',
        message: `Waiver for "${w.risks?.title || 'Unknown Risk'}" expires in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`,
        link: role === 'user' ? '/risks' : '/waivers',
      });
    });

    // 3. STALE HIGH/CRITICAL RISK NOTIFICATIONS
    // Risks that are High or Critical and have been open for 30+ days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(today.getDate() - 30);

    let riskQuery = supabase
      .from('risks')
      .select('id, title, severity_level, created_at, status')
      .in('severity_level', ['High', 'Critical'])
      .eq('status', 'Open')
      .lte('created_at', thirtyDaysAgo.toISOString());

    if (role === 'user') riskQuery = riskQuery.eq('user_id', user.id);

    const { data: staleRisks } = await riskQuery;

    (staleRisks || []).forEach(r => {
      const daysOpen = Math.floor((today - new Date(r.created_at)) / (1000 * 60 * 60 * 24));
      notifications.push({
        id: `stale-${r.id}`,
        type: 'error',
        icon: 'fa-triangle-exclamation',
        title: `${r.severity_level} Risk Unresolved`,
        message: `"${r.title}" has been open for ${daysOpen} days with no mitigation`,
        link: '/risks',
      });
    });

    // Sort: errors first, then warnings, then success
    const order = { error: 0, warning: 1, success: 2 };
    notifications.sort((a, b) => (order[a.type] ?? 3) - (order[b.type] ?? 3));

    return NextResponse.json(notifications, { status: 200 });
  } catch (err) {
    console.error('Notifications error:', err);
    return NextResponse.json([], { status: 200 }); // never crash the app for notifications
  }
}
