import { createClient } from '@supabase/supabase-js';
import { NextResponse } from 'next/server';

// Helper to init Supabase and check Auth
async function getAuth(request) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return { error: 'Unauthorized', status: 401 };
  
  const token = authHeader.replace('Bearer ', '');
  const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  
  if (error || !user) return { error: 'Unauthorized', status: 401 };
  return { supabase, user };
}

export async function GET(request) {
  try {
    const auth = await getAuth(request);
    if (auth.error) return NextResponse.json({ error: auth.error }, { status: auth.status });

    const { data, error } = await auth.supabase
      .from('incidents')
      .select('*, risks(title)')
      .order('created_at', { ascending: false });

    if (error) throw error;
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request) {
  try {
    const auth = await getAuth(request);
    if (auth.error) return NextResponse.json({ error: auth.error }, { status: auth.status });

    const body = await request.json();
    const { data, error } = await auth.supabase
      .from('incidents')
      .insert([{ 
        title: body.title, 
        description: body.description, 
        severity: body.severity, 
        related_risk_id: body.related_risk_id,
        reported_by: auth.user.id 
      }])
      .select();

    if (error) throw error;
    return NextResponse.json(data[0]);
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function PUT(request) {
  try {
    const auth = await getAuth(request);
    if (auth.error) return NextResponse.json({ error: auth.error }, { status: auth.status });

    const body = await request.json();
    const resolvedAt = body.status === 'Resolved' ? new Date().toISOString() : null;

    const { data, error } = await auth.supabase
      .from('incidents')
      .update({ status: body.status, resolved_at: resolvedAt })
      .eq('id', body.id)
      .select();

    if (error) throw error;
    return NextResponse.json(data[0]);
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
