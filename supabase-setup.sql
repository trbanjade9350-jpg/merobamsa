-- नातागोता ट्रयाकिङ: Supabase सेटअप (एक पटक मात्र चलाउनुहोस्)
-- सबै डाटा तालिकामा सिधै कसैले पढ्न/लेख्न नपाउने, पासवर्ड जाँच्ने फङ्सनबाट मात्र पहुँच हुने बनाइएको छ।

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.ntg_admin (
  id int primary key default 1 check (id = 1),
  pw_hash text not null
);

create table if not exists public.ntg_trees (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  data jsonb not null default '[]'::jsonb,
  edit_hash text not null,
  view_hash text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.ntg_admin enable row level security;
alter table public.ntg_trees enable row level security;
revoke all on table public.ntg_admin from anon, authenticated;
revoke all on table public.ntg_trees from anon, authenticated;

-- प्रशासक पासवर्ड जाँच (भित्री प्रयोगका लागि मात्र)
create or replace function public.ntg_is_admin(p_pw text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select coalesce((select a.pw_hash = crypt(p_pw, a.pw_hash) from public.ntg_admin a limit 1), false)
$$;
revoke execute on function public.ntg_is_admin(text) from public, anon, authenticated;

create or replace function public.ntg_admin_status(p_pw text) returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from public.ntg_admin) then return 'unset'; end if;
  if public.ntg_is_admin(p_pw) then return 'ok'; end if;
  perform pg_sleep(0.4);
  return 'bad';
end $$;

create or replace function public.ntg_admin_setup(p_pw text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_pw is null or length(p_pw) < 6 then raise exception 'password too short'; end if;
  if exists (select 1 from public.ntg_admin) then return false; end if;
  insert into public.ntg_admin(id, pw_hash) values (1, crypt(p_pw, gen_salt('bf')));
  return true;
end $$;

-- वंशावलीको सूची: नाम र सदस्य संख्या मात्र (डाटा होइन)
create or replace function public.ntg_list_trees()
returns table(id uuid, name text, n integer, has_view boolean, created_at timestamptz, updated_at timestamptz)
language sql security definer set search_path = public, extensions as $$
  select t.id, t.name, jsonb_array_length(t.data), (t.view_hash is not null), t.created_at, t.updated_at
  from public.ntg_trees t
  order by t.created_at
$$;

create or replace function public.ntg_create_tree(p_name text, p_data jsonb, p_edit text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  if p_name is null or length(btrim(p_name)) = 0 or length(p_name) > 120 then raise exception 'bad name'; end if;
  if p_edit is null or length(p_edit) < 6 then raise exception 'password too short'; end if;
  if p_data is null or jsonb_typeof(p_data) <> 'array' or length(p_data::text) > 400000 then raise exception 'bad data'; end if;
  if (select count(*) from public.ntg_trees) >= 500 then raise exception 'limit reached'; end if;
  insert into public.ntg_trees(name, data, edit_hash)
  values (btrim(p_name), p_data, crypt(p_edit, gen_salt('bf')))
  returning ntg_trees.id into v_id;
  return v_id;
end $$;

-- वंशावली पढ्ने: प्रशासक, बनाउने (सम्पादन पासवर्ड) वा हेर्ने पासवर्ड भएकाले मात्र
create or replace function public.ntg_get_tree(p_id uuid, p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare t public.ntg_trees%rowtype; v_role text;
begin
  select * into t from public.ntg_trees where ntg_trees.id = p_id;
  if not found then return null; end if;
  if public.ntg_is_admin(p_pw) then v_role := 'admin';
  elsif p_pw is not null and t.edit_hash = crypt(p_pw, t.edit_hash) then v_role := 'edit';
  elsif p_pw is not null and t.view_hash is not null and t.view_hash = crypt(p_pw, t.view_hash) then v_role := 'view';
  else
    perform pg_sleep(0.4);
    return null;
  end if;
  return jsonb_build_object('name', t.name, 'data', t.data, 'role', v_role, 'updated_at', t.updated_at);
end $$;

-- सुरक्षित गर्ने: प्रशासक वा बनाउनेले मात्र। p_base ले अर्कैले बीचमा फेरेको पत्ता लगाउँछ।
create or replace function public.ntg_save_tree(p_id uuid, p_pw text, p_name text, p_data jsonb, p_base timestamptz default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare t public.ntg_trees%rowtype; v_new timestamptz;
begin
  select * into t from public.ntg_trees where ntg_trees.id = p_id;
  if not found then return jsonb_build_object('ok', false, 'reason', 'notfound'); end if;
  if not (public.ntg_is_admin(p_pw) or (p_pw is not null and t.edit_hash = crypt(p_pw, t.edit_hash))) then
    perform pg_sleep(0.4);
    return jsonb_build_object('ok', false, 'reason', 'denied');
  end if;
  if p_base is not null and t.updated_at <> p_base then
    return jsonb_build_object('ok', false, 'reason', 'conflict');
  end if;
  if p_data is null or jsonb_typeof(p_data) <> 'array' or length(p_data::text) > 400000 then raise exception 'bad data'; end if;
  v_new := clock_timestamp();
  update public.ntg_trees
     set data = p_data,
         name = coalesce(nullif(left(btrim(p_name), 120), ''), ntg_trees.name),
         updated_at = v_new
   where ntg_trees.id = p_id;
  return jsonb_build_object('ok', true, 'updated_at', v_new);
end $$;

create or replace function public.ntg_set_view_pw(p_id uuid, p_admin text, p_view text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.ntg_is_admin(p_admin) then perform pg_sleep(0.4); return false; end if;
  if p_view is not null and length(p_view) > 0 and length(p_view) < 4 then raise exception 'password too short'; end if;
  update public.ntg_trees
     set view_hash = case when p_view is null or p_view = '' then null else crypt(p_view, gen_salt('bf')) end
   where ntg_trees.id = p_id;
  return found;
end $$;

create or replace function public.ntg_reset_edit_pw(p_id uuid, p_admin text, p_new text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.ntg_is_admin(p_admin) then perform pg_sleep(0.4); return false; end if;
  if p_new is null or length(p_new) < 6 then raise exception 'password too short'; end if;
  update public.ntg_trees set edit_hash = crypt(p_new, gen_salt('bf')) where ntg_trees.id = p_id;
  return found;
end $$;

create or replace function public.ntg_delete_tree(p_id uuid, p_pw text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare t public.ntg_trees%rowtype;
begin
  select * into t from public.ntg_trees where ntg_trees.id = p_id;
  if not found then return false; end if;
  if not (public.ntg_is_admin(p_pw) or (p_pw is not null and t.edit_hash = crypt(p_pw, t.edit_hash))) then
    perform pg_sleep(0.4);
    return false;
  end if;
  delete from public.ntg_trees where ntg_trees.id = p_id;
  return true;
end $$;

grant execute on function public.ntg_admin_status(text) to anon, authenticated;
grant execute on function public.ntg_admin_setup(text) to anon, authenticated;
grant execute on function public.ntg_list_trees() to anon, authenticated;
grant execute on function public.ntg_create_tree(text, jsonb, text) to anon, authenticated;
grant execute on function public.ntg_get_tree(uuid, text) to anon, authenticated;
grant execute on function public.ntg_save_tree(uuid, text, text, jsonb, timestamptz) to anon, authenticated;
grant execute on function public.ntg_set_view_pw(uuid, text, text) to anon, authenticated;
grant execute on function public.ntg_reset_edit_pw(uuid, text, text) to anon, authenticated;
grant execute on function public.ntg_delete_tree(uuid, text) to anon, authenticated;
