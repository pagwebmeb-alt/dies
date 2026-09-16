-- MAHA.BABYS — reparación de Administración y conversaciones
-- Ejecutar TODO este archivo en Supabase > SQL Editor.
-- No modifica productos, precios ni stock.

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.admin_users
    where user_id = auth.uid()
  );
$$;

grant execute on function public.is_admin() to authenticated;

-- IMPORTANTE: reemplazá este correo por el correo exacto que usás para entrar a Administración.
-- Si ya lo ejecutaste anteriormente con tu correo correcto, esta parte no cambia nada.
-- insert into public.admin_users(user_id)
-- select id from auth.users where email = 'TU_CORREO_ADMIN' on conflict (user_id) do nothing;

-- Políticas del administrador. Los clientes siguen limitados a sus propios datos.
drop policy if exists "admin products access" on public.products;
create policy "admin products access"
on public.products
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "admin carts access" on public.carts;
create policy "admin carts access"
on public.carts
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "admin cart items access" on public.cart_items;
create policy "admin cart items access"
on public.cart_items
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "admin orders access" on public.orders;
create policy "admin orders access"
on public.orders
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "admin order items access" on public.order_items;
create policy "admin order items access"
on public.order_items
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

drop policy if exists "admin conversations access" on public.conversations;
create policy "admin conversations access"
on public.conversations
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

-- Permite al cliente leer/escribir su propia conversación y únicamente como sender='client'.
drop policy if exists "conversations_own_select" on public.conversations;
create policy "conversations_own_select"
on public.conversations
for select to authenticated
using (
  exists (
    select 1 from public.carts c
    where c.id = conversations.cart_id and c.user_id = auth.uid()
  )
);

drop policy if exists "conversations_own_insert" on public.conversations;
create policy "conversations_own_insert"
on public.conversations
for insert to authenticated
with check (
  sender = 'client'
  and exists (
    select 1 from public.carts c
    where c.id = conversations.cart_id and c.user_id = auth.uid()
  )
);

-- RPC segura para que Administración pueda cargar TODOS los carritos aunque una política vieja
-- de RLS haya quedado mal configurada. Solo un usuario registrado en admin_users puede usarla.
create or replace function public.admin_get_carts()
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  result jsonb;
begin
  if not public.is_admin() then
    raise exception 'No autorizado';
  end if;

  select coalesce(jsonb_agg(row_to_json(x) order by x.created_at desc), '[]'::jsonb)
    into result
  from (
    select
      c.id,
      c.user_id,
      c.client_name,
      c.phone,
      c.province,
      c.city,
      c.neighborhood,
      c.street,
      c.house_number,
      c.postal_code,
      c.status,
      c.created_at,
      c.updated_at,
      coalesce((
        select jsonb_agg(
          jsonb_build_object(
            'product_id', ci.product_id,
            'quantity', ci.quantity,
            'unit_price', ci.unit_price
          ) order by ci.id
        )
        from public.cart_items ci
        where ci.cart_id = c.id
      ), '[]'::jsonb) as cart_items
    from public.carts c
  ) x;

  return result;
end;
$$;

revoke all on function public.admin_get_carts() from public;
grant execute on function public.admin_get_carts() to authenticated;
