-- =====================================================================
-- Pax International — réinitialisation des opérations (admins)
-- Avant d'effacer, toutes les transactions, envois et paiements d'agents
-- sont copiés dans des tables de sauvegarde (backup_*), avec la date.
-- Les comptes utilisateurs ne sont pas touchés.
-- =====================================================================

create table if not exists public.backup_transactions (like public.transactions);
alter table public.backup_transactions add column if not exists sauvegarde_le timestamptz not null default now();
create table if not exists public.backup_versements (like public.versements);
alter table public.backup_versements add column if not exists sauvegarde_le timestamptz not null default now();
create table if not exists public.backup_paiements_agents (like public.paiements_agents);
alter table public.backup_paiements_agents add column if not exists sauvegarde_le timestamptz not null default now();
alter table public.backup_transactions enable row level security;
alter table public.backup_versements enable row level security;
alter table public.backup_paiements_agents enable row level security;
-- (no policies: backups are only reachable from the Supabase dashboard)

create or replace function public._reset_operations()
returns json language plpgsql security definer set search_path = public as $$
declare n_tx int; n_vs int; n_pa int;
begin
  insert into public.backup_transactions select t.*, now() from public.transactions t;
  get diagnostics n_tx = row_count;
  insert into public.backup_versements select v.*, now() from public.versements v;
  get diagnostics n_vs = row_count;
  insert into public.backup_paiements_agents select p.*, now() from public.paiements_agents p;
  get diagnostics n_pa = row_count;
  delete from public.transactions;
  delete from public.versements;
  delete from public.paiements_agents;
  return json_build_object('transactions', n_tx, 'versements', n_vs, 'paiements', n_pa);
end $$;
revoke execute on function public._reset_operations() from public, anon, authenticated;

create or replace function public.admin_reset_operations(p_confirm text)
returns json language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Réservé aux administrateurs'; end if;
  if p_confirm is distinct from 'REINITIALISER' then raise exception 'Confirmation incorrecte'; end if;
  return public._reset_operations();
end $$;
revoke execute on function public.admin_reset_operations(text) from public, anon;
grant execute on function public.admin_reset_operations(text) to authenticated;
