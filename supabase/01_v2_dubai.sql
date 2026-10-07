-- =====================================================================
-- Pax International Travels and Services v2 — Dubaï → Bujumbura
-- A coller dans Supabase → SQL Editor → Run (une seule fois).
-- Archive l'ancien modèle (rien n'est supprimé), crée les tables
-- transactions (Dubaï) et versements (envois à Naomie), et les règles
-- d'accès par rôle : ADMIN, BUJA (Naomie), AGENT (Dubaï).
-- =====================================================================

-- ---------- Archive old model (kept, not deleted) ----------
alter table public.transactions rename to archive_transactions_france;
alter table public.rates rename to archive_rates;
drop policy if exists "Lecture transactions pour connectés" on public.archive_transactions_france;
drop policy if exists "Creation transactions pour connectés" on public.archive_transactions_france;
drop policy if exists "Maj transactions pour connectés" on public.archive_transactions_france;
drop policy if exists "Suppression transactions reservee editeurs" on public.archive_transactions_france;
drop policy if exists "Lecture taux pour connectés" on public.archive_rates;
drop policy if exists "Ecriture taux reservee editeurs" on public.archive_rates;
drop policy if exists "Maj taux reservee editeurs" on public.archive_rates;
drop policy if exists "Suppression taux reservee editeurs" on public.archive_rates;

-- ---------- Profiles: new roles & pending status ----------
drop policy if exists "Lecture profils pour connectés" on public.profiles;
drop policy if exists "Modification profils reservee editeurs" on public.profiles;
drop policy if exists "Ajout profils reserve editeurs" on public.profiles;
alter table public.profiles drop constraint profiles_role_check;
alter table public.profiles drop constraint profiles_statut_check;
alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists created_at timestamptz not null default now();
update public.profiles p set email = u.email from auth.users u where u.id = p.id;
alter table public.profiles add constraint profiles_role_check check (role in ('ADMIN','BUJA','AGENT'));
alter table public.profiles add constraint profiles_statut_check check (statut in ('en_attente','actif','inactif'));
alter table public.profiles alter column statut set default 'en_attente';
alter table public.profiles alter column role set default 'AGENT';
alter table public.profiles alter column pays set default 'Dubaï';

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid() and statut = 'actif'
$$;
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'ADMIN', false)
$$;
create or replace function public.is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('ADMIN','BUJA'), false)
$$;
create or replace function public.is_active_agent() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'AGENT', false)
$$;
create or replace function public.is_editor() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin()
$$;

create policy archive_tx_admin_read on public.archive_transactions_france for select to authenticated using (public.is_admin());
create policy archive_rates_admin_read on public.archive_rates for select to authenticated using (public.is_admin());

-- New sign-ups: AGENT, Dubaï, waiting for admin approval
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  -- Thierry (admin à Bujumbura) devient admin automatiquement à son inscription
  pre_admin boolean := lower(new.email) in ('niyikizatiger@gmail.com');
begin
  insert into public.profiles (id, nom, email, role, pays, statut, can_edit)
  values (new.id,
          coalesce(nullif(trim(new.raw_user_meta_data->>'nom'),''), split_part(new.email,'@',1)),
          new.email,
          case when pre_admin then 'ADMIN' else 'AGENT' end,
          case when pre_admin then 'Burundi' else 'Dubaï' end,
          case when pre_admin then 'actif' else 'en_attente' end,
          pre_admin);
  return new;
end $$;
revoke execute on function public.handle_new_user() from anon, authenticated, public;

create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_staff());
create policy profiles_update_admin on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
create policy profiles_delete_admin on public.profiles for delete to authenticated
  using (public.is_admin() and id <> auth.uid());

-- ---------- Transactions (Dubaï): AED -> USD (÷ taux AED/USD) -> BIF (× taux USD/BIF) ----------
create table public.transactions (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  agent_id uuid not null references public.profiles(id) on delete restrict,
  agent_nom text not null,
  client text not null,
  client_tel text,
  beneficiaire text not null,
  beneficiaire_tel text,
  mode_reception text,
  montant_aed numeric(14,2) not null check (montant_aed > 0),
  frais_aed numeric(14,2) not null default 0 check (frais_aed >= 0),
  taux_aed_usd numeric(10,4) not null default 3.66 check (taux_aed_usd > 0),
  taux_usd_bif numeric(14,2) not null check (taux_usd_bif > 0),
  montant_usd numeric(14,2) generated always as (round(montant_aed / taux_aed_usd, 2)) stored,
  montant_bif numeric(18,0) not null check (montant_bif > 0),
  statut text not null default 'EN_ATTENTE' check (statut in ('EN_ATTENTE','PAYEE','ANNULEE')),
  valide_par text,
  valide_le timestamptz,
  note text
);
create index transactions_agent_idx on public.transactions (agent_id);
create index transactions_statut_idx on public.transactions (statut);
alter table public.transactions enable row level security;
create policy tx_select on public.transactions for select to authenticated
  using (public.is_staff() or (public.is_active_agent() and agent_id = auth.uid()));
create policy tx_insert on public.transactions for insert to authenticated
  with check ((public.is_active_agent() or public.is_admin()) and agent_id = auth.uid() and statut = 'EN_ATTENTE');
create policy tx_update_staff on public.transactions for update to authenticated
  using (public.is_staff()) with check (public.is_staff());
create policy tx_delete on public.transactions for delete to authenticated
  using (public.is_admin() or (public.is_active_agent() and agent_id = auth.uid() and statut = 'EN_ATTENTE'));

create or replace function public.guard_tx_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if new.montant_aed is distinct from old.montant_aed or new.frais_aed is distinct from old.frais_aed
       or new.taux_aed_usd is distinct from old.taux_aed_usd or new.taux_usd_bif is distinct from old.taux_usd_bif
       or new.montant_bif is distinct from old.montant_bif or new.agent_id is distinct from old.agent_id
       or new.client is distinct from old.client or new.beneficiaire is distinct from old.beneficiaire
       or new.beneficiaire_tel is distinct from old.beneficiaire_tel then
      raise exception 'Seul un admin peut modifier les montants ou les noms';
    end if;
  end if;
  return new;
end $$;
create trigger guard_tx_update before update on public.transactions
  for each row execute function public.guard_tx_update();

-- ---------- Versements: money sent by an agent to Naomie ----------
create table public.versements (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  agent_id uuid not null references public.profiles(id) on delete restrict,
  agent_nom text not null,
  montant_aed numeric(14,2) not null check (montant_aed > 0),
  moyen text,
  note text,
  statut text not null default 'ENVOYE' check (statut in ('ENVOYE','RECU')),
  confirme_par text,
  confirme_le timestamptz
);
create index versements_agent_idx on public.versements (agent_id);
alter table public.versements enable row level security;
create policy vs_select on public.versements for select to authenticated
  using (public.is_staff() or (public.is_active_agent() and agent_id = auth.uid()));
create policy vs_insert on public.versements for insert to authenticated
  with check ((public.is_active_agent() and agent_id = auth.uid() and statut = 'ENVOYE') or public.is_admin());
create policy vs_update_staff on public.versements for update to authenticated
  using (public.is_staff()) with check (public.is_staff());
create policy vs_delete on public.versements for delete to authenticated
  using (public.is_admin() or (public.is_active_agent() and agent_id = auth.uid() and statut = 'ENVOYE'));

create or replace function public.guard_vs_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if new.montant_aed is distinct from old.montant_aed or new.agent_id is distinct from old.agent_id then
      raise exception 'Seul un admin peut modifier un montant';
    end if;
  end if;
  return new;
end $$;
create trigger guard_vs_update before update on public.versements
  for each row execute function public.guard_vs_update();

-- ---------- Team: keep Pacifique (admin) and Naomie (Bujumbura) ----------
update public.profiles set role='ADMIN', statut='actif', can_edit=true where email='pacifiqueniyokwizera77@gmail.com';
update public.profiles set role='BUJA', statut='actif', pays='Burundi', can_edit=false where email='naomiekaneza2110@gmail.com';
