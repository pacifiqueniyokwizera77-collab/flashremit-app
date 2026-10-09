-- =====================================================================
-- Pax International — réception réelle et ventes à Bujumbura
-- * versements : ce que Naomie a réellement reçu (montant + devise : USDT, KES…)
-- * ventes : chaque vente (partielle ou totale) d'un envoi reçu, avec son prix,
--   son mode de réception (banque, Lumicash…) et ses frais de vente en BIF
-- Visible et modifiable par Naomie et les admins uniquement.
-- =====================================================================

alter table public.versements
  add column if not exists recu_montant numeric(16,2) check (recu_montant is null or recu_montant > 0),
  add column if not exists recu_devise text;

create table if not exists public.ventes (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  versement_id uuid not null references public.versements(id) on delete cascade,
  devise text not null,
  quantite numeric(16,2) not null check (quantite > 0),
  taux numeric(14,4) not null check (taux > 0),            -- BIF par unité vendue
  mode_reception text,                                       -- Banque, Lumicash, Ecocash, Cash…
  frais_bif numeric(16,0) not null default 0 check (frais_bif >= 0),
  montant_bif numeric(18,0) generated always as (round(quantite * taux, 0)) stored,
  net_bif numeric(18,0) generated always as (round(quantite * taux, 0) - frais_bif) stored,
  note text,
  saisi_par text
);
create index if not exists ventes_versement_idx on public.ventes (versement_id);

alter table public.ventes enable row level security;
drop policy if exists ventes_select on public.ventes;
drop policy if exists ventes_insert on public.ventes;
drop policy if exists ventes_update on public.ventes;
drop policy if exists ventes_delete on public.ventes;
create policy ventes_select on public.ventes for select to authenticated using (public.is_staff());
create policy ventes_insert on public.ventes for insert to authenticated with check (public.is_staff());
create policy ventes_update on public.ventes for update to authenticated using (public.is_staff()) with check (public.is_staff());
create policy ventes_delete on public.ventes for delete to authenticated using (public.is_staff());

-- A transfer cannot be sold for more than what was received.
create or replace function public.guard_ventes() returns trigger
language plpgsql security definer set search_path = public as $$
declare recu numeric; deja numeric;
begin
  select recu_montant into recu from public.versements where id = new.versement_id;
  if recu is null then raise exception 'Confirmez d''abord la réception de cet envoi'; end if;
  select coalesce(sum(quantite),0) into deja from public.ventes
   where versement_id = new.versement_id and id <> new.id;
  if deja + new.quantite > recu then
    raise exception 'Quantité trop élevée : il reste % à vendre sur cet envoi', recu - deja;
  end if;
  return new;
end $$;
drop trigger if exists guard_ventes on public.ventes;
create trigger guard_ventes before insert or update on public.ventes
  for each row execute function public.guard_ventes();
