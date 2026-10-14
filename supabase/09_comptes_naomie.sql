-- =====================================================================
-- Pax International — comptes de Naomie (banques, Lumicash, cash…)
-- * comptes : chaque compte avec son solde de départ
-- * mouvements : transferts entre comptes, entrées et sorties d'argent
-- * ventes.compte_id : compte sur lequel l'argent d'une vente est arrivé
-- * transactions.paye_depuis / frais_paiement_bif : compte utilisé pour
--   payer le bénéficiaire et frais de ce paiement
-- Visible et modifiable par Naomie et les admins uniquement.
-- =====================================================================

create table if not exists public.comptes (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  nom text not null unique,
  type text not null default 'Banque',            -- Banque, Mobile, Cash
  solde_depart numeric(18,0) not null default 0,  -- solde au moment où le compte est ajouté
  actif boolean not null default true
);

create table if not exists public.mouvements (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  type text not null check (type in ('TRANSFERT','ENTREE','SORTIE')),
  compte_de uuid references public.comptes(id) on delete cascade,
  compte_vers uuid references public.comptes(id) on delete cascade,
  montant numeric(18,0) not null check (montant > 0),
  frais numeric(18,0) not null default 0 check (frais >= 0),
  note text,
  saisi_par text,
  check (
    (type = 'TRANSFERT' and compte_de is not null and compte_vers is not null and compte_de <> compte_vers)
    or (type = 'ENTREE' and compte_vers is not null)
    or (type = 'SORTIE' and compte_de is not null)
  )
);

alter table public.ventes
  add column if not exists compte_id uuid references public.comptes(id) on delete set null;

alter table public.transactions
  add column if not exists paye_depuis uuid references public.comptes(id) on delete set null,
  add column if not exists frais_paiement_bif numeric(16,0) not null default 0 check (frais_paiement_bif >= 0);

alter table public.comptes enable row level security;
alter table public.mouvements enable row level security;

drop policy if exists comptes_all on public.comptes;
create policy comptes_all on public.comptes for all to authenticated
  using (public.is_staff()) with check (public.is_staff());

drop policy if exists mouvements_all on public.mouvements;
create policy mouvements_all on public.mouvements for all to authenticated
  using (public.is_staff()) with check (public.is_staff());
