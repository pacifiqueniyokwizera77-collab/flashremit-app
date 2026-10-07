-- =====================================================================
-- Pax International — profits, frais d'envoi, gains des agents
-- * transactions : méthode d'envoi (Binance, M-Pesa…) + frais de la méthode,
--   lien vers l'envoi à Naomie, lien vers le paiement du gain de l'agent
-- * versements : taux de vente (1 $ = ? BIF) saisi par Naomie à la réception
-- * paiements_agents : historique des gains payés aux agents (remise à zéro)
-- Gain agent par transaction = (frais − frais d'envoi) ÷ 2
-- =====================================================================

create table public.paiements_agents (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  agent_id uuid not null references public.profiles(id) on delete restrict,
  agent_nom text not null,
  montant_aed numeric(14,2) not null,
  nb_transactions int not null default 0,
  paye_par text,
  note text
);
alter table public.paiements_agents enable row level security;
create policy pa_select on public.paiements_agents for select to authenticated
  using (public.is_admin() or (public.is_active_agent() and agent_id = auth.uid()));
create policy pa_delete on public.paiements_agents for delete to authenticated
  using (public.is_admin());

alter table public.transactions
  add column methode_envoi text,
  add column frais_envoi_aed numeric(14,2) not null default 0 check (frais_envoi_aed >= 0),
  add column versement_id uuid references public.versements(id) on delete set null,
  add column gain_paiement_id uuid references public.paiements_agents(id) on delete set null;
create index transactions_versement_idx on public.transactions (versement_id);
create index transactions_gain_idx on public.transactions (gain_paiement_id);

alter table public.versements
  add column taux_vente numeric(14,2) check (taux_vente is null or taux_vente > 0),
  add column taux_aed_usd numeric(10,4) not null default 3.66;

-- Only admins may change amounts, names, fees or the gain payment link.
create or replace function public.guard_tx_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if new.montant_aed is distinct from old.montant_aed or new.frais_aed is distinct from old.frais_aed
       or new.taux_aed_usd is distinct from old.taux_aed_usd or new.taux_usd_bif is distinct from old.taux_usd_bif
       or new.montant_bif is distinct from old.montant_bif or new.agent_id is distinct from old.agent_id
       or new.client is distinct from old.client or new.beneficiaire is distinct from old.beneficiaire
       or new.beneficiaire_tel is distinct from old.beneficiaire_tel
       or new.frais_envoi_aed is distinct from old.frais_envoi_aed or new.methode_envoi is distinct from old.methode_envoi
       or new.gain_paiement_id is distinct from old.gain_paiement_id then
      raise exception 'Seul un admin peut modifier les montants ou les noms';
    end if;
  end if;
  return new;
end $$;

-- Agent declares money sent to Naomie and ticks the transactions it covers.
create or replace function public.agent_create_versement(p_montant numeric, p_moyen text, p_note text, p_tx uuid[])
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid; me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid() and statut = 'actif';
  if me.id is null or me.role not in ('AGENT','ADMIN') then raise exception 'Accès refusé'; end if;
  if p_montant is null or p_montant <= 0 then raise exception 'Montant invalide'; end if;
  insert into public.versements (agent_id, agent_nom, montant_aed, moyen, note)
  values (me.id, me.nom, p_montant, nullif(trim(p_moyen),''), nullif(trim(p_note),''))
  returning id into v_id;
  update public.transactions set versement_id = v_id
   where id = any(coalesce(p_tx, '{}')) and agent_id = me.id and versement_id is null and statut <> 'ANNULEE';
  return v_id;
end $$;

-- Admin pays an agent all unpaid gains and resets the counter.
create or replace function public.admin_pay_agent(p_agent uuid, p_note text)
returns json language plpgsql security definer set search_path = public as $$
declare v_total numeric; v_n int; v_id uuid; a public.profiles; me public.profiles;
begin
  if not public.is_admin() then raise exception 'Réservé aux administrateurs'; end if;
  select * into a from public.profiles where id = p_agent;
  select * into me from public.profiles where id = auth.uid();
  select coalesce(sum((frais_aed - frais_envoi_aed) / 2), 0), count(*) into v_total, v_n
    from public.transactions where agent_id = p_agent and gain_paiement_id is null and statut <> 'ANNULEE';
  if v_n = 0 then raise exception 'Aucun gain à payer'; end if;
  insert into public.paiements_agents (agent_id, agent_nom, montant_aed, nb_transactions, paye_par, note)
  values (p_agent, a.nom, round(v_total, 2), v_n, me.nom, nullif(trim(p_note),''))
  returning id into v_id;
  update public.transactions set gain_paiement_id = v_id
   where agent_id = p_agent and gain_paiement_id is null and statut <> 'ANNULEE';
  return json_build_object('id', v_id, 'montant', round(v_total, 2), 'n', v_n);
end $$;

revoke execute on function public.agent_create_versement(numeric, text, text, uuid[]) from public, anon;
revoke execute on function public.admin_pay_agent(uuid, text) from public, anon;
grant execute on function public.agent_create_versement(numeric, text, text, uuid[]) to authenticated;
grant execute on function public.admin_pay_agent(uuid, text) to authenticated;
