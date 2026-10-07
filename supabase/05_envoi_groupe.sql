-- =====================================================================
-- Pax International — envoi groupé (plusieurs transactions dans un seul envoi)
-- Les frais de la méthode d'envoi (Binance, M-Pesa…) saisis sur l'envoi sont
-- répartis à parts égales entre les transactions cochées.
-- =====================================================================

alter table public.versements
  add column if not exists methode_envoi text,
  add column if not exists frais_envoi_aed numeric(14,2) not null default 0 check (frais_envoi_aed >= 0);

-- Allow the versement function (and only it) to set transfer fees for agents.
create or replace function public.guard_tx_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    if new.montant_aed is distinct from old.montant_aed or new.frais_aed is distinct from old.frais_aed
       or new.taux_aed_usd is distinct from old.taux_aed_usd or new.taux_usd_bif is distinct from old.taux_usd_bif
       or new.montant_bif is distinct from old.montant_bif or new.agent_id is distinct from old.agent_id
       or new.client is distinct from old.client or new.beneficiaire is distinct from old.beneficiaire
       or new.beneficiaire_tel is distinct from old.beneficiaire_tel
       or new.gain_paiement_id is distinct from old.gain_paiement_id
       or ((new.frais_envoi_aed is distinct from old.frais_envoi_aed or new.methode_envoi is distinct from old.methode_envoi)
           and coalesce(current_setting('pax.split_fee', true), '') <> 'on') then
      raise exception 'Seul un admin peut modifier les montants ou les noms';
    end if;
  end if;
  return new;
end $$;

drop function if exists public.agent_create_versement(numeric, text, text, uuid[]);
create or replace function public.agent_create_versement(
  p_montant numeric, p_moyen text, p_note text, p_tx uuid[],
  p_methode text default null, p_frais numeric default 0)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid; me public.profiles; n int; share numeric;
begin
  select * into me from public.profiles where id = auth.uid() and statut = 'actif';
  if me.id is null or me.role not in ('AGENT','ADMIN') then raise exception 'Accès refusé'; end if;
  if p_montant is null or p_montant <= 0 then raise exception 'Montant invalide'; end if;
  if coalesce(p_frais,0) < 0 then raise exception 'Montant invalide'; end if;

  insert into public.versements (agent_id, agent_nom, montant_aed, moyen, note, methode_envoi, frais_envoi_aed)
  values (me.id, me.nom, p_montant, nullif(trim(coalesce(p_moyen, p_methode)),''), nullif(trim(p_note),''),
          nullif(trim(p_methode),''), coalesce(p_frais,0))
  returning id into v_id;

  update public.transactions set versement_id = v_id
   where id = any(coalesce(p_tx, '{}')) and agent_id = me.id and versement_id is null and statut <> 'ANNULEE';
  get diagnostics n = row_count;

  -- one transfer fee for the whole batch: split it equally between the covered transactions
  if n > 0 and coalesce(p_frais,0) > 0 then
    share := round(p_frais / n, 2);
    perform set_config('pax.split_fee', 'on', true);
    update public.transactions
       set frais_envoi_aed = share, methode_envoi = coalesce(nullif(trim(p_methode),''), methode_envoi)
     where versement_id = v_id;
    -- put the rounding remainder on one transaction so the total is exact
    update public.transactions
       set frais_envoi_aed = frais_envoi_aed + (p_frais - share * n)
     where id = (select id from public.transactions where versement_id = v_id order by created_at limit 1);
    perform set_config('pax.split_fee', 'off', true);
  end if;
  return v_id;
end $$;

revoke execute on function public.agent_create_versement(numeric, text, text, uuid[], text, numeric) from public, anon;
grant execute on function public.agent_create_versement(numeric, text, text, uuid[], text, numeric) to authenticated;
