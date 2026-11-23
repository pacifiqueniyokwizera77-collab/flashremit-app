-- =====================================================================
-- Pax International — étape Kenya (Caleb Olame, acheteur de shillings)
-- Envois M-Pesa des agents de Dubaï :
--   1. l'agent déclare l'envoi (statut ENVOYE)
--   2. Caleb saisit les AED reçus, les KES obtenus et le taux KES → BIF :
--      le montant à envoyer à Naomie est calculé (statut KENYA)
--   3. Naomie confirme le montant BIF reçu de Caleb (statut RECU) ;
--      la vente KES → BIF est enregistrée automatiquement pour les profits.
-- =====================================================================

-- ---------- Nouveau rôle KENYA ----------
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('ADMIN','BUJA','AGENT','KENYA'));

create or replace function public.is_kenya() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() = 'KENYA', false)
$$;

-- ---------- Envois : étape Kenya ----------
do $$ declare c record; begin
  for c in select conname from pg_constraint
            where conrelid = 'public.versements'::regclass and contype = 'c' and pg_get_constraintdef(oid) ilike '%statut%'
  loop execute format('alter table public.versements drop constraint %I', c.conname); end loop;
end $$;
alter table public.versements add constraint versements_statut_check
  check (statut in ('ENVOYE','KENYA','RECU'));

alter table public.versements
  add column if not exists kenya_aed numeric(14,2),       -- AED réellement reçus par Caleb
  add column if not exists kenya_kes numeric(16,2),       -- shillings obtenus
  add column if not exists kenya_taux numeric(14,4),      -- 1 KES = ? BIF
  add column if not exists kenya_bif numeric(18,0),       -- à envoyer à Naomie = KES × taux
  add column if not exists kenya_par text,
  add column if not exists kenya_le timestamptz,
  add column if not exists kenya_bif_recu numeric(18,0);  -- ce que Naomie a reçu de Caleb

-- Caleb voit uniquement les envois M-Pesa
drop policy if exists vs_select on public.versements;
create policy vs_select on public.versements for select to authenticated
  using (
    public.is_staff()
    or (public.is_active_agent() and agent_id = auth.uid())
    or (public.is_kenya() and coalesce(methode_envoi, moyen, '') ilike 'M-Pesa%')
  );

-- ---------- Caleb valide ce qu'il a reçu ----------
create or replace function public.kenya_confirm(p_id uuid, p_aed numeric, p_kes numeric, p_taux numeric)
returns void language plpgsql security definer set search_path = public as $$
declare v public.versements; me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid() and statut = 'actif';
  if me.id is null or me.role not in ('KENYA','ADMIN') then raise exception 'Accès refusé'; end if;
  select * into v from public.versements where id = p_id for update;
  if v.id is null then raise exception 'Envoi introuvable'; end if;
  if coalesce(v.methode_envoi, v.moyen, '') not ilike 'M-Pesa%' then raise exception 'Cet envoi ne passe pas par le Kenya'; end if;
  if v.statut = 'RECU' then raise exception 'Naomie a déjà confirmé cet envoi'; end if;
  if coalesce(p_aed,0) <= 0 or coalesce(p_kes,0) <= 0 or coalesce(p_taux,0) <= 0 then raise exception 'Montant invalide'; end if;
  update public.versements
     set statut = 'KENYA', kenya_aed = p_aed, kenya_kes = p_kes, kenya_taux = p_taux,
         kenya_bif = round(p_kes * p_taux, 0), kenya_par = me.nom, kenya_le = now()
   where id = p_id;
end $$;

-- ---------- Naomie confirme le montant reçu de Caleb ----------
create or replace function public.naomie_confirm_kenya(p_id uuid, p_bif numeric)
returns void language plpgsql security definer set search_path = public as $$
declare v public.versements; me public.profiles;
begin
  select * into me from public.profiles where id = auth.uid() and statut = 'actif';
  if me.id is null or me.role not in ('BUJA','ADMIN') then raise exception 'Accès refusé'; end if;
  select * into v from public.versements where id = p_id for update;
  if v.id is null then raise exception 'Envoi introuvable'; end if;
  if v.kenya_kes is null then raise exception 'Caleb n''a pas encore validé cet envoi'; end if;
  if coalesce(p_bif,0) <= 0 then raise exception 'Montant invalide'; end if;

  update public.versements
     set statut = 'RECU', recu_montant = v.kenya_kes, recu_devise = 'KES', kenya_bif_recu = round(p_bif,0),
         confirme_par = me.nom, confirme_le = now()
   where id = p_id;

  -- the KES were "sold" to Caleb: one sale at the rate that gives exactly the BIF Naomie received
  delete from public.ventes where versement_id = p_id;
  insert into public.ventes (versement_id, devise, quantite, taux, mode_reception, frais_bif, note, saisi_par, date)
  values (p_id, 'KES', v.kenya_kes, round(p_bif / v.kenya_kes, 4), 'Caleb (Kenya)', 0,
          'Vente automatique : KES achetés par Caleb', me.nom, current_date);
end $$;

-- Undo Naomie's confirmation (back to "sent by Caleb")
create or replace function public.naomie_unconfirm_kenya(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'Accès refusé'; end if;
  delete from public.ventes where versement_id = p_id;
  update public.versements
     set statut = 'KENYA', recu_montant = null, recu_devise = null, kenya_bif_recu = null,
         confirme_par = null, confirme_le = null
   where id = p_id and kenya_kes is not null;
end $$;

revoke execute on function public.kenya_confirm(uuid,numeric,numeric,numeric) from anon, public;
revoke execute on function public.naomie_confirm_kenya(uuid,numeric) from anon, public;
revoke execute on function public.naomie_unconfirm_kenya(uuid) from anon, public;
grant execute on function public.kenya_confirm(uuid,numeric,numeric,numeric) to authenticated;
grant execute on function public.naomie_confirm_kenya(uuid,numeric) to authenticated;
grant execute on function public.naomie_unconfirm_kenya(uuid) to authenticated;
