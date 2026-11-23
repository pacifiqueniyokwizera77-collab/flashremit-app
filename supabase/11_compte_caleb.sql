-- =====================================================================
-- Pax International — compte courant avec Caleb (Kenya), en BIF
-- Solde = ce que Caleb doit à Pax (positif) ou ce que Pax doit à Caleb (négatif)
--   + chaque envoi M-Pesa validé par Caleb (KES × taux = BIF)
--   + ajustements « Pax a donné à Caleb »
--   − l'argent remis à Naomie (montant confirmé par Naomie)
--   − les bénéficiaires payés par Caleb à la demande de Pax
--   − ajustements « Caleb a remis à Pax »
-- La vente KES → BIF est enregistrée dès que Caleb valide un envoi.
-- =====================================================================

create table if not exists public.caleb_mouvements (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  date date not null default current_date,
  type text not null check (type in ('NAOMIE','BENEF','AJUST')),
  montant numeric(18,0) not null check (montant <> 0),     -- BIF ; AJUST : + Pax a donné à Caleb, − Caleb a remis à Pax
  montant_recu numeric(18,0),                               -- NAOMIE : ce que Naomie a réellement reçu
  statut text not null default 'OK' check (statut in ('ATTENTE','OK')),
  beneficiaire text,
  beneficiaire_tel text,
  transaction_id uuid references public.transactions(id) on delete set null,
  note text,
  saisi_par text,
  confirme_par text,
  confirme_le timestamptz
);
create index if not exists caleb_mv_tx_idx on public.caleb_mouvements (transaction_id);

alter table public.caleb_mouvements enable row level security;
drop policy if exists cm_select on public.caleb_mouvements;
drop policy if exists cm_insert on public.caleb_mouvements;
drop policy if exists cm_update on public.caleb_mouvements;
drop policy if exists cm_delete on public.caleb_mouvements;
create policy cm_select on public.caleb_mouvements for select to authenticated
  using (public.is_staff() or public.is_kenya());
-- Caleb declares what he sent to Naomie (to be confirmed) and beneficiaries he paid; adjustments are admin only
create policy cm_insert on public.caleb_mouvements for insert to authenticated
  with check (
    public.is_admin()
    or (public.is_staff() and type in ('NAOMIE','BENEF'))
    or (public.is_kenya() and type in ('NAOMIE','BENEF') and montant > 0
        and statut = 'ATTENTE' and montant_recu is null and confirme_par is null and transaction_id is null)
  );
create policy cm_update on public.caleb_mouvements for update to authenticated
  using (public.is_staff()) with check (public.is_staff());
create policy cm_delete on public.caleb_mouvements for delete to authenticated
  using (public.is_admin() or (public.is_staff() and type <> 'AJUST')
         or (public.is_kenya() and confirme_par is null and type in ('NAOMIE','BENEF') and statut = 'ATTENTE'));

-- What Caleb enters (money sent to Naomie, beneficiary paid) starts "ATTENTE" and only counts once
-- Naomie or an admin confirms it; until then Caleb can still delete it. Staff entries are OK directly.

-- ---------- Caleb validates an M-Pesa send: the KES are sold to him at once ----------
create or replace function public.kenya_confirm(p_id uuid, p_aed numeric, p_kes numeric, p_taux numeric)
returns void language plpgsql security definer set search_path = public as $$
declare v public.versements; me public.profiles; bif numeric;
begin
  select * into me from public.profiles where id = auth.uid() and statut = 'actif';
  if me.id is null or me.role not in ('KENYA','ADMIN') then raise exception 'Accès refusé'; end if;
  select * into v from public.versements where id = p_id for update;
  if v.id is null then raise exception 'Envoi introuvable'; end if;
  if coalesce(v.methode_envoi, v.moyen, '') not ilike 'M-Pesa%' then raise exception 'Cet envoi ne passe pas par le Kenya'; end if;
  if v.statut = 'RECU' and v.kenya_kes is null then raise exception 'Cet envoi a déjà été confirmé par Naomie'; end if;
  if coalesce(p_aed,0) <= 0 or coalesce(p_kes,0) <= 0 or coalesce(p_taux,0) <= 0 then raise exception 'Montant invalide'; end if;
  bif := round(p_kes * p_taux, 0);
  update public.versements
     set statut = 'RECU', kenya_aed = p_aed, kenya_kes = p_kes, kenya_taux = p_taux, kenya_bif = bif,
         kenya_par = me.nom, kenya_le = now(),
         recu_montant = p_kes, recu_devise = 'KES', confirme_par = me.nom, confirme_le = now()
   where id = p_id;
  delete from public.ventes where versement_id = p_id;
  insert into public.ventes (versement_id, devise, quantite, taux, mode_reception, frais_bif, note, saisi_par, date)
  values (p_id, 'KES', p_kes, p_taux, 'Caleb (Kenya)', 0, 'KES achetés par Caleb', me.nom, current_date);
end $$;

-- Undo Caleb's validation (admin)
create or replace function public.kenya_unconfirm(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Accès refusé'; end if;
  delete from public.ventes where versement_id = p_id;
  update public.versements
     set statut = 'ENVOYE', kenya_aed = null, kenya_kes = null, kenya_taux = null, kenya_bif = null,
         kenya_par = null, kenya_le = null, kenya_bif_recu = null,
         recu_montant = null, recu_devise = null, confirme_par = null, confirme_le = null
   where id = p_id and kenya_kes is not null;
end $$;

-- ---------- A pending transaction paid by Caleb instead of Naomie ----------
create or replace function public.tx_paid_by_caleb(p_tx uuid, p_note text default null)
returns void language plpgsql security definer set search_path = public as $$
declare t public.transactions; me public.profiles; caleb text;
begin
  select * into me from public.profiles where id = auth.uid() and statut = 'actif';
  if me.id is null or me.role not in ('BUJA','ADMIN') then raise exception 'Accès refusé'; end if;
  select * into t from public.transactions where id = p_tx for update;
  if t.id is null then raise exception 'Transaction introuvable'; end if;
  if t.statut <> 'EN_ATTENTE' then raise exception 'Cette transaction n''est plus à payer'; end if;
  select nom into caleb from public.profiles where role = 'KENYA' and statut = 'actif' order by created_at limit 1;
  update public.transactions set statut = 'PAYEE', valide_par = coalesce(caleb, 'Caleb') || ' (Kenya)', valide_le = now() where id = p_tx;
  insert into public.caleb_mouvements (type, montant, beneficiaire, beneficiaire_tel, transaction_id, note, saisi_par, confirme_par, confirme_le)
  values ('BENEF', t.montant_bif, t.beneficiaire, t.beneficiaire_tel, t.id, nullif(trim(p_note),''), me.nom, me.nom, now());
end $$;

revoke execute on function public.kenya_unconfirm(uuid) from anon, public;
revoke execute on function public.tx_paid_by_caleb(uuid,text) from anon, public;
grant execute on function public.kenya_unconfirm(uuid) to authenticated;
grant execute on function public.tx_paid_by_caleb(uuid,text) to authenticated;

-- the per-send confirmation by Naomie is replaced by the deliveries in caleb_mouvements
drop function if exists public.naomie_confirm_kenya(uuid,numeric);
drop function if exists public.naomie_unconfirm_kenya(uuid);
