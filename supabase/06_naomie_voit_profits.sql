-- Pax International — Naomie (Bujumbura) peut voir l'historique des paiements aux agents (lecture seule)
drop policy if exists pa_select on public.paiements_agents;
create policy pa_select on public.paiements_agents for select to authenticated
  using (public.is_staff() or (public.is_active_agent() and agent_id = auth.uid()));
