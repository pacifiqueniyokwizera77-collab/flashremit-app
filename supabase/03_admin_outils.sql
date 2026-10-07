-- =====================================================================
-- Pax International — outils admin (à lancer une fois dans SQL Editor)
-- 1) admin_confirm_user : confirme l'email d'un compte (si l'email de
--    confirmation n'est jamais arrivé).
-- 2) admin_set_password : définit un nouveau mot de passe pour un compte
--    (quand l'email « mot de passe oublié » n'arrive pas).
-- Les deux fonctions refusent toute personne qui n'est pas admin active.
-- =====================================================================

create or replace function public.admin_confirm_user(target uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Réservé aux administrateurs'; end if;
  update auth.users set email_confirmed_at = coalesce(email_confirmed_at, now()) where id = target;
end $$;

create or replace function public.admin_set_password(target uuid, new_password text)
returns void language plpgsql security definer set search_path = public, auth, extensions as $$
begin
  if not public.is_admin() then raise exception 'Réservé aux administrateurs'; end if;
  if new_password is null or length(new_password) < 6 then
    raise exception 'Le mot de passe doit contenir au moins 6 caractères';
  end if;
  update auth.users
     set encrypted_password = extensions.crypt(new_password, extensions.gen_salt('bf')),
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at = now()
   where id = target;
end $$;

revoke execute on function public.admin_confirm_user(uuid) from public, anon;
revoke execute on function public.admin_set_password(uuid, text) from public, anon;
grant execute on function public.admin_confirm_user(uuid) to authenticated;
grant execute on function public.admin_set_password(uuid, text) to authenticated;
