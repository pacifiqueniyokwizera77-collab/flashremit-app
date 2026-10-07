-- Supprime définitivement les comptes de Dargus, Chris Miguel et Darnelle.
-- Les anciennes transactions archivées gardent leurs noms (texte), rien d'autre n'est touché.
delete from auth.users
where email in ('dargusmwet@gmail.com', 'chrismiguelishaka@gmail.com', 'darnellegat08@gmail.com');
