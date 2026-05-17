Vous êtes sur la page d'un mini projet web pour le stockage et le partage d'informations confidentielles (un secret).

Il y a encore du travail a réaliser afin de le terminer et de le sécuriser.

Fonctionnalités manquantes ou à ajouter
- Supprimer un secret (avec ou sans mot de passe) après sa consultation lorsqu'il est en mode "à la demande".
- Ajouter une durée de vie de 1h
- Ajouter un compteur du nombre de consultations
- Permettre la consultation en nombre limité et avec une durée de vie courte (1h et 24h)
- Ajouter un cron pour la gestion des expirations temporelles

Sécurité
- Ajouter un HMAC pour la requête "query" afin de valider l'autorisation de lecture du secret chiffré
- Limiter la taille du body HTTP (pour éviter les secrets abusivement gros)
- Bloquer les accès abusifs par brute-force via un challenge côté client
- Voir pour utiliser Argon2id ou PBKDF2
- Déplacer le dossier /html/secrets directement dans /secrets
- Ajouter une protection contre le XSS sur les données et remontées par JS
- Faire une configuration Apache HTTPD propre et sécurisée

Autres points
- Résoudre les différents problèmes de CSP, notamment l'injection de Javascript "inline".
- Résourdre le problème de gestion des sessions avec le favicon.
- Embarquer dans les différents CSS/JS directement dans le HTML.
