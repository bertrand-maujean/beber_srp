## Synopsis
Script en Python 3.5 pour permettre de configurer la fonctionnalité Software Restriction Policy de Windows, 
sur les versions Home qui n'ont pas les consoles secpol.msc et gpedit.msc
En ligne de commande, avec des menus


## Motivation
Activer les SRP à la maison comme au bureau, notamment pour se prémunir des malwares

## Principe des SRP
Document Microsoft :
https://technet.microsoft.com/en-us/library/cc786941(v=ws.10).aspx

Document sympa expliquant le principe, et la mise en place quand on dispose d'un Windows Pro
https://www.bleepingcomputer.com/tutorials/create-an-application-whitelist-policy-in-windows/
(si vous avez secpol.msc ou gpedit.msc, alors vous n'avez pas besoin de mon script)

Très important : l'activation des SRP suppose que vous avez déjà mis en place un utilisateur 
non privilégié pour le travail de tout les jours avec une identité disjointe de celle de l'administrateur.
Et laisser l'UAC activé  bien sûr.


## Installation
Ce script n'a pas de programme d'installation, et est entièrement contenu dans lui même
Lancer par :
python beber_srp.pyw
(en adaptant les chemins éventuellement...)
Ou lancer dans Idle
Attention : il faut être administrateur pour pouvoir faire des modifications

Mise en garde :
- le script va toucher à votre base de registre
- si vous bloquer l'exécution dans c:\windows ou c:\program files, vous risquez de gros soucis
- Faire un point de restauration avant toute utilisation
- S'assurer que vous avez accès au mode sans échec avant toute utilisation
- Vous utilisez ce script sous votre seule responsabilité. Je suis un piètre développeur, et ce serait à vous d'assumer les éventuels bugs que j'aurais pu programmer.

## Dépendances
Utilise le module winreg livré avec Python 3.5 pour Windows
A priori, aucune dépendance, marche directement avec une installation Windows de Python 3.5, sans rien ajouter.

##FAQ
Pourquoi les hachés ne sont pas gérés ? 
Parce que pour le moment je n'en ai pas eu besoin, mais je pense le faire un jour

Pourquoi les URL ne sont pas gérées ?
Parce que je n'ai pas compris ce que ça fait

Pourquoi les certificats ne sont pas gérés ?
Parce que Microsoft nous sort une focntionnalité mais nous dit de ne pas l'utiliser car elle prend trop de ressources...

Pourquoi le script n'est pas livré en .EXE ?
Parce que vous devez pouvoir l'auditer avant de l'éxécuter, pardis !

Pourquoi les SRP qui sont une fonctionnalité ancienne, et pas Applocker ?
Parce que j'ai trouvé comment le faire marcher sur mes Windows Home, et il faut bien commencer quelque part.
C'est simple et direct, un peu comme AppArmor vs SELinux.





