## Synopsis
Script en Python 3.5 pour permettre de configurer la fonctionnalit� Software Restriction Policy de Windows, 
sur les versions Home qui n'ont pas les consoles secpol.msc et gpedit.msc
En ligne de commande, avec des menus


## Motivation
Activer les SRP � la maison comme au bureau, notamment pour se pr�munir des malwares

## Principe des SRP
Document Microsoft :
https://technet.microsoft.com/en-us/library/cc786941(v=ws.10).aspx

Document sympa expliquant le principe, et la mise en place quand on dispose d'un Windows Pro
https://www.bleepingcomputer.com/tutorials/create-an-application-whitelist-policy-in-windows/
(si vous avez secpol.msc ou gpedit.msc, alors vous n'avez pas besoin de mon script)

Tr�s important : l'activation des SRP suppose que vous avez d�j� mis en place un utilisateur 
non privil�gi� pour le travail de tout les jours avec une identit� disjointe de celle de l'administrateur.
Et laisser l'UAC activ�  bien s�r.


## Installation
Ce script n'a pas de programme d'installation, et est enti�rement contenu dans lui m�me
Lancer par :
python beber_srp.pyw
(en adaptant les chemins �ventuellement...)
Ou lancer dans Idle
Attention : il faut �tre administrateur pour pouvoir faire des modifications

Mise en garde :
- le script va toucher � votre base de registre
- si vous bloquer l'ex�cution dans c:\windows ou c:\program files, vous risquez de gros soucis
- Faire un point de restauration avant toute utilisation
- S'assurer que vous avez acc�s au mode sans �chec avant toute utilisation
- Vous utilisez ce script sous votre seule responsabilit�. Je suis un pi�tre d�veloppeur, et ce serait � vous d'assumer les �ventuels bugs que j'aurais pu programmer.

## D�pendances
Utilise le module winreg livr� avec Python 3.5 pour Windows
A priori, aucune d�pendance, marche directement avec une installation Windows de Python 3.5, sans rien ajouter.

##FAQ
Pourquoi les hach�s ne sont pas g�r�s ? 
Parce que pour le moment je n'en ai pas eu besoin, mais je pense le faire un jour

Pourquoi les URL ne sont pas g�r�es ?
Parce que je n'ai pas compris ce que �a fait

Pourquoi les certificats ne sont pas g�r�s ?
Parce que Microsoft nous sort une focntionnalit� mais nous dit de ne pas l'utiliser car elle prend trop de ressources...

Pourquoi le script n'est pas livr� en .EXE ?
Parce que vous devez pouvoir l'auditer avant de l'�x�cuter, pardis !

Pourquoi les SRP qui sont une fonctionnalit� ancienne, et pas Applocker ?
Parce que j'ai trouv� comment le faire marcher sur mes Windows Home, et il faut bien commencer quelque part.
C'est simple et direct, un peu comme AppArmor vs SELinux.





