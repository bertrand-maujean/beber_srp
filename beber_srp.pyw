import winreg
import re
import random
import time
import struct


# Chemin de la branche de registre
# Et le même avec echappement des \, pour utilisation par re.split
saferBranch = r"SOFTWARE\Policies\Microsoft\Windows\safer"
saferBranchEscaped=r"SOFTWARE\\Policies\\Microsoft\\Windows\\safer"
#saferBranch = r"SOFTWARE\Policies\Microsoft\Windows\safertest"
#saferBranchEscaped=r"SOFTWARE\\Policies\\Microsoft\\Windows\\safertest"


# Genere un GUID 128 entre accolades
def newGUID():
        r=random.randint(0,65535)
        a=format(random.randint(0,65535), "04x")
        b=format(random.randint(0,65535), "04x")
        c=format(random.randint(0,65535), "04x")
        d=format(random.randint(0,65535), "04x")
        e=format(random.randint(0,65535), "04x")
        f=format(random.randint(0,65535), "04x")
        g=format(random.randint(0,65535), "04x")
        h=format(random.randint(0,65535), "04x")
        return "{"+a+b+"-"+c+"-"+d+"-"+e+"-"+f+g+h+"}"



# Genere un "LastModified" en packed byte
def newLastModified():
    t = time.time() # float
    t = 100000000*t
    t = int(t)
    r = struct.pack("<q", t)
    return r


# Retourne True si il faut utiliser REG_EXPAND_SZ au lieu de REG_SZ
def isExpandable(s):
        if s.find("%")==-1:
                return False
        else:
                return True
        

# Classe pour stocker une clé de SRP chemin
class CpathSRP:
        def __init__(self, keyRegistre):
                self.niveau=0
                self.guid = ""
                self.chemin = ""
                self.description = ""
                self.valide=0   # A 1 seulement si le CpathSRP est considere comme
                                # valide, càd qu'on a réussi son initialisation

                self.enbase=0   # mis à 1 si l'enregistrement est déjà dans la base de registres
                self.a_supprimer=0 # mettre à 1 si ce chemin doit etre supprimé à l'enregistrement
                self.a_enregistrer=0
                self.keyRegistre=keyRegistre

                #print("CpathSRP.__init__(\""+str(keyRegistre)+"\")")                        


                if keyRegistre==None:
                        self.chemin=input("Entrez le chemin : ")
                        self.description=input("Entrez une description :")
                        self.guid=newGUID()
                        #print("GUID aleatoire :"+self.guid)
                        
                        while True:
                                try:
                                        rep=input("Niveau (262144=non restreint, 131072=utilisateur normal seulement, 0=aucune execution) ?")
                                        nrep=int(rep)
                                        if nrep!=0 and nrep != 131072 and nrep!= 262144:
                                                continue
                                                                               
                                except:
                                        continue
                                
                                break
                        
                        self.niveau=nrep
                        self.a_enregistrer=1
                        self.keyRegistre=saferBranch+"\\CodeIdentifiers\\" +str(self.niveau)+"\\Paths\\"+self.guid
                        print("clé="+self.keyRegistre)
                        
                        
                        
                        
                else:
                        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keyRegistre)
                        self.chemin = winreg.QueryValueEx(k, "ItemData") [0]
                        self.description = winreg.QueryValueEx(k, "Description") [0]                        

                        x = re.split(saferBranchEscaped+r"\\CodeIdentifiers\\(\d*)\\Paths\\(.{38})", keyRegistre)
                        #print(x)
                        if len(x) != 4:
                                print("CpathSRP.lisRegistre(): erreur, le split du chemin ne renvoie pas le bon nombre d'elements. Etait :"+keyRegistre)
                                return

                        self.niveau=int(x[1])
                        self.guid=x[2]
                        self.enbase=1
                return


        # Affiche le chemin, si son niveau 0, 0x20000, 0x40000 correspond
        # au filtre
        def affiche(self):
                intitules = { 0x0: "Non autorise", 0x20000: "Utilisateur standard", 0x40000: "Non restreint" }
                print (self.chemin+"\n\t\t"+intitules[self.niveau]+" ("+str(self.niveau)+")" )
                if self.a_supprimer==1:
                        print("\t\tsera supprimé")
                elif self.a_enregistrer==1:
                        print("\t\tsera mis à jour")
                
                print("\t\t("+self.description+")\n")
            
                return

        # Met a jour la base de registre si necessaire
        def maj(self):
                if self.a_supprimer==1:
                        try:
                                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, self.keyRegistre)
                        except OSError:
                                print("Erreur Windows à la suppression dans la base de registre")
                                
                elif self.a_enregistrer==1:
                        key=winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, self.keyRegistre) # Create fait l'effet d'un Open sur une clé existante
                        
                        winreg.SetValueEx(key, "LastModified", 0, 11, newLastModified())
                        winreg.SetValueEx(key, "Description", 0, winreg.REG_SZ, self.description)
                        winreg.SetValueEx(key, "SaferFlags", 0, winreg.REG_DWORD, 0)
                        if isExpandable(self.chemin):
                                 winreg.SetValueEx(key, "ItemData", 0, winreg.REG_EXPAND_SZ, self.chemin)
                        else:
                                 winreg.SetValueEx(key, "ItemData", 0, winreg.REG_SZ, self.chemin)
                                 
                        winreg.CloseKey(key)
                        
                #else:
                #        print("Appel maj sans rien faire "+self.chemin)
                                
                return

        # Menu modifie
        def menu_modifie(self):
                rep=input("\tChemin ["+self.chemin+"] ? ")
                if rep!="":
                        self.chemin==rep

                rep=input("\tDescription ["+self.description+"] ? ")
                if rep!="":
                        self.description==rep
                self.a_enregistrer=1
                print("(Pour changer le niveau : supprimer cette entrée et en créer une autre...)")
                
                return

        



# Recupere les types de fichiers executables
def getExeExtensions():
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+r"\\codeidentifiers")
                (v,t) = winreg.QueryValueEx(key, "ExecutableTypes")
        except OSError:
                return []
                
        if (t != winreg.REG_MULTI_SZ):
                print("getExeExtension : la cle n'a pas le bon type")
                return []
        
        return v

def setExeExtensions(v):
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+"\\codeidentifiers", access=winreg.KEY_WRITE)
                winreg.SetValueEx(key, "ExecutableTypes", 0, winreg.REG_MULTI_SZ, v)
                
        except OSError:
                print("Erreur système dans setExensions()")
                return
                
        return



# Recupere le niveau par defaut
def getDefaultLevel():
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+"\\CodeIdentifiers")
                (v,t) = winreg.QueryValueEx(key, "DefaultLevel")
                
        except OSError:
                print("Erreur : on dirait que SRP n'est pas installé du tout. Essayer d'appliquer une configuration de départ")
                return None

        
        if (t != winreg.REG_DWORD):
                print("getDefaultLevel : la cle n'a pas le bon type")
                return None
        
        if (v != 0 and v != 0x40000 and v != 0x20000):
                print("getDefaultLevel : valeur lue incorrecte")
                return None           

        intitules = { 0x0: "Non autorise", 0x20000: "Utilisateur standard", 0x40000: "Non restreint" }
                        
        return (v, intitules[v])

def setDefaultLevel(v):
        print("Appel à setdefaultLevel() "+str(v))
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+r"\CodeIdentifiers", access=winreg.KEY_WRITE)
                winreg.SetValueEx(key, "DefaultLevel", 0, winreg.REG_DWORD, v)
                
        except OSError:
                print("Erreur système dans setDefaultLevel()")
                return None
                
        return


# Recupere le policyScope
def getPolicyScope():
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,saferBranch+r"\codeidentifiers")
                (v,t) = winreg.QueryValueEx(key, "PolicyScope")

        except OSError:
                print("Erreur : on dirait que SRP n'est pas installé du tout. Essayer d'appliquer une configuration de départ")
                return None
        
                
        if (t != winreg.REG_DWORD):
                print("getPolicyScope : la cle n'a pas le bon type")
                return None
        
        if (v != 0 and v != 1):
                print("getPolicyScope : valeur lue incorrecte")
                return None           

        intitules = { 0x0: "All users", 0x1: "All users except admins" }
        
        return (v, intitules[v])

def setPolicyScope(v):
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+r"\CodeIdentifiers", access=winreg.KEY_WRITE)
                winreg.SetValueEx(key, "PolicyScope", 0, winreg.REG_DWORD, v)
                
        except OSError:
                print("Erreur système dans setPolicyScope()")
                return
                
        return


# Recupere le transparentEnabled
def getTransparentEnabled():   
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+r"\CodeIdentifiers")
                (v,t) = winreg.QueryValueEx(key, "TransparentEnabled")
                
        except OSError: 
                (v,t) = (-1, winreg.REG_DWORD)
                pass
        
        if (t != winreg.REG_DWORD):
                print("getTransparentEnabled : la cle n'a pas le bon type")
                return None
        
        if (v!=-1 and v != 0 and v != 1 and v!= 2):
                print("getTransparentEnabled : valeur lue incorrecte")
                return None           

        intitules = { -1: "SRP pas installé", 0x0: "No enforcement", 0x1: "All files except DLL", 0x2: "All files including DLL" }
                        
        return (v, intitules[v])


# Reprogramme le mode transparent
def setTransparentEnabled(v):
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+r"\CodeIdentifiers", access=winreg.KEY_WRITE)
                winreg.SetValueEx(key, "TransparentEnabled", 0, winreg.REG_DWORD, v)
                
        except OSError:
                print("Erreur système dans setTransparentEnabled()")
                return
                
        return
        


# Recupere le fichier de log
def getLogFileName():     
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, saferBranch+"\\CodeIdentifiers")
                (v,t) = winreg.QueryValueEx(key, "LogFileName")
                if (t != winreg.REG_SZ):
                        print("getLogFileName : la cle n'a pas le bon type")
                        v=None
                        
        except OSError:
                v=None
                pass
        
        return v


def setLogFileName(v):
        keyPath=saferBranch+"\\CodeIdentifiers"
        #print(keyPath)
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keyPath, access=winreg.KEY_WRITE )
                if v==None:
                        # suppression de la clé
                        winreg.DeleteValue(key, "LogFileName")
                else:
                        # creation/modification
                        winreg.SetValueEx(key, "LogFileName", 0, winreg.REG_SZ, v)
                        
        except OSError:
                print("Erreur système dans setLogFileName(). Il faut etre admin.")
                return
                
        return




def regles_initiales():
        extensions=["ADE","ADO","BAS","BAT","CHM","CMD","COM","COL","CRT","EXE","HLO","HTA","INf","INS","MDB","MDE",
                "MSC","MSI","MSO","OCX","OCD","OIF","REG","SCR","SHS","URL","VB","wSC","PS1","JSE","VBS","SCT","VBE","WSF"]

        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,saferBranch+r"")
                key = winreg.CreateKeyEx(key, "CodeIdentifiers")
                winreg.SetValueEx(key,"DefaultLevel",        0, winreg.REG_DWORD, 0x40000)
                winreg.SetValueEx(key,"TransparentEnabled",  0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key,"PolicyScope",         0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key,"AuthenticodeEnabled", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key,"ExecutableTypes",     0, winreg.REG_MULTI_SZ, extensions)
                                                
                winreg.CreateKey(key,"0")
                winreg.CreateKey(key,"0\\Hashes")
                winreg.CreateKey(key,"0\\UrlZones")
                winreg.CreateKey(key,"0\\Paths")
                winreg.CreateKey(key,"131072")
                winreg.CreateKey(key,"131072\\Hashes")
                winreg.CreateKey(key,"131072\\UrlZones")
                winreg.CreateKey(key,"131072\\Paths")
                winreg.CreateKey(key,"262144")
                winreg.CreateKey(key,"262144\\Hashes")
                winreg.CreateKey(key,"262144\\UrlZones")
                winreg.CreateKey(key,"262144\\Paths")
                winreg.CloseKey(key)

                key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,saferBranch+r"\\CodeIdentifiers\\262144\\Paths")
          
				
                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified", 0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description", 0, winreg.REG_SZ, r"Repertoire Windows")
                winreg.SetValueEx(key2, "SaferFlags", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData", 0, winreg.REG_EXPAND_SZ, r"%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%")
                winreg.CloseKey(key2)
				
                
                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified",         0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description",          0, winreg.REG_SZ, r"Program Files on 64 bits")
                winreg.SetValueEx(key2, "SaferFlags",           0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData",             0, winreg.REG_EXPAND_SZ, r"%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir%")
                winreg.CloseKey(key2)
				
                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified",         0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description",          0, winreg.REG_SZ, r"Program Files x86")
                winreg.SetValueEx(key2, "SaferFlags",           0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData",             0, winreg.REG_SZ, r"C:\Program Files (x86)")
                winreg.CloseKey(key2)

                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified",         0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description",          0, winreg.REG_SZ, r"%ProgramW6432%")
                winreg.SetValueEx(key2, "SaferFlags",           0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData",             0, winreg.REG_EXPAND_SZ, r"%ProgramW6432%")
                winreg.CloseKey(key2)

                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified",         0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description",          0, winreg.REG_SZ, r"%ProgramFiles(x86)%")
                winreg.SetValueEx(key2, "SaferFlags",           0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData",             0, winreg.REG_EXPAND_SZ, r"%ProgramFiles(x86)%")
                winreg.CloseKey(key2)

                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified",         0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description",          0, winreg.REG_SZ, r"%ProgramFiles%")
                winreg.SetValueEx(key2, "SaferFlags",           0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData",             0, winreg.REG_EXPAND_SZ, r"%ProgramFiles%")
                winreg.CloseKey(key2)            

                guid=newGUID()
                key2=winreg.CreateKey(key,guid)
                winreg.SetValueEx(key2, "LastModified",         0, 11, newLastModified())
                winreg.SetValueEx(key2, "Description",          0, winreg.REG_SZ, r"%SystemRoot%")
                winreg.SetValueEx(key2, "SaferFlags",           0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key2, "ItemData",             0, winreg.REG_EXPAND_SZ, r"%SystemRoot%")
                winreg.CloseKey(key2)

		
                winreg.CloseKey(key)

        except OSError:
                print("Echec à l'application des règles initiales. Cause possible : le programme n'a pas été lancé avec les droits d'administrateur")
                return

        print("\nUn jeu de règles initiales a été appliqué. Attention :")
        print("- Le DefaultLevel est à 0x40000, c'est à dire que rien n'est restreint")
        print("- Le TransparentEnabled est à 0, c'est à dire que le SRP n'est pas mis en place")
        print("- Des répertoires par défaut ont été créé, parfois redondants et inutiles. Vous pouvez ajuster, ou laisser ainsi")
        print("Pour terminer la configuration, vous devrez modifier ces valeurs")
       
        return


# Suppression des sous clé d'une clé (pour suppression récurisve d'une branche)
def elagueBranche(key):
        n=0
        while 1:
                try:
                        subkey_name=winreg.EnumKey(key, n)
                except OSError:
                        break

                subkey=winreg.OpenKey(key, subkey_name)
                elagueBranche(subkey)
                winreg.CloseKey(subkey)
                winreg.DeleteKey(key, subkey_name)
                
        


def supprimeTout():
        try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,saferBranch+r"", access=winreg.KEY_ALL_ACCESS)
        except OSError:
                print("supprimeTout() : erreur sur OpenKey")
                return

        elagueBranche(key)
        
        key2 = winreg.CreateKeyEx(key, "CodeIdentifiers")
        winreg.SetValueEx(key2,"AuthenticodeEnabled", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        winreg.CloseKey(key2)
        
        return


# Recupere la liste de chemin pour un niveau donne
"""
def getPathsAncien(level):
        chemin_cle = saferBranch+r"\\codeidentifiers\\"+str(level)+"\\Paths"

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,chemin_cle)
        index=0
        chemins_registry=[]
        while 1:
                try:
                        data=winreg.EnumKey(key, index)
                        index+=1
                        chemins_registry.append(chemin_cle+"\\"+data)
                except OSError:
                        break

        result = []
        
        for i in chemins_registry:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, i)
                result.append ( winreg.QueryValueEx(key, "ItemData") [0] )
                
        return result
"""


# Récupère tous les chemins existants sous forme d'une liste d'object CpathSRP
def getPaths():
        result=[]
        for l in [0, 0x20000, 0x40000]:
                chemin_cle=saferBranch+"\\CodeIdentifiers\\"+str(l)+"\\Paths"
                #print(chemin_cle)

                try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,chemin_cle)
                        
                except OSError:
                        print("getPaths() erreur OpenKey") 
                        pass
                                        
                index=0
                while 1:
                        try:
                                data=winreg.EnumKey(key, index)
                                

                        except (NameError): # NameError si le winreg.OpenKey a foiré. Dans ce cas, key n'est pas défini
                                #print("getPaths() NameError EnumKey")
                                break

                        except (OSError):
                                #print("getPaths() OSError EnumKey")
                                break

                        index+=1
                        result.append(CpathSRP(chemin_cle+"\\"+data))
                
       
        return result

# Menu des chemins d'execution
def menu_chemins_execution():      
        cheminsExe = getPaths()
        encore=1
        modif=0
        while encore:
                print("\n\nMenu principal>Parametres globaux>Chemins d'execution>")
                i=1
                for c in cheminsExe:
                        print("\t"+str(i)+" ", end="")
                        c.affiche()
                        i+=1
                print("")
                print("\ta: Ajout d'un chemin")
                print("\td: Suppression d'un chemin")
                print("\tm: modifier un chemin")
                print("\t0: menu précédent")
                print("\tChoix", end="")
                c=input("?")
                c=c.upper()

                if c=="0":
                        encore=0
                        
                elif c=="A":
                        cheminsExe.append(CpathSRP(None))
                        print

                elif c=="D":
                        print("Entrez le numero du chemin à supprimer", end="")
                        try:
                                cc=input("?")
                                n=int(cc)
                                cheminsExe[n-1].a_supprimer=1 # Nb l'affichage commence à 1...
                        except:
                                print ("Erreur...")
                                pass
                        
                        
                elif c=="M":
                        print


        for i in cheminsExe:
                i.maj()
                
        return

# Menu des extensions executables
def menu_extensions_executables():
        print("\n\nMenu principal>Parametres globaux>Extensions executables>")
        encore=1
        modif=0
        exts=getExeExtensions()
        while encore:
                n=0
                print("\t", end="")
                for i in exts:
                        print(i+" ", end="")
                        n+=1
                        if n %16 == 0:
                                print("\n\t", end="")

                print("\n\tExtension à ajouter/supprimer, ou rien pour revenir au menu précédent", end="")
                e=input("?")
        

                if e!="":
                        e=e.upper()
                        try:
                                i=exts.index(e)
                                print("\tSuppression de "+e)
                                modif=1
                                exts.pop(i)
                        except ValueError:
                                print("\tAjout de "+e)
                                modif=1
                                exts.append(e)
                                                                
                else:
                        encore=0

                print("")
                
        if modif==1:
                print("\tConfirmer la modification (o/n)", end="")
                c=input("?")
                if c.upper()=="O":
                        print("\tModification de la base de registre")
                        setExeExtensions(exts)
                        
                      
        return


def menuChgTransparentEnabled():
        print("\n\nMenu principal>Parametres globaux>Changement activation>")
        t=getTransparentEnabled()
        print("\tTransparentEnable: 0=No enforcement, 1=All files except DLL, 2=All files including DLL")
        print("\tNouvel etat [actuel="+str(t)+"]: ", end="")
        r=input("?")
        if r!="":
                try:
                        n=int(r)
                except:
                        n=-1

                if n==0 or n==1 or n==2:
                        if n>t[0]:
                                r=input("Vous demandez une valeur plus restrictive. Confirmez (o/n) ?")
                                r=r.upper()
                                if r=="O":
                                        setTransparentEnabled(n)
                        else:
                                setTransparentEnabled(n)
                        
                else:
                        print("\tValeur invalide. Pas de changement")
        
        else:
                print("\tPas de changement")
        
        return

     
def menuChgPolicyScope():
        print("\n\nMenu principal>Parametres globaux>PolicyScope>")
        t=getPolicyScope()
        print("\t0=All users, 1=All users except admins")
        print("\tNouvel etat [actuel="+str(t)+"]: ", end="")
        r=input("?")
        if r!="":
                try:
                        n=int(r)
                except:
                        n=-1

                if n==0 or n==1:
                        setPolicyScope(n)
                else:
                        print("\tValeur invalide. Pas de changement")
        else:
                print("\tPas de changement")
        
        return

               
def menuChgDefaultLevel():
        print("\n\nMenu principal>Parametres globaux>Default level>")
        t=getDefaultLevel()
        print("\t0=Non autorise, 131072(0x20000)=Utilisateur standard, 262144(0x40000)=Non restreint")
        print("\tNouvel etat [actuel="+str(t)+"]: ", end="")
        r=input("?")
        if r!="":
                try:
                        n=int(r)
                except:
                        n=-1

                if n==0 or n==0x20000 or n==0x40000:
                        if n<t[0]:
                                r=input("Nouvelle valeur plus restrictive. Confirmez (o/n) ?")
                                if r.upper()=="O":
                                        setDefaultLevel(n)
                        else:
                                setDefaultLevel(n)

                        
                else:
                        print("\tValeur invalide. Pas de changement")
        else:
                print("\tPas de changement")
        
        return
        

               
def menuChgLogFileName():
        print("\n\nMenu principal>Parametres globaux>LogFileName>")
        lfn=getLogFileName()
        print("\tNouveau fichier journal, laisse vide pour supprimer le journal [actuel="+str(lfn)+"]: ", end="")
        lfn=input("?")
        if lfn=="":
                lfn=None

                
        if lfn!=None:
                print("\tNouveau fichier de log:"+str(lfn), end="")
        else:
                print("\tDésaciver le fichier de log.", end="")
                      
        print(" Confirmation (o/n)", end="")  
        c=input("?")  
        if c.upper()=="O":
                print("\tMise en place du nouveau fichier de log")
                setLogFileName(lfn)

        print("")
        return




# Parametres globaux
def menu_parametres_globaux():
        encore=1
        while encore:
                print("\n\nMenu principal>Parametres globaux>")
                t=getTransparentEnabled()
                print("\t1: Etat d'activation SRP :"+t[1]+" ("+str(t[0])+")")
                if t!=0:
                        s=getPolicyScope()
                        if s!=None:
                                print("\t2: Appliqué sur: "+s[1]+" ("+str(s[0])+")")

                        d=getDefaultLevel()
                        if d!=None:
                                print("\t3: Niveau par défaut: "+d[1]+" ("+str(d[0])+")")

                        l=getLogFileName()
                        if l==None:
                                print("\t4: Pas de fichier journal défini")
                        else:
                                print("\t4: Fichier journal: "+l)
                                
                print("\t0: retour au menu principal")

                choix=input("\tVotre choix / parametre à changer ?")
                try:
                        nchoix=int(choix)
                except:
                        nchoix=-1
                        pass

                if nchoix==1:
                        menuChgTransparentEnabled()
                elif nchoix==2:
                        menuChgPolicyScope()
                elif nchoix==3:
                        menuChgDefaultLevel()
                elif nchoix==4:
                        menuChgLogFileName()
                elif nchoix==0:
                        encore=0
                else:
                        print("Choix invalide")
                        


# Menu principal
def menu_principal():
        encore=1
        while encore:
       
                print("\nMenu principal>:")
                print("\t1: Paramètres globaux")
                print("\t2: Extensions executables")
                print("\t3: Chemins d'execution")
                print("\t4: Hachés")
                print("\t5: Installer un jeu de règles initiales")
                print("\t6: Supprimer la configuration SRP")
                print("\t0: Quitter")

                choix=input("\tVotre choix ?")
                try:
                        nchoix=int(choix)
                except:
                        nchoix=-1
                        pass

                if nchoix==1:
                        menu_parametres_globaux()
                elif nchoix==2:
                        menu_extensions_executables()
                elif nchoix==3:
                        menu_chemins_execution()
                elif nchoix==4:
                        print("Le programme ne prend pas encore en compte les hachés")
                elif nchoix==5:
                        regles_initiales()
                elif nchoix==6:
                        supprimeTout()
                elif nchoix==0:
                        encore=0
                else:
                        print("Choix invalide\n")

                
                
                        
        


# Programme principal
print ("Utilitaire de controle de Software Restriction Policy de Windows\n")
print ("Mise en garde : ce programme modifie la base de registre, et peut bloquer l'exécution de programmes")
print ("nécessaires au bon fonctionnement de Windows. Donc bloquer tout Windows. Il est fortement recommandé")
print ("de créer un point de restauration du système avant de mettre en place les SRP")
print ("(panneau de config/système/protection du système/créer)")
print ("Assurez vous également d'avoir accès au mode sans échec (F8 au démarrage / bcdedit /set {bootmgr} displaybootmenu yes pour W>=8)")

print ("---------------------")
menu_principal()

