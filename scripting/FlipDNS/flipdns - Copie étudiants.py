#!/usr/bin/env python3
# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === SCRIPT ORIGINAL CRÉÉ PAR JEANNE ÉMARD, CONSULTANTE CHEZ 'LES SUPER ADMINS'                                                             ===
# === VERSION 1.0 : JUIN 2026                                                                                                                ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === IMPORTER LES MODULES REQUIS POUR L'EXÉCUTION DU SCRIPT                                                                                 ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
import argparse                              # Permet de lire et gérer les paramètres passés en ligne de commande (ex: -d, -f, -l)
import platform                              # Permet d’identifier le système d’exploitation (Windows, Linux, etc.)
import subprocess                            # Permet d’exécuter des commandes du système (netsh, nmcli, etc.)
import xml.etree.ElementTree as g_ArbreXML   # Permet de lire et analyser un fichier XML (config des DNS)
import os                                    # Permet d’interagir avec le système (fichiers, dossiers, suppression, etc.)
import json                                  # Permet de lire et écrire des données au format JSON (sauvegarde des DNS)
import locale                                # Permet de connaître les paramètres locaux (ex: encodage du système)
import re                                    # Permet d’utiliser des expressions régulières (recherche avancée dans du texte)
import sys                                   # Permet d'utiliser les fonctions du système d'exploitation
import socket                                # Importe le module socket pour permettre à Python de communiquer sur le réseau (TCP/IP, IPv4, IPv6)

# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === DÉFINITION DES VARIABLES GLOBALES                                                                                                      ===
# ===                                                                                                                                        ===
# === Toutes les valeurs codées en durs sont des variables globales.  Il suffit de modifier les variables dans cette section.                ===
# === Inutile de parcourir tout le code.                                                                                                     ===
# === Pour utiliser une variable globale, il suffit d'inscrire 'global' avec le nom de la variable, au début de la fonction.                 ===
# ===                                                                                                                                        ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
g_Debogue = False                                                   # Pour le débogage.  Voir la fonction principale.
g_FichierXMLDefaut = "./DNS.xml"                                    # Le fichier XML par défaut
g_SystemeExploitation = ""                                          # Le système d'exploitation sur lequel le script s'exécute
g_FichierSauvegardeDNS = "dns.bkp"                                  # Le nom du fichier de sauvegarde à utiliser
g_VersionIP = { "ipv4": "ip", "ipv6": "ipv6" }                      # Pour les commandes DNS Windows, la commande doit spécifier si les DNS IPv4 ou IPv6 sont visés.  Note: Ce n'est pas le cas de Linux. 
g_VersionIP1 = { "ipv4": "ipv4", "ipv6": "ipv6" }                   # Pour les commandes DNS Linux, la commande doit spécifier si les DNS IPv4 ou IPv6 sont visés.  Note: Ce n'est pas le cas de Linux
g_TypeDNS = { "principal": "set", "secondaire": "add" }             # Dans Windows, il faut une commande pour configurer le DNS principal, et une commande pour configurer les DNS secondaire.  La commande sera ajustée à l'aide de cette variable
g_IPv4Pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'                      # Patterns d'analyse RegEx pour adresses IPv4
g_IPv6Pattern = r'\b(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+\b'             # Patterns d'analyse RegEx pour adresses IPv6
g_DNSTest = "crosemont.qc.ca"                                       # Le domaine DNS à résoudre lors des tests de vérification du DNS

# Indique l'état de fonctionnement des stacks IP pour éviter des plantages du script lors des vérifications et des configurations.
g_StacksActifs = { "ipv4": { "statut": False, "ip_validation": "8.8.8.8", "port": 53, "timeout": 3, "stack": "4" }, 
                   "ipv6": { "statut": False, "ip_validation": "2001:4860:4860::8888", "port": 53, "timeout": 3, "stack": "6" }
                 }

# La variable ci-dessous contiendra les adresses DNS obtenus de l'interface active
g_DNSInterfaceActive = {
    "ipv4": [],
    "ipv6": []
}

# Informations spécifique aux systèmes d'exploitation.  Rend les fonctions ci-dessous facilement ajustable si on ajoute un système d'exploitation
g_ConfigSystemeExploitation = {
    "WINDOWS": {
        "nom": "Windows",
        "encodage": "utf-8",
        "etats_connexion": ["Connected", "Connecté"],
        "lire_interface": 'netsh interface show interface',
        "longueur_fonction_split": -1,
        "lire_dns_interface": 'netsh interface {%VERSION_IP%} show dns name="{%NOM_INTERFACE%}"',
        "ecrire_dns_interface": 'netsh interface {%VERSION_IP%} {%TYPE_DNS%} dns name="{%NOM_INTERFACE%}" {%STATIC%} {%ADRESSE_IP%}',
        "verifier_dns": 'dig A {%DNSTest%} @"{%ServeurDNS%}" -{%STACK_IP%}',
        "activer_dhcp": 'netsh interface {%VERSION_IP%} set dnsservers "{%NOM_INTERFACE%}" dhcp'
    }
}


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === EXÉCUTER UNE COMMANDE DE SYSTÈME D'EXPLOITATION: Certaines fonctions n'existent pas dans Python.                                       ===
# === Il faut utiliser des commandes PowerShell ou Bash pour effectuer des opérations sur le système d'exploitation.                         ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. La commande à exécuter                                                                                                           ===
# ===    2. Encodage (pour avoir les catactères accentués)                                                                                   ===
# ===                                                                                                                                        ===
# === Valeurs retournées:                                                                                                                    ===
# ===    La sortie standard de la commande                                                                                                   ===
# ===    La sortie des erreurs de la commande                                                                                                ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ExecuterCommande(p_Commande, p_Encodage):
    global g_Debogue
    
    if g_Debogue: print("f_ExecuterCommande() : commande reçue: '" + p_Commande + "' (encodage='" + p_Encodage + "')")
    
    try:
        l_Resultat = subprocess.run(p_Commande, shell=True, capture_output=True, text=True, encoding=p_Encodage)
        return (l_Resultat.stdout or "").strip(), (l_Resultat.stderr or "").strip()
    except Exception as l_Erreur:
        if g_Debogue: print(f"Erreur commande: {l_Erreur}")
        return "", str(l_Erreur)


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === QUEL SYSTÈME EXPLOITATION: Détermine le système d'exploitation sur lequel s'exécute le script.                                         ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    Aucun paramètre requis.                                                                                                             ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    La variable g_SystemeExploitation est mise à jour                                                                                   ===
# ===    Vrai est retourné si le système est valide.  Faux sinon.                                                                            ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_QuelSystemeExploitation():
    global g_SystemeExploitation
    
    # Obtenir le système d'exploitation
    g_SystemeExploitation = platform.system().upper()
    
    # Vérifier si le système d'exploitation est valide
    if g_SystemeExploitation in g_ConfigSystemeExploitation:
       l_ValeurRetournee = True
    else:
       l_ValeurRetournee = False
    
    return l_ValeurRetournee


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === ERREUR FATALE: Affiche un message d'erreur puis termine le script.                                                                     ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. p_MessageErreur : le message d'erreur à afficher.                                                                                ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    1 : indique l'échec du script                                                                                                       ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ErreurFatale(p_MessageErreur):
    # Afficher le message à la console
    print("ERREUR FATALE : " + p_MessageErreur)
    
    # Éviter que la console se ferme avant que l'utilisateur voit le message
    input("APPUYER SUR LA TOUCHE ENTRÉE POUR CONTINUER !")
    
    # Quitter le script
    sys.exit(-1)


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === AFFICHER AIDE: Affiche l'aide à la console quand -? est spécifié.                                                                      ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    Aucun paramètre requis.                                                                                                             ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_AfficherAide():
    print("AIDE TOI ET LE CIEL T'AIDERA")


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === CHARGER LE CONTENU DU FICHIER XML                                                                                                      ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. p_FichierXML : le fichier XML à lire.  L'existence du fichier a été validée dans la fonction principale.                         ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    1 : la liste des fournisseurs DNS                                                                                                   ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ChargerConfigDNS(p_FichierXML):
    global g_Debogue
    
    l_FournisseursDNS = []
    
    if g_Debogue: print("f_charger_config_dns() : entrée dans la fonction")
    
    try: l_ContenuXML = g_ArbreXML.parse(p_FichierXML)
    except g_ArbreXML.ParseError: f_ErreurFatale("Le fichier XML est vide ou invalide.")
    
    try: l_NoeudRacine = l_ContenuXML.getroot()
    except l_ContenuXML.ParseError: f_ErreurFatale("Impossible de lire le noeud racine.")
    
    l_NoeudFournisseurs = l_NoeudRacine.find("fournisseurs")
    if l_NoeudFournisseurs is None: f_ErreurFatale("Le noeud XML 'fournisseurs' est introuvable.")
    
    for l_FournisseurDNS in l_NoeudFournisseurs.findall("fournisseur"):
        l_NomFournisseur = l_FournisseurDNS.get("nom")
        l_TestDNS = l_FournisseurDNS.get("test") == "true"
        
        l_DNSv4 = [l_AdresseIP.text for l_AdresseIP in l_FournisseurDNS.findall("ipv4")]
        l_DNSv6 = [l_AdresseIP.text for l_AdresseIP in l_FournisseurDNS.findall("ipv6")]
        
        l_FournisseursDNS.append({
            "nom": l_NomFournisseur,
            "ipv4": l_DNSv4,
            "ipv6": l_DNSv6,
            "test": l_TestDNS
        })
    
    if g_Debogue:
       print(f"Nombre de fournisseurs DNS chargés: {len(l_FournisseursDNS)}")
       for l_FournisseurDNS in l_FournisseursDNS:
           print(l_FournisseurDNS)
    
    if g_Debogue: print("f_charger_config_dns() : fonction terminée")
    return l_FournisseursDNS


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === VÉRIFIER SI LES STACKS IPV$ ET IPV? SONT ACTIFS                                                                                        ===
# === Note: un sytack inactif peut causer l'échec du script, en particulier lors des vérifications ou des configurations des DNS..           ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    Aucun                                                                                                                               ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_VerifierStacksIP():
    global g_Debogue
    global g_StacksActifs
    
    if g_Debogue: print("f_VerifierStacksIP() : entrée dans la fonction")
    
    # Vérifier si le stack IPv4 est actif
    try:
        socket.create_connection((g_StacksActifs["ipv4"]["ip_validation"], g_StacksActifs["ipv4"]["port"]), timeout=g_StacksActifs["ipv4"]["timeout"])
        g_StacksActifs["ipv4"]["statut"] = True
        if g_Debogue: print("f_VerifierStacksIP() : Stack IPv4 actif")
    except OSError:
        g_StacksActifs["ipv4"]["statut"] = False
        if g_Debogue: print("f_VerifierStacksIP() : Stack IPv4 inactif")
    
    # Vérifier si le stack IPv6 est actif
    try:
        socket.create_connection((g_StacksActifs["ipv6"]["ip_validation"], g_StacksActifs["ipv4"]["port"]), timeout=g_StacksActifs["ipv4"]["timeout"])
        g_StacksActifs["ipv6"]["statut"] = True
        if g_Debogue: print("f_VerifierStacksIP() : Stack IPv6 actif")
    except OSError:
        g_StacksActifs["ipv6"]["statut"] = False
        if g_Debogue: print("f_VerifierStacksIP() : Stack IPv6 inactif")
    
    if g_Debogue: print("f_VerifierStacksIP() : fonction terminée")
    
    return None


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === OBTENIR L'INTERFACE RÉSEAU ACTIVE: Le script agit sur l'interface active                                                               ===
# === Note: 1. la fonction présume que le système d'exploitation a été validé.                                                               ===
# ===       2. Si plus d'une interface est active, l'utilisateur devra choisir sur laquelle il faut travailler.                              ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    Aucun                                                                                                                               ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Le nom de l'interface active                                                                                                        ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ObtenirInterfaceActive():
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    
    l_InterfacesActives = []      # Variable qui contiendra les interfaces actives
    l_NomTemporaire = ""          # Variable temporaire
    
    if g_Debogue: print("f_ObtenirInterfaceActive() : entrée dans la fonction")
    
    # Spécifier la commande à exécuter selon le système d'exploitation
    l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["lire_interface"]
    if g_Debogue: print("La commande à exécuter est :'" + l_Commande + "' [" + g_ConfigSystemeExploitation[g_SystemeExploitation]["nom"] + "]")
    
    # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
    l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
    if g_Debogue: print("Résultats: " + l_Resultat)
    if g_Debogue: print("Erreurs: " + l_Erreurs)
    
    # Récupérer la liste des interfaces réseau actives
    for l_LigneResultat in l_Resultat.splitlines():
        if any(État in l_LigneResultat for État in g_ConfigSystemeExploitation[g_SystemeExploitation]["etats_connexion"]):
           l_NomTemporaire = re.sub(r'(?<! ) (?! )', '_', l_LigneResultat)
           l_NomTemporaire = l_NomTemporaire.split()[g_ConfigSystemeExploitation[g_SystemeExploitation]["longueur_fonction_split"]]
           l_NomTemporaire = l_NomTemporaire.replace(":" + str(g_ConfigSystemeExploitation[g_SystemeExploitation]["etats_connexion"][0]),"")
           l_NomTemporaire = l_NomTemporaire.replace(":" + str(g_ConfigSystemeExploitation[g_SystemeExploitation]["etats_connexion"][1]),"")
           l_InterfacesActives.append(l_NomTemporaire)
    
    # Si une seule interface est active, on la retourne
    if len(l_InterfacesActives) == 1:
       if g_Debogue: print("Une seule interface active.")
       return l_InterfacesActives[0]
    
    # Plusieurs interfaces actives: demander à l'utilisateur de choisir
    if len(l_InterfacesActives) > 1:
       if g_Debogue: print("Plusieurs interfaces actives.")
       
       # Afficher la liste des choix
       print("0. Quitter")
       for l_Idx, l_UneInterface in enumerate(l_InterfacesActives, 1):
           print(f"{l_Idx}. {l_UneInterface}")
       
       # Demander un choix valide
       while True:
             try:
                 # Demander de faire un choix
                 l_LeChoix = int(input("\nChoisissez une interface : ")) - 1
                 
                 # Vérifier si l'option Quitter a été choisie
                 if l_LeChoix == -1:
                    if g_Debogue: print("Option Quitter choisie")
                    return None
                 else:
                    if g_Debogue: print("Valeur sélectionnée: " + str(l_LeChoix))
                    
                    # Valider les bornes inférieure et supérieure
                    if l_LeChoix >= 0 and l_LeChoix < len(l_InterfacesActives):
                       # Le choix est valide, retourner l'interface choisie
                       return(l_InterfacesActives[l_LeChoix])
                    else:
                       print("Le choix doit être entre 0 (Quitter) et " + str(len(l_InterfacesActives)))
                   
             # Valeur erronée choisie
             except Exception as l_Erreur:
                 # Choix non numérique
                 print(f"Erreur détectée: {l_Erreur}")
                 print("Choix invalide. Réessayez.")
    
    if g_Debogue: print("Aucune interface trouvée ou sélectionnée")
    # Si rien n'a été trouvé
    return None


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === CONFIGURER LES VALEURS DNS POUR L'INTERFACE ACTIVE                                                                                     ===
# === Notes:                                                                                                                                 ===
# ===     1. la fonction utilise les valeurs de la variable globale g_DNSInterfaceActive                                                     ===
# ===     2. seuls les stacks IP actifs sont configurés, pour éviter les erreurs                                                             ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. L'interface réseau active/choisie                                                                                                ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ConfigurerDNS(p_InterfaceActive):
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    global g_DNSInterfaceActive
    global g_FichierSauvegardeDNS
    global g_VersionIP
    global g_VersionIP1
    global g_TypeDNS
    global g_StacksActifs
    
    if g_Debogue: print("f_ConfigurerDNS() : entrée dans la fonction")
    
    # Vérifier si le satck IPv4 est actif
    if g_StacksActifs["ipv4"]["statut"] == True:
       # Configurer les adresses IPv4
       l_Principale = True   # La première adresse configurée sera considérée l'adresse DNS principale
       for l_UnDNS in g_DNSInterfaceActive["ipv4"]:
           # S'il s'agit de l'adresse principale
           if l_Principale:
              l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["ecrire_dns_interface"].replace("{%NOM_INTERFACE%}", p_InterfaceActive).replace("{%VERSION_IP%}",g_VersionIP["ipv4"]).replace("{%VERSION_IP1%}",g_VersionIP1["ipv4"]).replace("{%STATIC%}","static").replace("{%TYPE_DNS%}",g_TypeDNS["principal"]).replace("{%AJOUT%}","")
              l_Principale = False
           # Sinon il s'agit d'une adresse secondaire
           else:
              l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["ecrire_dns_interface"].replace("{%NOM_INTERFACE%}", p_InterfaceActive)
              l_Commande = l_Commande.replace("{%VERSION_IP%}",g_VersionIP["ipv4"]).replace("{%STATIC%}","").replace("{%TYPE_DNS%}",g_TypeDNS["secondaire"]).replace("{%AJOUT%}","+").replace("{%VERSION_IP1%}",g_VersionIP1["ipv4"])
           
           l_Commande = l_Commande.replace("{%ADRESSE_IP%}",str(l_UnDNS))
           if g_Debogue: print("La commande à exécuter: '" + l_Commande + "'")
           
           # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
           l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
           if g_Debogue: print("Résultats: " + l_Resultat)
           if g_Debogue: print("Erreurs: " + l_Erreurs)
           
           if l_Erreurs != "":
              f_ErreurFatale("Impossible de configurer l'adresse DNS '" + str(l_UnDNS) + "' pour l'interface '" + p_InterfaceActive + "'")
    else:
        if g_Debogue: print("Le stack IPv4 est inactif")
    
    # Vérifier si le satck IPv6 est actif
    if g_StacksActifs["ipv6"]["statut"] == True:
       # Configurer les adresses IPv6
       l_Principale = True   # La première adresse configurée sera considérée l'adresse DNS principale
       for l_UnDNS in g_DNSInterfaceActive["ipv6"]:
           # S'il s'agit de l'adresse principale
           if l_Principale:
              l_Commande = ((g_ConfigSystemeExploitation[g_SystemeExploitation]["ecrire_dns_interface"].replace("{%NOM_INTERFACE%}", p_InterfaceActive)).replace("{%VERSION_IP%}",g_VersionIP["ipv6"]).replace("{%STATIC%}","static").replace("{%TYPE_DNS%}",g_TypeDNS["principal"])).replace("{%VERSION_IP1%}",g_VersionIP1["ipv6"]).replace("{%AJOUT%}","+")
              l_Principale = False
           # Sinon il s'agit d'une adresse secondaire
           else:
              l_Commande = ((g_ConfigSystemeExploitation[g_SystemeExploitation]["ecrire_dns_interface"].replace("{%NOM_INTERFACE%}", p_InterfaceActive)).replace("{%VERSION_IP%}",g_VersionIP["ipv6"]).replace("{%STATIC%}","").replace("{%TYPE_DNS%}",g_TypeDNS["secondaire"])).replace("{%VERSION_IP1%}",g_VersionIP1["ipv6"]).replace("{%AJOUT%}","")
           
           l_Commande = l_Commande.replace("{%ADRESSE_IP%}",str(l_UnDNS))
           if g_Debogue: print("La commande à exécuter: '" + l_Commande + "'")
           
           # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
           l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
           if g_Debogue: print("Résultats: " + l_Resultat)
           if g_Debogue: print("Erreurs: " + l_Erreurs)
           
           if l_Erreurs != "":
              f_ErreurFatale("Impossible de configurer l'adresse DNS '" + str(l_UnDNS) + "' pour l'interface '" + p_InterfaceActive + "'")
    else:
        if g_Debogue: print("Le stack IPv6 est inactif")
    
    if g_Debogue: print("f_ConfigurerDNS() : fonction terminée")
    return None


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === ACTIVER LES DNS DU DHCP POUR L'INTERFACE ACTIVE                                                                                        ===
# === Note:                                                                                                                                  ===
# ===     1. la fonction utilise les valeurs de la variable globale g_DNSInterfaceActive                                                     ===
# ===     2. la fonction agit uniquement sur les stacks IP actifs                                                                            ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. L'interface réseau active/choisie                                                                                                ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ActiverDNSDHCP(p_InterfaceActive):
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    global g_DNSInterfaceActive
    global g_FichierSauvegardeDNS
    global g_VersionIP
    global g_VersionIP1
    global g_StacksActifs
    
    if g_Debogue: print("f_ActiverDNSDHCP() : entrée dans la fonction")
    
    # Vérifier si le stack IPv4 est actif
    if g_StacksActifs["ipv4"]["statut"] == True:
       # Construire la commande d'activation du DHCP pour IPv4
       l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["activer_dhcp"].replace("{%NOM_INTERFACE%}", p_InterfaceActive).replace("{%VERSION_IP%}",g_VersionIP["ipv4"]).replace("{%VERSION_IP1%}",g_VersionIP1["ipv4"])
       if g_Debogue: print("La commande à exécuter: '" + l_Commande + "'")
       
       # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
       l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
       if g_Debogue: print("Résultats: " + l_Resultat)
       if g_Debogue: print("Erreurs: " + l_Erreurs)
       
       if l_Erreurs != "":
          f_ErreurFatale("Impossible de configurer le DNS dynamique IPv4 pour l'interface '" + p_InterfaceActive + "'")
    else:
        if g_Debogue: print("f_ActiverDNSDHCP() : le stack IPv4 est inactif")
    
    # Vérifier si le stack IPv6 est actif
    if g_StacksActifs["ipv6"]["statut"] == True:
       # Construire la commande d'activation du DHCP pour IPv6
       l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["activer_dhcp"].replace("{%NOM_INTERFACE%}", p_InterfaceActive).replace("{%VERSION_IP%}",g_VersionIP["ipv6"]).replace("{%VERSION_IP1%}",g_VersionIP1["ipv6"])
       if g_Debogue: print("La commande à exécuter: '" + l_Commande + "'")
       
       # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
       l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
       if g_Debogue: print("Résultats: " + l_Resultat)
       if g_Debogue: print("Erreurs: " + l_Erreurs)
       
       if l_Erreurs != "":
          f_ErreurFatale("Impossible de configurer le DNS dynamique IPv6 pour l'interface '" + p_InterfaceActive + "'")
    else:
        if g_Debogue: print("f_ActiverDNSDHCP() : le stack IPv6 est inactif")
    
    if g_Debogue: print("f_ActiverDNSDHCP() : fonction terminée")


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === EXTRAIRE LES DNS DU TEXTE OBTENU LORS DE L'AFFICHAGE DES VALEURS DNS DE L'INTERFACE ACTIVE                                             ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. Le texte à analyser                                                                                                              ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    La liste des adresses IP obtenues                                                                                                   ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ExtraireDNS(p_Texte):
    global g_IPv4Pattern
    global g_IPv6Pattern
    
    # Procéder à l'analyse du texte
    l_IPv4Adresses = re.findall(g_IPv4Pattern, p_Texte)
    l_IPv6Adresses = re.findall(g_IPv6Pattern, p_Texte)
    
    return {
        "ipv4": l_IPv4Adresses,
        "ipv6": l_IPv6Adresses
    }


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === AFFICHER OU ENREGISTRER LES VALEURS DNS DE L'INTERFACE RÉSEAU ACTIVE                                                                   ===
# === Notes: La fonction obtient, affiche ou enregistre les adresses coonfigurées même si le stack IP est inactif.                           ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. L'interface réseau active/choisie                                                                                                ===
# ===    2. Obtenir (O), afficher (A) ou sauvegarder (S) les informations                                                                    ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ListerEnregistrerDNS(p_InterfaceActive, p_Action):
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    global g_DNSInterfaceActive
    global g_FichierSauvegardeDNS
    global g_VersionIP
    global g_VersionIP1
    
    if g_Debogue: print("f_ListerSauvegarderDNS() : entrée dans la fonction")
    
    # Obtenir les adresses IPv4
    l_CommandeIPv4 = (g_ConfigSystemeExploitation[g_SystemeExploitation]["lire_dns_interface"].replace("{%NOM_INTERFACE%}", p_InterfaceActive)).replace("{%VERSION_IP%}",g_VersionIP["ipv4"]).replace("{%VERSION_IP1%}",g_VersionIP1["ipv4"])
    if g_Debogue: print("La commande à exécuter: '" + l_CommandeIPv4 + "'")
    
    # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
    l_ResultatIPv4, l_ErreursIPv4 = f_ExecuterCommande(l_CommandeIPv4, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
    if g_Debogue: print("Résultats: " + l_ResultatIPv4)
    if g_Debogue: print("Erreurs: " + l_ErreursIPv4)
    
    # Obtenir les adresses IPv6
    l_CommandeIPv6 = (g_ConfigSystemeExploitation[g_SystemeExploitation]["lire_dns_interface"].replace("{%NOM_INTERFACE%}", p_InterfaceActive)).replace("{%VERSION_IP%}",g_VersionIP["ipv6"]).replace("{%VERSION_IP1%}",g_VersionIP1["ipv6"])
    if g_Debogue: print("La commande à exécuter: '" + l_CommandeIPv6 + "'")
    
    # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
    l_ResultatIPv6, l_ErreursIPv6 = f_ExecuterCommande(l_CommandeIPv6, g_ConfigSystemeExploitation[g_SystemeExploitation]["encodage"])
    if g_Debogue: print("Résultats: " + l_ResultatIPv6)
    if g_Debogue: print("Erreurs: " + l_ErreursIPv6)
    
    if l_ErreursIPv4 == "" and l_ErreursIPv6 == "":
       # Obtenir la liste des adresses IPv4
       l_DNSInterfaceActiveIPv4 = f_ExtraireDNS(l_ResultatIPv4)
       
       # Obtenir la liste des adresses IPv6
       l_DNSInterfaceActiveIPv6 = f_ExtraireDNS(l_ResultatIPv6)
       
       # Fusionner les deux listes si elles sont différentes
       if l_DNSInterfaceActiveIPv4["ipv4"] != l_DNSInterfaceActiveIPv6["ipv4"] or l_DNSInterfaceActiveIPv4["ipv6"] != l_DNSInterfaceActiveIPv6["ipv6"]:
          g_DNSInterfaceActive = { "ipv4": l_DNSInterfaceActiveIPv4["ipv4"], "ipv6": l_DNSInterfaceActiveIPv6["ipv6"] }
       else:
          g_DNSInterfaceActive = { "ipv4": l_DNSInterfaceActiveIPv4["ipv4"], "ipv6": l_DNSInterfaceActiveIPv4["ipv6"] }
       
       # Agir selon l'action désirée
       match p_Action:
          case "S":
               # Enregistrer les informations dans un fichier
               
               # Le fichier de sauvegarde doit se faire par interface réseau, pour éviter de restorer des valeurs DNS erronée pour une autre interface.
               # Pour éviter des erreurs, le système d'exploitation est aussi spécifé.
               # Construire le nom du fichier de sauvegarde
               l_NomFichierSauvegarde = (g_SystemeExploitation.lower() + "_" + p_InterfaceActive.replace(" ","")).lower() + "_" + g_FichierSauvegardeDNS
               if g_Debogue: print("Le fichier de sauvegarde de cette configuration DNS est '" + l_NomFichierSauvegarde + "'")
               
               # Préparer les informations de sauvegarde.
               l_DonneesSauvegarde = {
                    "interface": p_InterfaceActive,
                    "ipv4": g_DNSInterfaceActive["ipv4"],
                    "ipv6": g_DNSInterfaceActive["ipv6"],
                    "os": g_SystemeExploitation
                    }
               
               # Effectuer la sauvegarde
               with open(l_NomFichierSauvegarde, "w", encoding="utf-8") as f:
                    json.dump(l_DonneesSauvegarde, f, indent=4)
          
          case "A":
               # Afficher les informations à la console
               
               # Afficher les adresses IPv4 s'il y en a
               if len(g_DNSInterfaceActive["ipv4"]) != 0:
                  # Afficher un message si le stack IPv4 est inactif
                  if g_StacksActifs["ipv4"]["statut"] == False:
                     print("Notez que des adresses IPv4 sont configurées pour un stack IP inactif")
                  print("Pour '" + p_InterfaceActive + "', les adresses IPv4 sont: ", end="")
                  for l_IPv4 in g_DNSInterfaceActive["ipv4"]:
                      print(l_IPv4 + "   ", end="")
                  print("")
               else:
                  print("Pour '" + p_InterfaceActive + "', il n'y a aucune adresse IPv4.")
               
               # Afficher les adresses IPv6 s'il y en a
               if len(g_DNSInterfaceActive["ipv6"]) != 0:
                  # Afficher un message si le stack IPv6 est inactif
                  if g_StacksActifs["ipv6"]["statut"] == False:
                     print("Notez que des adresses IPv6 sont configurées pour un stack IP inactif")
                  print("Pour '" + p_InterfaceActive + "', les adresses IPv6 sont: ", end="")
                  for l_IPv6 in g_DNSInterfaceActive["ipv6"]:
                      print(l_IPv6 + "   ", end="")
                  print("")
               else:
                  print("Pour '" + p_InterfaceActive + "', il n'y a aucune adresse IPv6.")
          
          case "O":
               if g_Debogue: print("Obtenir les adresses DNS uniquement")
          
          case _:
               f_ErreurFatale("f_ListerSauvegarderDNS() : action inconnue")
    else:
        f_ErreurFatale("Impossible d'obtenir les adresses DNS pour l'interface '" + p_InterfaceActive + "'")
    
    if g_Debogue: print("f_ListerSauvegarderDNS() : sortie de la fonction")


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === SUPPRIMER L'ENREGISTREMENT DES VALEURS DNS D'UNE L'INTERFACE RÉSEAU ACTIVE                                                             ===
# ===                                                                                                                                        ===
# === Note: si le fichier de sauvegarde n'existe pas, aucune suppression n'est effectuée et aucun message d'erreur n'est retourné.           ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. L'interface réseau active/choisie                                                                                                ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_SupprimerEnregistrementDNS(p_InterfaceActive):
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    global g_FichierSauvegardeDNS
    
    if g_Debogue: print("f_SupprimerEnregistrementDNS() : entrée dans la fonction")
    
    # Construire le nom du fichier de sauvegarde
    l_NomFichierSauvegarde = (g_SystemeExploitation + "_" + p_InterfaceActive.replace(" ","")).lower() + "_" + g_FichierSauvegardeDNS
    if g_Debogue: print("Le fichier de sauvegarde de cette configuration DNS est '" + l_NomFichierSauvegarde + "'")
    
    # Vérifier si le fichier existe
    if os.path.exists(l_NomFichierSauvegarde):
       # Si le fichier existe, le supprimer.  Sinon, rien à faire puisque le fichier n'existe pas
       try:
            os.remove(l_NomFichierSauvegarde)
            if g_Debogue: print(f"Fichier supprimé : {l_NomFichierSauvegarde}")
       # Erreur de suppression
       except Exception as l_Erreur:
            if g_Debogue: print(f"Erreur suppression de '{l_NomFichierSauvegarde}' : {l_Erreur}")
    else:
       if g_Debogue: print(f"Le fichier '{l_NomFichierSauvegarde}' n'existe pas.")
    
    if g_Debogue: print("f_SupprimerEnregistrementDNS() : sortie de la fonction")


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === RÉCUPÉRER LES VALEURS DNS ENREGISTRÉES POUR L'INTERFACE RÉSEAU ACTIVE                                                                  ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. L'interface réseau active/choisie                                                                                                ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Les informations du fichier de sauvegarde                                                                                           ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_RecupererEnregistrementDNS(p_InterfaceActive):
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    global g_FichierSauvegardeDNS
    
    if g_Debogue: print("f_RecupererEnregistrementDNS() : entrée dans la fonction")
    
    # Construire le nom du fichier de sauvegarde
    l_NomFichierSauvegarde = (g_SystemeExploitation + "_" + p_InterfaceActive.replace(" ","")).lower() + "_" + g_FichierSauvegardeDNS
    if g_Debogue: print("Le fichier de sauvegarde de cette configuration DNS est '" + l_NomFichierSauvegarde + "'")
    
    # Vérifier si le fichier existe
    if os.path.exists(l_NomFichierSauvegarde):
       try:
           # Ouvrir le fichier
           with open(l_NomFichierSauvegarde, "r", encoding="utf-8") as l_ContenuFichierSauvegarde:
                # Lire le contenu du fichier de sauvegarde
                l_DonneesSauvegarde = json.load(l_ContenuFichierSauvegarde)
       # Erreur de lecture du fichier
       except Exception as l_Erreur:
             f_ErreurFatale(f"Erreur lecture du fichier : {l_Erreur}")
       
       # Valider les informations récupérée
       # Premièrement, des données ont-elle été récupérées?
       if len(l_DonneesSauvegarde) == 0:
          f_ErreurFatale("Aucune donnée récupérée pour l'interface '" + p_InterfaceActive + "'")
       else:
          if g_Debogue: print("Les données lues sont pour l'interface '" + l_DonneesSauvegarde["interface"] + "' sur un système '" + l_DonneesSauvegarde["os"] + "'")
          
          # Est-ce la bonne interface
          if l_DonneesSauvegarde["interface"] != p_InterfaceActive:
             f_ErreurFatale("Les informations récupérées sont pour l'interface '" + l_DonneesSauvegarde["interface"] + "'")
          
          if l_DonneesSauvegarde["os"] != g_SystemeExploitation:
             f_ErreurFatale("Les informations récupérées sont pour le système d'exploitation '" + l_DonneesSauvegarde["os"] + "'")
          
          return l_DonneesSauvegarde
    else:
       f_ErreurFatale("Aucune configuration sauvegardée pour l'interface '" + p_InterfaceActive + "'")
    
    if g_Debogue: print("f_RecupererEnregistrementDNS() : sortie de la fonction")


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === CHOISIR LA CONFIGURATION DNS À IMPORTER                                                                                                ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. Les informations obtenue du fichier XML                                                                                          ===
# ===    2. Vrai: le choix des DNS de tests est affiché.  Faux: le choix n'est pas affiché.                                                  ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    COnfiguration du fournisseur choisi.  None est retourné si aucun choix.                                                         ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_ChoisirFournisseurDNS(p_FournisseursDNS, p_AfficherTest):
    if g_Debogue: print("f_ChoisirFournisseurDNS() : entrée dans la fonction")
    
    print("0: Quitter")
    
    # Contient les adresses DNS des fournisseurs parmi lesquels choisir.
    l_AdressesDisponibles = []
    
    # Contient le choix
    l_AdressesChoisies = {}
    
    # Numéro de choix
    l_Idx = 1
    
    for l_FournisseurDNS in p_FournisseursDNS:
        if l_FournisseurDNS["test"] and not p_AfficherTest:
           continue
        print(f"{l_Idx}. {l_FournisseurDNS['nom']}")
        
        # Enregistrer dans la liste les adresses du fournisseur
        l_AdressesDisponibles.append(l_FournisseurDNS)
        
        # Incrémenter le numéro de choix
        l_Idx += 1
    
    # Demander de choisir
    l_ChoixFournisseurDNS = int(input("\nChoisir le fournisseur DNS : ")) - 1
    
    # L'utilisateur a-t-il choisi de quitter ou un choix de fournisseur
    if l_ChoixFournisseurDNS != -1:
       if g_Debogue: print("f_ChoisirFournisseurDNS() : choix : " + str(l_ChoixFournisseurDNS + 1))
       l_AdressesChoisies = l_AdressesDisponibles[l_ChoixFournisseurDNS]
    else:
        if g_Debogue: print("f_ChoisirFournisseurDNS() : Vous avez choisi de quitter")
        l_AdressesChoisies = {"nom": ""}
    
    if g_Debogue: print("f_ChoisirFournisseurDNS() : sortie de la fonction")
    
    return l_AdressesChoisies


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === VÉRIFIER SI LES DNS DE L'INTERFACE RÉSEAU SONT FONCTIONNELS                                                                            ===
# === Notes: seules les stacks IP actifs sont vérifiés.                                                                                      ===
# ===                                                                                                                                        ===
# === Paramètres:                                                                                                                            ===
# ===    1. L'interface réseau active/choisie                                                                                                ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_VerifierDNS(p_InterfaceActive):
    global g_Debogue
    global g_SystemeExploitation
    global g_ConfigSystemeExploitation
    global g_DNSInterfaceActive
    global g_DNSTest
    global g_StacksActifs
    
    if g_Debogue: print("f_VerifierDNS() : entrée dans la fonction")
    
    # Obtenir les adresses DNS de l'interface
    f_ListerEnregistrerDNS(p_InterfaceActive, "O")
    
    # Vérifier si le stack IPv4 est actif
    if g_StacksActifs["ipv4"]["statut"] == True:
       # Construire la commande de vérification
       l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["verifier_dns"].replace("{%DNSTest%}", g_DNSTest).replace("{%STACK_IP%}",g_StacksActifs["ipv4"]["stack"])
       if g_Debogue: print("La commande à exécuter: '" + l_Commande + "'")
       
       # Valider les adresses pour la version IPv4
       if len(g_DNSInterfaceActive["ipv4"]) != 0:
          print("Exécuter la vérification DNS IPv4")
          for l_IPv4 in g_DNSInterfaceActive["ipv4"]:
              l_Commande = l_Commande.replace("{%ServeurDNS%}", l_IPv4)
              
              # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
              print("   - " + str(l_IPv4) + ": ",end="")
              l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, locale.getpreferredencoding())
              if g_Debogue: print("Résultats: " + l_Resultat)
              if g_Debogue: print("Erreurs: " + l_Erreurs)
              
              # Vérifier les résultats
              if "status: noerror" in l_Resultat.lower():
                 print("OK")
              else:
                 print("NOK")
       else:
          if g_Debogue: print("f_VerifierDNS() : aucune adresse DNS configurée pour IPv4")
    else:
       if g_Debogue: print("f_VerifierDNS() : le stack IPv4 est inactif")
    
    # Vérifier si le stack IPv4 est actif
    if g_StacksActifs["ipv6"]["statut"] == True:
       # Réinitialiser la commande de vérification
       l_Commande = g_ConfigSystemeExploitation[g_SystemeExploitation]["verifier_dns"].replace("{%DNSTest%}", g_DNSTest).replace("{%STACK_IP%}",g_StacksActifs["ipv6"]["stack"])
       if g_Debogue: print("La commande à exécuter: '" + l_Commande + "'")
       
       # Valider les adresses pour la version IPv6
       if len(g_DNSInterfaceActive["ipv6"]) != 0:
          print("Exécuter la vérification DNS IPv6")
          for l_IPv6 in g_DNSInterfaceActive["ipv6"]:
              l_Commande = l_Commande.replace("{%ServeurDNS%}", l_IPv6)
              
              # Procéder à l'exécution de la commande et capturer les résultats (sortie et erreurs)
              print("   - " + str(l_IPv6) + ": ",end="")
              l_Resultat, l_Erreurs = f_ExecuterCommande(l_Commande, locale.getpreferredencoding())
              if g_Debogue: print("Résultats: " + l_Resultat)
              if g_Debogue: print("Erreurs: " + l_Erreurs)
              
              # Vérifier les résultats
              if "status: noerror" in l_Resultat.lower():
                 print("OK")
              else:
                 print("NOK")
       else:
          if g_Debogue: print("f_VerifierDNS() : aucune adresse DNS configurée pour IPv6")
    else:
       if g_Debogue: print("f_VerifierDNS() : le stack IPv6 est inactif")
     
    if g_Debogue: print("f_VerifierDNS() : sortie de la fonction")


# ==============================================================================================================================================
# ===                                                                                                                                        ===
# === FONCTION PRINCIPALE                                                                                                                    ===
# ===                                                                                                                                        ===
# === Notez les conventions suivantes:                                                                                                       ===
# ===    1. les variables ayant une portée locale débutent par l_                                                                            ===
# ===    2. les paramètres reçus dans les fonctions débutent par p_                                                                          ===
# ===    3. les paramètres ayant une portée globale débutent par g_                                                                          ===
# ===    4. les constantes débutent par k_                                                                                                   ===
# ===    5. les fonctions débutent par f_                                                                                                    ===
# ===                                                                                                                                        ===
# === Algorithme:                                                                                                                            ===
# ===    1. Obtenir les paramètres d'exécution                                                                                               ===
# ===    2. Valider si le script est dans le bon environnement (Système d'exploitation)                                                      ===
# ===    3. Lancer les actions qui n'utilise pas une interface (par exemple, l'affichage de l'aide)                                          ===
# ===    4. Exécuter les actions qui s'applique sur une interface réseau:                                                                    ===
# ===                                                                                                                                        ===
# === Valeur retournée:                                                                                                                      ===
# ===    Aucune                                                                                                                              ===
# ===                                                                                                                                        ===
# ==============================================================================================================================================
def f_Principale():
    # Spécifier les variables globales à utiliser
    global g_Debogue
    global g_FichierXMLDefaut
    global g_SystemeExploitation
    global g_DNSInterfaceActive
    
    # Préparer la récupération des paramètres d'exécution
    l_Parser = argparse.ArgumentParser(description="Utilitaire Flip DNS")
    
    # Ajouter les paramètres standards
    l_Parser.add_argument("-?", "--aider", action="store_true", help="Afficher l'aide")
    l_Parser.add_argument("-d", "--deboguer", action="store_true", help="Mode débogage") 
    l_Parser.add_argument("-f", "--fichier", default=g_FichierXMLDefaut, help="Sélection des configurations DNS")
    l_Parser.add_argument("-t", "--tester", action="store_true", help="Ajouter l'option de configurer un DNS de test (avec adresses IP invalides)")
    l_Parser.add_argument("-v", "--verifier", action="store_true", help="Vérifier si le DNS fonctionne")
    
    # Ajouter les paramètres s'excluant mutuellement
    l_GroupeParams = l_Parser.add_mutually_exclusive_group()
    l_GroupeParams.add_argument("-l", "--lister", action="store_true", help="Afficher les DNS de l'interface réseau active")
    l_GroupeParams.add_argument("-e", "--enregistrer", action="store_true", help="Sauvegarder les DNS pour l'interface réseau active")
    l_GroupeParams.add_argument("-r", "--recuperer", action="store_true", help="Restaurer les DNS de l'interface réseau active")
    l_GroupeParams.add_argument("-s", "--supprimer", action="store_true", help="Supprimer les valeurs DNS enregistrées")
    l_GroupeParams.add_argument("-x", "--dynamique", action="store_true", help="Reconfigurer l'interface pour utiliser les configurations DNS du DHCP")
    
    # Récupérer les paramètres spécifiés sur la ligne de commande 
    try:
        l_Args = l_Parser.parse_args()
    # Erreur avec les paramètres
    except SystemExit as l_Erreur:
           print(f"Erreur avec les paramètres de la commande : {l_Erreur}")
           f_AfficherAide()
           f_ErreurFatale("")
    
    # La valeur de débogage doit être accessible à toutes les fonctions du script.  Donc elle doit être une variable globale.
    if l_Args.deboguer: g_Debogue = True
    
    # Afficher les paramètres de la ligne de commande
    print("Voici les paramètres reçus:")
    print("   - Afficher l'aide") if l_Args.aider else print("   - Ne pas afficher l'aide")
    print("   - Lister les valeurs DNS") if l_Args.lister else print("   - Ne pas lister les valeurs DNS")
    print("   - Ajouter le DNS de test dans les choix") if l_Args.tester else print("   - Ne pas ajouter le DNS de test dans les choix")
    print("   - Enregistrer les valeurs DNS") if l_Args.enregistrer else print("   - Ne pas enregistrer les valeurs DNS")
    print("   - Récupérer les valeurs DNS") if l_Args.recuperer else print("   - Ne pas récupérer les valeurs DNS")
    print("   - Supprimer les valeurs DNS enregistrées") if l_Args.verifier else print("   - Ne pas supprimer les valeurs DNS enregistrées")
    print("   - Forcer l'utilisation des DNS du DHCP") if l_Args.dynamique else print("   - Ne pas forcer l'utilisation des DNS du DHCP")
    print("   - Utiliser le fichier XML " + l_Args.fichier)
    
    # Déterminer le système d'exploitation et si le script peut s'exécuter sur ce système
    if f_QuelSystemeExploitation():
       if l_Args.deboguer: print("Le script s'exécute dans l'environnement " + g_SystemeExploitation)
       
       # Agir selon les paramètres spécifiés
       # Traiter les paramètres qui apparaissent seuls sur la ligne de commande (exécuter l'action et quitter le script)  
       if l_Args.aider:
          if l_Args.aider: f_AfficherAide()   # Afficher l'aide
       else:
          # Python change parfois son environnement d'exécution pour se positionner sur un autre dossier dans le système.
          # Forcer le script à se positionner au même endroit que le script
          os.chdir(os.path.dirname(os.path.abspath(__file__)))
          if g_Debogue: print("Dossier d'exécution du script : '" + os.getcwd() + "'")   # Afficher le dossier courant
          
          # Le script agit sur les DNS d'une interface réseau active.  Sélectionner l'interface réseau.
          l_InterfaceActive = f_ObtenirInterfaceActive()
          
          # Si une interface active a été détectée ou choisie par l'utilisateur
          if l_InterfaceActive is not None:
             print(f"Interface choisie : {l_InterfaceActive}")
             
             # Identifier les stacks IP actifs
             if g_Debogue: print("Identifier les stacks IP disponibles")
             f_VerifierStacksIP()
             
             # Afficher les valeurs du DNS pour l'interface active
             if l_Args.lister:
                print("Débogage: Afficher les valeurs DNS pour l'interface active")
                f_ListerEnregistrerDNS(l_InterfaceActive, "A")
             
             # Enregistrer les valeurs du DNS pour l'interface active
             if l_Args.enregistrer:
                print("Débogage: Enregistrer les valeurs DNS pour l'interface active")
                f_ListerEnregistrerDNS(l_InterfaceActive, "S")
             
             # Supprimer les valeurs du DNS enregistrées pour l'interface active
             if l_Args.supprimer:
                print("Débogage: Supprimer l'enregistrement des valeurs DNS pour l'interface active")
                f_SupprimerEnregistrementDNS(l_InterfaceActive)
             
             # Récupérer les valeurs du DNS pour l'interface active
             if l_Args.recuperer:
                print("Débogage: Récupérer les valeurs DNS pour l'interface active")
                l_DNSSauvegardes = f_RecupererEnregistrementDNS(l_InterfaceActive)
                
                # Effectuer la configuration DNS
                g_DNSInterfaceActive = { "ipv4": l_DNSSauvegardes["ipv4"], "ipv6": l_DNSSauvegardes["ipv6"] }
                f_ConfigurerDNS(l_InterfaceActive)
             
             # Forcer l'utilisation des DNS du DHCP pour l'interface active
             if l_Args.dynamique:
                print("Débogage: Forcer l'utilisation des DNS du DHCP pour l'interface active")
                f_ActiverDNSDHCP(l_InterfaceActive)
             
             # Si aucune des options précédentes n'a été spécifiée, le script agit par défaut, soit la modification des adresses DNS de l'interface réseau active
             if not l_Args.lister and not l_Args.enregistrer and not l_Args.supprimer and not l_Args.recuperer and not l_Args.dynamique:
                # Vérifier que le fichier XML existe.  Si le fichier n'existe pas, le script ne peut se poursuivre.
                if os.path.exists(l_Args.fichier):
                   
                   # Le fichier XML existe.  Le lire pour charger les configurations des DNS.
                   if g_Debogue: print("Fichier XML à utiliser : '" + l_Args.fichier + "'")   # Afficher le dossier courant
                   l_FournisseursDNS = f_ChargerConfigDNS(l_Args.fichier)
                   
                   # Vérifier si des informations ont été chargées
                   if len(l_FournisseursDNS) != 0:
                      print("Débogage: Modifier les valeurs DNS pour l'interface active")
                      l_DNSChoisis = f_ChoisirFournisseurDNS(l_FournisseursDNS, l_Args.tester)
                      
                      # Si le nom est vide, c'est que Quitter a été choisi
                      if l_DNSChoisis["nom"] != "":
                         if g_Debogue: print("Configurer le DNS avec le valeur du fournisseur: " + l_DNSChoisis["nom"])
                         
                         # Effectuer la configuration DNS
                         g_DNSInterfaceActive = { "ipv4": l_DNSChoisis["ipv4"], "ipv6": l_DNSChoisis["ipv6"] }
                         f_ConfigurerDNS(l_InterfaceActive)
                      else:
                         if g_Debogue: print("Vous avez choisi de quitter")
                      #
                      #set_dns(l_InterfaceActive, selected["ipv4"], selected["ipv6"])
                   else:
                      # Erreur: Aucune information chargée
                      f_ErreurFatale("Le fichier XML ne contient aucune information pertinente")
                else:
                   # Erreur: le fichier XML est introuvable
                   f_ErreurFatale("Le fichier XML est introuvable")
             
             # Valider les  DNS pour l'interface active
             if l_Args.verifier:
                print("Débogage: Vérifier les DNS pour l'interface active")
                f_VerifierDNS(l_InterfaceActive)
          else:
             # Erreur: aucune interface disponible ou choisie
             f_ErreurFatale("Aucune interface réseau disponible ou choisie")
    else:
        f_ErreurFatale("Ce système d'exploitation (" + g_SystemeExploitation + ") n'est pas supporté!")

# J'ai pris ceci sur le web mais je ne comprends pas.
# Expliquer ce if
if __name__ == "__main__":
   f_Principale()
   
   # Pour empêcher la fenêtre Python de se fermer avant de lire les affichages, on demande à l'utilisateur de peser sur la touche ENTRÉE
   input("SCRIPT COMPLÉTÉ : APPUYER SUR LA TOUCHE ENTRÉE POUR CONTINUER !")
