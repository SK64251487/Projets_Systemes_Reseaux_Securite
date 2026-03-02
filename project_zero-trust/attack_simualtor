#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script d'exfiltration pour tester le controleur Zero Trust
Envoie simplement des paquets UDP sans besoin de serveur
"""

import socket
import time
import sys

def exfiltrer(ip_destination, nombre_paquets=2000, taille_paquet=1000):
    """
    Envoie beaucoup de paquets UDP rapidement pour declencher la detection
    
    Args:
        ip_destination: IP de destination (ex: 10.0.0.2)
        nombre_paquets: Nombre de paquets a envoyer (défaut: 2000)
        taille_paquet: Taille de chaque paquet en octets (defaut: 1000)
    """
    
    print("=" * 60)
    print("  EXFILTRATION DE DONNEES - TEST SIMPLE")
    print("=" * 60)
    print(f"Destination    : {ip_destination}")
    print(f"Paquets        : {nombre_paquets}")
    print(f"Taille/paquet  : {taille_paquet} octets")
    print(f"Total          : {nombre_paquets * taille_paquet:,} octets ({nombre_paquets * taille_paquet / 1024 / 1024:.2f} MB)")
    print(f"Seuil detection: 1,000,000 octets en 10 secondes")
    print("=" * 60)
    print()
    
    # Créer le socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Données a envoyer (juste des 'X')
    donnees = b'X' * taille_paquet
     
    port = 9999  # Port quelconque
    
    octets_envoyes = 0
    debut = time.time()
    
    print(f"[*] Debut de l'exfiltration vers {ip_destination}:{port}")
    print(f"[*] Envoi de {nombre_paquets} paquets...")
    print()
    
    try:
        for i in range(nombre_paquets):
            # Envoyer le paquet UDP
            sock.sendto(donnees, (ip_destination, port))
            octets_envoyes += taille_paquet
            
            # Afficher la progression tous les 200 paquets
            if (i + 1) % 200 == 0:
                temps_ecoule = time.time() - debut
                debit = octets_envoyes / temps_ecoule if temps_ecoule > 0 else 0
                pourcentage = ((i + 1) / nombre_paquets) * 100
                
                print(f"[{i+1:4d}/{nombre_paquets}] "
                      f"{pourcentage:5.1f}% | "
                      f"{octets_envoyes:,} octets | "
                      f"{debit:,.0f} o/s | "
                      f"{temps_ecoule:.2f}s")
                
                # Vérifier si le seuil est dépassé
                if octets_envoyes > 1000000 and i < nombre_paquets - 1:
                    print()
                    print("SEUIL DEPASSE ! Le controleur devrait detecter maintenant...")
                    print()
            
            # Petit délai pour ne pas saturer (optionnel)
            # time.sleep(0.001)
    
    except Exception as e:
        print(f"\n[!] Erreur: {e}")
        print("[!] Connexion probablement bloquee par le controleur!")
    
    finally:
        temps_total = time.time() - debut
        debit_moyen = octets_envoyes / temps_total if temps_total > 0 else 0
        
        print()
        print("=" * 60)
        print("  RESUME")
        print("=" * 60)
        print(f"Octets envoyes : {octets_envoyes:,} ({octets_envoyes/1024/1024:.2f} MB)")
        print(f"Temps total    : {temps_total:.2f} secondes")
        print(f"Debit moyen    : {debit_moyen:,.0f} octets/seconde")
        print()
        
        if octets_envoyes > 1000000:
            print("SEUIL DEPASSE - Le controleur DOIT avoir detecte!")
            print("   Verifiez les logs du controleur pour:")
            print("   - 'DATA EXFILTRATION DETECTED'")
            print("   - 'ACCESS REVOKED'")
        else:
            print("  Seuil non atteint - Augmentez nombre_paquets")
        
        print("=" * 60)
        
        sock.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 exfil_simple.py <IP_DESTINATION> [nombre_paquets] [taille_paquet]")
        print()
        print("Exemples:")
        print("  python3 exfil_simple.py 10.0.0.2")
        print("  python3 exfil_simple.py 10.0.0.2 3000")
        print("  python3 exfil_simple.py 10.0.0.2 2000 1000")
        print()
        print("Dans Mininet:")
        print("  mininet> h1 python3 exfil_simple.py 10.0.0.2")
        print("  mininet> h1 python3 exfil_simple.py 10.0.0.10")
        sys.exit(1)
    
    ip = sys.argv[1]
    nb_paquets = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    taille = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    
    exfiltrer(ip, nb_paquets, taille)
