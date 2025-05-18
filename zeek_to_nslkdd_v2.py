#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ce script convertit les fichiers de logs Zeek en format compatible avec le dataset NSL-KDD
pour entraîner un système de détection d'intrusion (IDS) intelligent.
"""

import os
import gzip
import json
import csv
import re
import time
import ipaddress
from datetime import datetime
from collections import defaultdict

class ZeekToNSLKDD:
    def __init__(self, zeek_logs_dir, output_file="nslkdd_format.csv", real_time=False, es_integration=False):
        """
        Initialise le convertisseur Zeek vers NSL-KDD avec des options supplémentaires.

        Args:
            zeek_logs_dir (str): Chemin vers le répertoire contenant les logs Zeek
            output_file (str): Nom du fichier de sortie au format NSL-KDD
            real_time (bool): Si True, surveille les logs en temps réel
            es_integration (bool): Si True, intègre les données dans ElasticSearch
        """
        self.zeek_logs_dir = zeek_logs_dir
        self.output_file = output_file
        self.real_time = real_time
        self.es_integration = es_integration
        self.real_time_logs_dir = "/opt/zeek/spool/zeek"  # Répertoire des logs en temps réel

        # Configuration ElasticSearch
        self.es_config = {
            "url": "https://elasticsearch.service:9200",
            "api_key": "ZUdDc1VKUUJXUEhKR0N5eXF1Rng6c1NTOU4xN29SZXFWMHA4eDhRWnNjdw==",
            "index": "zeek-ids-analytics",
            "batch_size": 1000  # Nombre max de documents à envoyer en un seul appel bulk
        }

        # Dictionnaire pour stocker les données extraites des différents logs
        self.connections = {}
        
        # Mappage des services Zeek vers les services NSL-KDD
        self.service_mapping = {
            'dns': 'domain',
            'http': 'http',
            'https': 'http_443',
            'ssh': 'ssh',
            'ftp': 'ftp',
            'ftp-data': 'ftp_data',
            'smtp': 'smtp',
            'pop3': 'pop_3',
            'imap': 'imap4',
            'telnet': 'telnet',
            'nntp': 'nntp',
            'irc': 'IRC',
            'whois': 'whois',
            'ssl': 'private',  # Approximation
            'dhcp': 'other',
            'ntp': 'ntp_u',
            'ldap': 'ldap',
            'finger': 'finger',
            # Compléter avec d'autres mappages selon besoin
            # Par défaut, 'other' sera utilisé
        }
        
        # Mappage des flags de connexion TCP entre Zeek et NSL-KDD
        self.flag_mapping = {
            'S0': 'S0',       # Connection attempt seen, no reply
            'SF': 'SF',       # Normal establishment and termination
            'REJ': 'REJ',     # Connection attempt rejected
            'S1': 'S1',       # Connection established, not terminated
            'S2': 'S2',       # Connection established and close attempt by originator seen
            'S3': 'S3',       # Connection established and close attempt by responder seen
            'RSTO': 'RSTO',   # Connection established, originator aborted
            'RSTR': 'RSTR',   # Established, responder aborted
            'RSTOS0': 'RSTOS0', # Originator sent a SYN followed by a RST
            'SH': 'SH',       # Originator sent a SYN followed by a FIN
            'OTH': 'OTH',     # No SYN, not closed
        }
        
        # Attributs NSL-KDD que nous allons remplir
        self.nslkdd_attributes = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
            'wrong_fragment', 'hot', 'logged_in', 'num_compromised', 'count', 
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate'
        ]

    def is_new_file(self, file_path):
        """Vérifie si un fichier n'a pas encore été traité"""
        return file_path not in self.processed_files

    def mark_file_as_processed(self, file_path):
        """Marque un fichier comme déjà traité"""
        self.processed_files.add(file_path)

    def extract_connection_data(self, real_time=False):
        """
        Extrait les données de connexion pertinentes à partir des fichiers de logs Zeek.

        Args:
            real_time (bool): Si True, ne traite que les nouveaux fichiers depuis le dernier traitement
            
        Returns:
            int: Nombre de nouvelles connexions extraites
        """
        # Initialiser processed_files si ce n'est pas déjà fait et si on est en mode temps réel
        if real_time and not hasattr(self, 'processed_files'):
            self.processed_files = set()
        
        # Initialiser conn_records pour éviter UnboundLocalError
        conn_records = []
        
        # Nombre de nouvelles connexions détectées
        new_connections = 0

        # Parcourir tous les fichiers de logs dans le répertoire
        for date_dir in os.listdir(self.zeek_logs_dir):
            date_path = os.path.join(self.zeek_logs_dir, date_dir)
            if not os.path.isdir(date_path):
                continue

            # Traiter les fichiers conn.log
            conn_logs = [f for f in os.listdir(date_path) if f.startswith('conn.') and f.endswith('.log.gz')]

            # En mode temps réel, ne traiter que les nouveaux fichiers
            if real_time:
                conn_logs = [f for f in conn_logs if self.is_new_file(os.path.join(date_path, f))]
                if not conn_logs:  # Aucun nouveau fichier à traiter
                    continue

            for conn_log in conn_logs:
                try:
                    current_records, _ = self.read_log_file(os.path.join(date_path, conn_log))
                    if current_records:
                        conn_records.extend(current_records)
                        # Marquer le fichier comme traité pour le mode temps réel
                        if real_time:
                            self.mark_file_as_processed(os.path.join(date_path, conn_log))
                except Exception as e:
                    print(f"Erreur lors de la lecture du fichier {conn_log}: {str(e)}")
                    continue

            # Traitement des enregistrements
            for record in conn_records:
                if not record or 'uid' not in record:
                    continue

                uid = record['uid']
                # Ne traiter que les nouvelles connexions non déjà enregistrées
                if uid not in self.connections:
                    ts = record.get('ts')
                    # Valider le timestamp
                    if not ts or '\x00' in ts or not ts.replace('.', '').replace('-', '').isdigit():
                        print(f"Skipping invalid timestamp '{ts}' for connection {uid}")
                        continue

                    self.connections[uid] = {
                        'ts': ts,
                        'uid': uid,
                        'id.orig_h': record.get('id.orig_h'),
                        'id.orig_p': record.get('id.orig_p'),
                        'id.resp_h': record.get('id.resp_h'),
                        'id.resp_p': record.get('id.resp_p'),
                        'proto': record.get('proto'),
                        'service': record.get('service'),
                        'duration': record.get('duration'),
                        'orig_bytes': record.get('orig_bytes'),
                        'resp_bytes': record.get('resp_bytes'),
                        'conn_state': record.get('conn_state'),
                        'missed_bytes': record.get('missed_bytes'),
                        'history': record.get('history'),
                        'orig_pkts': record.get('orig_pkts'),
                        'orig_ip_bytes': record.get('orig_ip_bytes'),
                        'resp_pkts': record.get('resp_pkts'),
                        'resp_ip_bytes': record.get('resp_ip_bytes')
                    }
                    new_connections += 1

            # Enrichir avec les données des autres logs (HTTP, DNS, SSL, etc.)
            self.enrich_with_protocol_logs(date_path)

        return new_connections

    def enrich_with_protocol_logs(self, date_path):
        """
        Enrichit les données de connexion avec les informations des logs spécifiques aux protocoles.
        
        Args:
            date_path (str): Chemin vers le répertoire contenant les logs d'une date spécifique
        """
        # Liste des logs de protocole à traiter
        protocol_logs = {
            'http': 'http.',
            'dns': 'dns.',
            'ssh': 'ssh.',
            'ssl': 'ssl.',
            'ftp': 'ftp.',
            'smtp': 'smtp.',
            'dhcp': 'dhcp.',
            'ntp': 'ntp.',
            'weird': 'weird.'
        }
        
        for protocol, prefix in protocol_logs.items():
            log_files = [f for f in os.listdir(date_path) if f.startswith(prefix) and f.endswith('.log.gz')]
            
            for log_file in log_files:
                records, _ = self.read_log_file(os.path.join(date_path, log_file))
                
                for record in records:
                    if not record or 'uid' not in record:
                        continue
                        
                    uid = record['uid']
                    if uid in self.connections:
                        # Si la connexion existe déjà, enrichir avec les données spécifiques au protocole
                        if protocol not in self.connections[uid]:
                            self.connections[uid][protocol] = []
                        self.connections[uid][protocol].append(record)
                        
                        # Si le service n'est pas défini dans les données de connexion, le définir
                        if not self.connections[uid]['service']:
                            self.connections[uid]['service'] = protocol

    def compute_nslkdd_features(self):
        """
        Calcule les caractéristiques au format NSL-KDD à partir des données de connexion.

        Returns:
            list: Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        nslkdd_records = []

        # Dictionnaires pour le calcul des caractéristiques basées sur le temps
        host_connections = defaultdict(list)  # Pour les connexions par host
        srv_connections = defaultdict(list)   # Pour les connexions par service

        # Trier les connexions par timestamp, en gérant les timestamps invalides
        def get_timestamp(conn):
            ts = conn.get('ts')
            if ts and isinstance(ts, str):
                try:
                    return float(ts)
                except ValueError:
                    print(f"Warning: Invalid timestamp '{ts}' for connection {conn.get('uid', 'unknown')}. Using 0.")
                    return 0
            return 0

        sorted_connections = sorted(self.connections.values(), key=get_timestamp)

        for conn in sorted_connections:
            # Extraire les caractéristiques de base
            nslkdd_record = {}

            # 1. duration: durée de la connexion en secondes
            nslkdd_record['duration'] = conn['duration'] if conn['duration'] else 0

            # 2. protocol_type: type de protocole (tcp, udp, icmp)
            proto = conn['proto'].lower() if conn['proto'] else 'tcp'
            if proto not in ['tcp', 'udp', 'icmp']:
                proto = 'tcp'  # Valeur par défaut
            nslkdd_record['protocol_type'] = proto

            # 3. service: type de service de destination
            service = conn['service'] if conn['service'] else 'other'
            nslkdd_record['service'] = self.service_mapping.get(service, 'other')

            # 4. flag: état de la connexion
            # Mapper l'état de connexion Zeek vers NSL-KDD
            conn_state = conn['conn_state'] if conn['conn_state'] else 'OTH'
            nslkdd_record['flag'] = self.flag_mapping.get(conn_state, 'OTH')

            # 5. src_bytes: nombre d'octets de la source vers la destination
            nslkdd_record['src_bytes'] = int(conn['orig_bytes']) if conn['orig_bytes'] else 0

            # 6. dst_bytes: nombre d'octets de la destination vers la source
            nslkdd_record['dst_bytes'] = int(conn['resp_bytes']) if conn['resp_bytes'] else 0

            # 7. wrong_fragment: nombre de fragments "erronés"
            # Cette information n'est pas directement disponible dans Zeek
            nslkdd_record['wrong_fragment'] = self.compute_wrong_fragment(conn)

            # 8. hot: nombre d'indicateurs "hot"
            # Cette information n'est pas directement disponible dans Zeek
            nslkdd_record['hot'] = self.compute_hot_indicators(conn)

            # 9. logged_in: connexion réussie (1) ou non (0)
            nslkdd_record['logged_in'] = self.compute_logged_in(conn)

            # 10. num_compromised: nombre d'actions "compromised"
            # Cette information n'est pas directement disponible dans Zeek
            nslkdd_record['num_compromised'] = self.compute_num_compromised(conn)

            # Caractéristiques basées sur le temps (window-based)
            # Mettre à jour les listes de connexions pour le calcul des statistiques
            src_ip = conn['id.orig_h']
            if src_ip:
                host_connections[src_ip].append(conn)

            # 11. count: nombre de connexions vers la même destination dans les 2 dernières secondes
            nslkdd_record['count'] = self.compute_same_host_count(conn, host_connections)

            # 12. srv_count: nombre de connexions vers le même service dans les 2 dernières secondes
            nslkdd_record['srv_count'] = self.compute_same_service_count(conn, srv_connections)

            # 13, 14, 15. Taux d'erreurs (serror_rate, srv_serror_rate, rerror_rate)
            error_rates = self.compute_error_rates(conn, host_connections, srv_connections)
            nslkdd_record['serror_rate'] = error_rates['serror_rate']
            nslkdd_record['srv_serror_rate'] = error_rates['srv_serror_rate']
            nslkdd_record['rerror_rate'] = error_rates['rerror_rate']

            nslkdd_records.append(nslkdd_record)

        return nslkdd_records

    def compute_wrong_fragment(self, conn):
        """
        Fonction d'espace réservé pour calculer le nombre de fragments erronés.
        Cette information n'est pas directement disponible dans Zeek.

        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            int: Nombre estimé de fragments erronés
        """
        # Cette caractéristique pourrait être estimée à partir des logs 'weird'
        # Pour l'instant, retournons une valeur par défaut
        if 'weird' in conn and conn['weird']:
            # Compter les événements weird liés à des problèmes de fragmentation
            frag_issues = sum(1 for weird in conn['weird'] 
                              if weird.get('name') and 'frag' in weird['name'].lower())
            return frag_issues
        return 0

    def compute_hot_indicators(self, conn):
        """
        Fonction d'espace réservé pour calculer le nombre d'indicateurs "hot".
        Cette caractéristique fait référence à des indicateurs de compromission
        ou d'activités potentiellement malveillantes.
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            int: Nombre estimé d'indicateurs "hot"
        """
        # Pour un IDS complet, cette fonction devrait analyser les logs
        # à la recherche d'indicateurs de compromission
        hot_count = 0
        
        # Exemple: vérifier si des commandes de système sont présentes dans les URL HTTP
        if 'http' in conn and conn['http']:
            for http_req in conn['http']:
                uri = http_req.get('uri', '')
                if uri:
                    # Recherche de motifs suspects dans les URI
                    suspicious_patterns = ['cmd=', 'exec=', '/bin/', '/etc/', 'passwd', 
                                          'shadow', '.php?', 'eval(', 'system(']
                    hot_count += sum(1 for pattern in suspicious_patterns if pattern in uri)
        
        return hot_count

    def compute_logged_in(self, conn):
        """
        Détermine si une connexion représente une session authentifiée.
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            str: '1' si authentifié, '0' sinon
        """
        # Vérifier les services qui nécessitent généralement une authentification
        auth_services = ['ssh', 'ftp', 'smtp', 'pop3', 'imap', 'telnet']
        service = conn['service']
        
        # Si c'est un service authentifié et la connexion est établie (SF)
        if service in auth_services and conn['conn_state'] == 'SF':
            # Vérifier les logs spécifiques pour confirmer l'authentification
            if service == 'ssh' and 'ssh' in conn:
                for ssh_log in conn['ssh']:
                    if ssh_log.get('auth_success') == 'true':
                        return '1'
            elif service == 'ftp' and 'ftp' in conn:
                for ftp_log in conn['ftp']:
                    if ftp_log.get('user') and ftp_log.get('password'):
                        return '1'
            # Par défaut pour les services authentifiés avec une connexion établie
            return '1'
        
        # HTTP peut avoir des authentifications
        if 'http' in conn and conn['http']:
            for http_req in conn['http']:
                if http_req.get('username') or 'Authorization' in (http_req.get('request_headers', '') or ''):
                    return '1'
        
        return '0'

    def compute_num_compromised(self, conn):
        """
        Fonction d'espace réservé pour estimer le nombre d'actions "compromised".
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            int: Nombre estimé d'actions "compromised"
        """
        # Cette fonction devrait idéalement analyser les logs à la recherche
        # d'indicateurs de compromission spécifiques
        compromised_count = 0
        
        # Exemple: vérifier les notices de sécurité
        if 'notice' in conn and conn['notice']:
            for notice in conn['notice']:
                notice_type = notice.get('note', '')
                if any(x in notice_type.lower() for x in ['exploit', 'attack', 'backdoor', 'trojan']):
                    compromised_count += 1
        
        return compromised_count

    def compute_same_host_count(self, conn, host_connections):
        """
        Calcule le nombre de connexions vers la même destination dans les 2 dernières secondes.

        Args:
            conn (dict): Données de connexion actuelle
            host_connections (dict): Dictionnaire des connexions par hôte source

        Returns:
            int: Nombre de connexions vers la même destination
        """
        if not conn.get('ts') or not conn.get('id.resp_h'):
            return 0

        def get_timestamp(c):
            ts = c.get('ts')
            if ts and isinstance(ts, str):
                try:
                    return float(ts)
                except ValueError:
                    print(f"Warning: Invalid timestamp '{ts}' for connection {c.get('uid', 'unknown')}. Using 0.")
                    return 0
            return 0

        current_ts = get_timestamp(conn)
        dest_ip = conn['id.resp_h']

        # Compter les connexions vers la même destination dans une fenêtre de 2 secondes
        count = sum(1 for c in host_connections.get(conn['id.orig_h'], [])
                    if c['id.resp_h'] == dest_ip and
                    get_timestamp(c) >= current_ts - 2 and
                    get_timestamp(c) <= current_ts)

        return count

    def compute_same_service_count(self, conn, srv_connections):
        """
        Calcule le nombre de connexions vers le même service dans les 2 dernières secondes.
        
        Args:
            conn (dict): Données de connexion actuelle
            srv_connections (dict): Dictionnaire des connexions par service
            
        Returns:
            int: Nombre de connexions vers le même service
        """
        if not conn['ts'] or not conn['service']:
            return 0
            
        current_ts = float(conn['ts'])
        service = conn['service']
        
        # Mettre à jour le dictionnaire des services
        if service not in srv_connections:
            srv_connections[service] = []
        srv_connections[service].append(conn)
        
        # Compter les connexions vers le même service dans une fenêtre de 2 secondes
        count = sum(1 for c in srv_connections[service]
                   if float(c['ts']) >= current_ts - 2 and 
                   float(c['ts']) <= current_ts)
        
        return count

    def compute_error_rates(self, conn, host_connections, srv_connections):
        """
        Calcule les taux d'erreurs pour différentes catégories.

        Args:
            conn (dict): Données de connexion actuelle
            host_connections (dict): Dictionnaire des connexions par hôte source
            srv_connections (dict): Dictionnaire des connexions par service

        Returns:
            dict: Dictionnaire contenant les différents taux d'erreurs
        """
        error_rates = {
            'serror_rate': 0.0,      # Taux de connexions SYN error vers la même dest
            'srv_serror_rate': 0.0,  # Taux de connexions SYN error vers le même service
            'rerror_rate': 0.0       # Taux de connexions REJ error vers la même dest
        }

        if not conn.get('ts') or not conn.get('id.orig_h'):
            return error_rates

        def get_timestamp(c):
            ts = c.get('ts')
            if ts and isinstance(ts, str):
                try:
                    return float(ts)
                except ValueError:
                    print(f"Warning: Invalid timestamp '{ts}' for connection {c.get('uid', 'unknown')}. Using 0.")
                    return 0
            return 0

        current_ts = get_timestamp(conn)
        src_ip = conn['id.orig_h']
        dest_ip = conn['id.resp_h']
        service = conn['service']

        # Connexions récentes vers la même destination
        same_host_conns = [c for c in host_connections.get(src_ip, [])
                           if c['id.resp_h'] == dest_ip and
                           get_timestamp(c) >= current_ts - 2 and
                           get_timestamp(c) <= current_ts]

        # Connexions récentes vers le même service
        same_srv_conns = [c for c in srv_connections.get(service, [])
                          if get_timestamp(c) >= current_ts - 2 and
                          get_timestamp(c) <= current_ts]

        # Calculer les taux d'erreurs
        if same_host_conns:
            error_rates['serror_rate'] = sum(1 for c in same_host_conns
                                             if c['conn_state'] == 'S0') / len(same_host_conns)
            error_rates['rerror_rate'] = sum(1 for c in same_host_conns
                                             if c['conn_state'] == 'REJ') / len(same_host_conns)

        if same_srv_conns:
            error_rates['srv_serror_rate'] = sum(1 for c in same_srv_conns
                                                 if c['conn_state'] == 'S0') / len(same_srv_conns)

        return error_rates

    def write_nslkdd_format(self, nslkdd_records):
        """
        Écrit les enregistrements au format NSL-KDD dans un fichier CSV.
        
        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.nslkdd_attributes)
            writer.writeheader()
            for record in nslkdd_records:
                writer.writerow(record)
                
        print(f"Fichier de sortie '{self.output_file}' créé avec succès!")
        print(f"Nombre d'enregistrements: {len(nslkdd_records)}")

    def convert(self):
        """
        Exécute le processus complet de conversion des logs Zeek vers le format NSL-KDD.
        """
        print("Début de la conversion des logs Zeek vers le format NSL-KDD...")
        print(f"Répertoire des logs Zeek: {self.zeek_logs_dir}")
        print(f"Fichier de sortie: {self.output_file}")
        
        # 1. Extraire les données de connexion
        print("Extraction des données de connexion...")
        self.extract_connection_data()
        print(f"Nombre de connexions extraites: {len(self.connections)}")
        
        # 2. Calculer les caractéristiques NSL-KDD
        print("Calcul des caractéristiques NSL-KDD...")
        nslkdd_records = self.compute_nslkdd_features()
        
        # 3. Écrire le fichier de sortie
        print("Écriture du fichier de sortie...")
        self.write_nslkdd_format(nslkdd_records)
        
        print("Conversion terminée avec succès!")

    def monitor_real_time_logs(self, interval=60):
        """
        Surveille les logs Zeek en temps réel et traite uniquement les nouvelles entrées à chaque intervalle.
        
        Args:
            interval (int): Intervalle de temps entre chaque vérification en secondes
        """
        import time
        import json
        import os
        from datetime import datetime
        
        print(f"Surveillance des logs en temps réel démarrée. Intervalle: {interval} secondes")
        print(f"Répertoire de surveillance: {self.real_time_logs_dir}")
        print("Appuyez sur Ctrl+C pour arrêter...\n")

        # Fichier pour stocker les positions
        positions_file = "zeek_log_positions.json"
        
        # Dictionnaire pour stocker les numéros de ligne des fichiers
        file_positions = {}
        
        # Liste des fichiers connus pour détecter les nouveaux fichiers après redémarrage
        known_files = set()
        
        # Charger les positions précédentes si le fichier existe
        if os.path.exists(positions_file):
            try:
                with open(positions_file, 'r') as f:
                    file_positions = json.load(f)
                print(f"Positions de lecture chargées: {len(file_positions)} fichiers")
                
                # Ajouter les fichiers chargés à la liste des fichiers connus
                known_files = set(file_positions.keys())
            except Exception as e:
                print(f"Erreur lors du chargement des positions: {e}")
        
        # Compteur de vérifications consécutives sans nouvelles connexions
        consecutive_empty_checks = 0
        
        try:
            while True:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Traitement des nouveaux logs...")
                
                # Vérifier s'il y a de nouveaux fichiers (potentiellement après un redémarrage de Zeek)
                current_files = set()
                for f in os.listdir(self.real_time_logs_dir):
                    if f.endswith('.log') and not f.startswith('stderr') and not f.startswith('stdout'):
                        current_files.add(os.path.join(self.real_time_logs_dir, f))
                
                # Détecter les nouveaux fichiers
                new_files = current_files - known_files
                if new_files:
                    print(f"Nouveaux fichiers détectés: {len(new_files)}")
                    for new_file in new_files:
                        print(f"  - {os.path.basename(new_file)}")
                        # Réinitialiser la position pour les nouveaux fichiers
                        file_positions[new_file] = 0
                    
                    # Mettre à jour la liste des fichiers connus
                    known_files = current_files
                
                # Vérifier si des fichiers ont disparu (supprimés ou renommés)
                missing_files = known_files - current_files
                if missing_files:
                    print(f"Fichiers disparus: {len(missing_files)}")
                    for missing_file in missing_files:
                        print(f"  - {os.path.basename(missing_file)}")
                        # Supprimer les fichiers manquants du dictionnaire de positions
                        if missing_file in file_positions:
                            del file_positions[missing_file]
                    
                    # Mettre à jour la liste des fichiers connus
                    known_files = current_files

                # Extraire seulement les nouvelles connexions et mettre à jour les positions
                # Si plusieurs échecs consécutifs, réinitialiser les positions pour forcer une relecture complète
                if consecutive_empty_checks >= 3:
                    print("Plusieurs vérifications sans nouvelles connexions. Réinitialisation des positions...")
                    file_positions = {f: 0 for f in file_positions}
                    consecutive_empty_checks = 0

                new_connections, file_positions = self.extract_real_time_connection_data(file_positions)

                # Sauvegarder les positions pour la prochaine exécution
                try:
                    with open(positions_file, 'w') as f:
                        json.dump(file_positions, f)
                except Exception as e:
                    print(f"Erreur lors de la sauvegarde des positions: {e}")

                if new_connections > 0:
                    # Calculer les caractéristiques NSL-KDD pour les nouvelles connexions
                    nslkdd_records = self.compute_nslkdd_features()
                    
                    # Ajouter les nouvelles données au fichier CSV
                    self.append_to_nslkdd_file(nslkdd_records)
                    
                    print(f"Données ajoutées au fichier CSV: {new_connections} enregistrements\n")
                    consecutive_empty_checks = 0  # Réinitialiser le compteur d'échecs
                else:
                    print("Aucune nouvelle connexion détectée depuis le dernier intervalle\n")
                    consecutive_empty_checks += 1

                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nSurveillance arrêtée par l'utilisateur.")
            # Sauvegarder les positions avant de quitter
            try:
                with open(positions_file, 'w') as f:
                    json.dump(file_positions, f)
                print(f"Positions de lecture sauvegardées dans {positions_file}")
            except Exception as e:
                print(f"Erreur lors de la sauvegarde des positions: {e}")

    def extract_real_time_connection_data(self, file_positions=None):
        """
        Extrait les données de connexion depuis les logs en temps réel de Zeek.
        Ne traite que les nouvelles entrées depuis la dernière lecture.

        Args:
            file_positions (dict): Dictionnaire des positions de départ pour chaque fichier log

        Returns:
            tuple: (nombre de nouvelles connexions, dictionnaire mis à jour des positions de fichier)
        """
        import os

        # Initialiser le dictionnaire des positions si non fourni
        if file_positions is None:
            file_positions = {}
            
        # Réinitialiser le dictionnaire des connexions pour détecter les nouvelles connexions
        # même après redémarrage du script
        self.connections = {}

        # Vérifier que le répertoire des logs en temps réel existe
        if not os.path.exists(self.real_time_logs_dir):
            print(f"ERREUR: Le répertoire des logs en temps réel '{self.real_time_logs_dir}' n'existe pas.")
            return 0, file_positions

        # Liste des fichiers log à traiter
        log_files_to_check = []
        
        # Obtenir la liste de tous les fichiers dans le répertoire
        for f in os.listdir(self.real_time_logs_dir):
            # Filtrer pour n'inclure que les fichiers .log (non compressés en temps réel)
            if f.endswith('.log') and not f.startswith('stderr') and not f.startswith('stdout'):
                log_files_to_check.append(f)
        
        print(f"Fichiers de log trouvés: {len(log_files_to_check)}")
        
        if not log_files_to_check:
            print("Aucun fichier log trouvé dans le répertoire de surveillance.")
            return 0, file_positions

        # Nombre de nouvelles connexions détectées
        new_connections = 0
        
        # Dictionnaire temporaire pour stocker les UIDs des logs de service qui seront traités plus tard
        service_logs_uids = {}

        # Première étape: Traiter conn.log pour établir les connexions de base
        conn_file = os.path.join(self.real_time_logs_dir, 'conn.log')
        
        if os.path.exists(conn_file):
            # Obtenir le numéro de ligne à partir duquel commencer la lecture
            start_line = file_positions.get(conn_file, 0)
            print(f"Lecture de {conn_file} depuis la ligne {start_line}")
            
            try:
                with open(conn_file, 'r', encoding='utf-8') as f:
                    # Ignorer les lignes déjà lues
                    for _ in range(start_line):
                        next(f, None)
                    
                    # Définir les variables pour le parsing
                    header = None
                    lines_read = 0
                    current_line = start_line
                    
                    # Lire et parser les nouvelles lignes
                    for line in f:
                        current_line += 1
                        lines_read += 1
                        line = line.strip()
                        
                        # Ignorer les lignes vides ou commentées, mais traiter l'en-tête
                        if not line or line.startswith('#') and not line.startswith('#fields'):
                            continue
                        
                        # Capturer l'en-tête
                        if line.startswith('#fields'):
                            header = line[8:].strip().split('\t')
                            continue
                        
                        # Si on n'a pas encore trouvé l'en-tête, continuer
                        if not header:
                            continue
                        
                        # Parser la ligne de données
                        values = line.split('\t')
                        if len(values) > 1:  # S'assurer qu'il y a assez de valeurs
                            record = {}
                            for i, field in enumerate(header):
                                if i < len(values):
                                    # Gérer les valeurs manquantes (représentées par '-' dans Zeek)
                                    if values[i] == '-':
                                        record[field] = None
                                    else:
                                        record[field] = values[i]
                                else:
                                    record[field] = None
                            
                            # Ajouter l'enregistrement si un UID valide est présent
                            if 'uid' in record and record['uid']:
                                uid = record['uid']
                                
                                # Valider le timestamp
                                ts = record.get('ts')
                                if not ts or '\x00' in ts or not ts.replace('.', '').replace('-', '').isdigit():
                                    print(f"Skipping invalid timestamp '{ts}' for connection {uid}")
                                    continue
                                
                                # Enregistrer la connexion
                                self.connections[uid] = {
                                    'ts': ts,
                                    'uid': uid,
                                    'id.orig_h': record.get('id.orig_h'),
                                    'id.orig_p': record.get('id.orig_p'),
                                    'id.resp_h': record.get('id.resp_h'),
                                    'id.resp_p': record.get('id.resp_p'),
                                    'proto': record.get('proto'),
                                    'service': record.get('service'),
                                    'duration': record.get('duration'),
                                    'orig_bytes': record.get('orig_bytes'),
                                    'resp_bytes': record.get('resp_bytes'),
                                    'conn_state': record.get('conn_state'),
                                    'missed_bytes': record.get('missed_bytes'),
                                    'history': record.get('history'),
                                    'orig_pkts': record.get('orig_pkts'),
                                    'orig_ip_bytes': record.get('orig_ip_bytes'),
                                    'resp_pkts': record.get('resp_pkts'),
                                    'resp_ip_bytes': record.get('resp_ip_bytes')
                                }
                                new_connections += 1
                    
                    # Mettre à jour le nombre de lignes lues
                    file_positions[conn_file] = current_line
                    print(f"Lecture de conn.log: {new_connections} connexions trouvées sur {lines_read} lignes")
                    print(f"Nouvelle position pour conn.log: ligne {current_line}")
            
            except Exception as e:
                print(f"Erreur lors de la lecture du fichier {conn_file}: {e}")

        # Deuxième étape: Enrichir avec les données des autres logs (http, dns, etc.)
        print("Enrichissement des connexions avec les données des services spécifiques...")
        
        for log_file in log_files_to_check:
            if log_file == 'conn.log':  # Déjà traité
                continue

            file_path = os.path.join(self.real_time_logs_dir, log_file)
            if not os.path.exists(file_path):
                continue
            
            # Déterminer le type de service à partir du nom du fichier
            log_type = log_file.split('.')[0]
            service_logs_uids[log_type] = set()  # Pour suivre les UIDs trouvés dans ce log
            
            # Obtenir le numéro de ligne à partir duquel commencer la lecture
            start_line = file_positions.get(file_path, 0)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # Ignorer les lignes déjà lues
                    for _ in range(start_line):
                        next(f, None)
                    
                    # Définir les variables pour le parsing
                    header = None
                    lines_read = 0
                    current_line = start_line
                    enriched_count = 0
                    
                    # Lire et parser les nouvelles lignes
                    for line in f:
                        current_line += 1
                        lines_read += 1
                        line = line.strip()
                        
                        # Ignorer les lignes vides ou commentées, mais traiter l'en-tête
                        if not line or line.startswith('#') and not line.startswith('#fields'):
                            continue
                        
                        # Capturer l'en-tête
                        if line.startswith('#fields'):
                            header = line[8:].strip().split('\t')
                            continue
                        
                        # Si on n'a pas encore trouvé l'en-tête, continuer
                        if not header:
                            continue
                        
                        # Parser la ligne de données
                        values = line.split('\t')
                        if len(values) > 1:  # S'assurer qu'il y a assez de valeurs
                            record = {}
                            for i, field in enumerate(header):
                                if i < len(values):
                                    # Gérer les valeurs manquantes (représentées par '-' dans Zeek)
                                    if values[i] == '-':
                                        record[field] = None
                                    else:
                                        record[field] = values[i]
                                else:
                                    record[field] = None
                            
                            # Traiter l'enregistrement s'il contient un UID
                            if 'uid' in record and record['uid']:
                                uid = record['uid']
                                service_logs_uids[log_type].add(uid)
                                
                                # Si la connexion existe déjà, l'enrichir avec ces données
                                if uid in self.connections:
                                    if log_type not in self.connections[uid]:
                                        self.connections[uid][log_type] = []
                                    self.connections[uid][log_type].append(record)
                                    
                                    # Si le service n'est pas défini, le définir en fonction du type de log
                                    if not self.connections[uid]['service'] and log_type in ['http', 'dns', 'ssh', 'ssl', 'ftp', 'smtp']:
                                        self.connections[uid]['service'] = log_type
                                    
                                    enriched_count += 1
                    
                    # Mettre à jour le nombre de lignes lues
                    file_positions[file_path] = current_line
                    if lines_read > 0:
                        print(f"Lecture de {log_file}: {lines_read} lignes, {enriched_count} connexions enrichies")
                        print(f"  UIDs uniques trouvés dans {log_file}: {len(service_logs_uids[log_type])}")
                        print(f"Nouvelle position pour {log_file}: ligne {current_line}")
            
            except Exception as e:
                print(f"Erreur lors de la lecture du fichier {file_path}: {e}")
        
        # Statistiques finales
        print(f"Nouvelles connexions détectées: {new_connections}")
        print(f"Nombre total de connexions en mémoire: {len(self.connections)}")
        
        return new_connections, file_positions

    def append_to_nslkdd_file(self, nslkdd_records):
        """
        Ajoute les enregistrements NSL-KDD à un fichier CSV existant.
        Si le fichier n'existe pas, il est créé avec un en-tête.

        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        import os
        import csv

        file_exists = os.path.isfile(self.output_file)

        with open(self.output_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.nslkdd_attributes)
            if not file_exists:
                writer.writeheader()
            for record in nslkdd_records:
                writer.writerow(record)

    def enrich_data_for_elasticsearch(self, nslkdd_records):
        """
        Enrichit les données NSL-KDD avec des informations supplémentaires pour ElasticSearch.

        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD

        Returns:
            list: Liste de dictionnaires enrichis pour ElasticSearch
        """
        from datetime import datetime
        import socket

        enriched_records = []

        for i, record in enumerate(nslkdd_records):
            # Récupérer l'identifiant de connexion correspondant
            conn_id = list(self.connections.keys())[i] if i < len(self.connections) else None
            conn = self.connections.get(conn_id, {})

            # Créer un nouvel enregistrement enrichi
            enriched = record.copy()

            # Ajouter des informations temporelles
            ts = conn.get('ts')
            if ts and isinstance(ts, str):
                try:
                    timestamp = datetime.fromtimestamp(float(ts))
                    enriched['@timestamp'] = timestamp.isoformat()
                except (ValueError, TypeError):
                    print(f"Warning: Invalid timestamp '{ts}' for connection {conn_id}. Using current time.")
                    enriched['@timestamp'] = datetime.now().isoformat()
            else:
                enriched['@timestamp'] = datetime.now().isoformat()

            # Ajouter des informations réseau
            enriched['src_ip'] = conn.get('id.orig_h')
            enriched['src_port'] = conn.get('id.orig_p')
            enriched['dst_ip'] = conn.get('id.resp_h')
            enriched['dst_port'] = conn.get('id.resp_p')

            # Résolution DNS (optionnelle, peut être coûteux en performance)
            src_ip = conn.get('id.orig_h')
            dst_ip = conn.get('id.resp_h')
            try:
                if src_ip:
                    enriched['src_hostname'] = socket.getfqdn(src_ip)
                if dst_ip:
                    enriched['dst_hostname'] = socket.getfqdn(dst_ip)
            except:
                pass

            # Ajouter des informations de trafic réseau
            enriched['bytes_in'] = conn.get('orig_bytes')
            enriched['bytes_out'] = conn.get('resp_bytes')
            enriched['packets_in'] = conn.get('orig_pkts')
            enriched['packets_out'] = conn.get('resp_pkts')

            # Récupérer le nom du service depuis le mappage
            service = conn.get('service')
            if service:
                enriched['service_name'] = service
                enriched['service_mapped'] = self.service_mapping.get(service, 'other')

            # Ajouter l'identifiant unique de la connexion
            enriched['conn_uid'] = conn_id

            # Ajouter des informations d'état de connexion
            enriched['conn_state_desc'] = self.get_conn_state_description(conn.get('conn_state'))

            # Vérifier si la connexion contient des indicateurs de sécurité
            if 'notice' in conn:
                notices = [n.get('note') for n in conn['notice'] if n.get('note')]
                if notices:
                    enriched['security_notices'] = notices

            # Autres métadonnées
            enriched['source'] = 'zeek'
            enriched['event_type'] = 'network_connection'

            enriched_records.append(enriched)

        return enriched_records

    def get_conn_state_description(self, conn_state):
        """
        Retourne une description en langage naturel pour un état de connexion donné.

        Args:
            conn_state (str): État de connexion Zeek

        Returns:
            str: Description de l'état de connexion
        """
        descriptions = {
            'S0': "Tentative de connexion sans réponse",
            'SF': "Établissement et terminaison normale",
            'REJ': "Tentative de connexion rejetée",
            'S1': "Connexion établie, non terminée",
            'S2': "Connexion établie, tentative de fermeture par l'initiateur",
            'S3': "Connexion établie, tentative de fermeture par le destinataire",
            'RSTO': "Connexion établie, avortée par l'initiateur",
            'RSTR': "Connexion établie, avortée par le destinataire",
            'RSTOS0': "L'initiateur a envoyé un SYN suivi d'un RST",
            'SH': "L'initiateur a envoyé un SYN suivi d'un FIN",
            'OTH': "Pas de SYN, non fermée"
        }

        return descriptions.get(conn_state, "État inconnu")

    def store_in_elasticsearch(self, nslkdd_records):
        """
        Stocke les enregistrements NSL-KDD dans ElasticSearch.

        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        try:
            from elasticsearch import Elasticsearch, helpers
            import urllib3
            import warnings

            # Désactiver les avertissements SSL
            urllib3.disable_warnings()
            warnings.filterwarnings('ignore')

            # Enrichir les données pour ElasticSearch
            es_records = self.enrich_data_for_elasticsearch(nslkdd_records)

            # Connexion à ElasticSearch
            es = Elasticsearch(
                self.es_config["url"],
                api_key=self.es_config["api_key"],
                verify_certs=False,
                ssl_show_warn=False
            )

            # Vérifier la connexion
            if not es.ping():
                print("ERREUR: Impossible de se connecter à ElasticSearch.")
                return

            # Préparation des données pour l'insertion en bloc
            actions = []
            for record in es_records:
                action = {
                    "_index": self.es_config["index"],
                    "_source": record
                }
                actions.append(action)

            # Insérer les données par lots
            if actions:
                # Diviser en lots si nécessaire
                batch_size = self.es_config["batch_size"]
                for i in range(0, len(actions), batch_size):
                    batch = actions[i:i+batch_size]
                    success, failed = helpers.bulk(es, batch, stats_only=True)
                    print(f"ElasticSearch: {success} documents indexés, {failed} échecs")

        except ImportError:
            print("ERREUR: Module Elasticsearch non disponible. Installez-le avec 'pip install elasticsearch'")
        except Exception as e:
            print(f"ERREUR lors de l'insertion dans ElasticSearch: {e}")

    def verify_file_positions(self, file_positions):
        """
        Vérifie la cohérence entre les positions de lecture et les tailles actuelles des fichiers.
        
        Args:
            file_positions (dict): Dictionnaire des positions de lecture des fichiers
            
        Returns:
            dict: Dictionnaire mis à jour des positions de lecture
        """
        import os
        
        updated_positions = file_positions.copy()
        files_to_reset = []
        
        print("Vérification des positions de fichiers...")
        
        for file_path, position in file_positions.items():
            if not os.path.exists(file_path):
                print(f"Fichier non trouvé: {file_path}, position réinitialisée")
                files_to_reset.append(file_path)
                continue
                
            file_size = os.path.getsize(file_path)
            
            # Si le fichier est plus petit que la position enregistrée, il a probablement été recréé
            if position > file_size + 100:  # Marge de tolérance de 100 octets
                print(f"Anomalie de position détectée pour {file_path}")
                print(f"  Position enregistrée: {position}, Taille du fichier: {file_size}")
                files_to_reset.append(file_path)
                
            # Vérifier si le fichier a peu évolué malgré beaucoup de lignes
            try:
                with open(file_path, 'r') as f:
                    line_count = sum(1 for _ in f)
                avg_line_size = file_size / max(line_count, 1)
                estimated_lines_read = position / max(avg_line_size, 1) if avg_line_size > 0 else 0
                
                if position > 0 and line_count > 10 and estimated_lines_read > line_count * 1.5:
                    print(f"Possible problème de lecture pour {file_path}")
                    print(f"  Nombre de lignes: {line_count}, Estimation des lignes lues: {int(estimated_lines_read)}")
                    files_to_reset.append(file_path)
            except Exception as e:
                print(f"Erreur lors de l'analyse du fichier {file_path}: {e}")
        
        # Réinitialiser les positions problématiques
        for file_path in set(files_to_reset):
            updated_positions[file_path] = 0
            print(f"Position réinitialisée pour {file_path}")
        
        if files_to_reset:
            print(f"{len(files_to_reset)} fichiers ont eu leur position réinitialisée.")
        
        return updated_positions


def main():
    """
    Fonction principale qui analyse les arguments de ligne de commande et exécute les actions appropriées.
    """
    import argparse
    import sys

    # Analyser les arguments de ligne de commande
    parser = argparse.ArgumentParser(description='Convertit les logs Zeek en format NSL-KDD pour les systèmes de détection d\'intrusion.')
    parser.add_argument('--logs-dir', type=str, default='/opt/zeek/logs',
                        help='Répertoire contenant les logs Zeek (par défaut: /opt/zeek/logs)')
    parser.add_argument('--output', type=str, default='nslkdd_format.csv',
                        help='Fichier de sortie au format NSL-KDD (par défaut: nslkdd_format.csv)')
    parser.add_argument('--real-time', action='store_true',
                        help='Surveiller les logs Zeek en temps réel')
    parser.add_argument('--interval', type=int, default=60,
                        help='Intervalle de surveillance en secondes (par défaut: 60)')
    parser.add_argument('--elasticsearch', action='store_true',
                        help='Intégrer les données dans ElasticSearch')

    args = parser.parse_args()

    # Créer le convertisseur avec les options spécifiées
    converter = ZeekToNSLKDD(
        zeek_logs_dir=args.logs_dir,
        output_file=args.output,
        real_time=args.real_time,
        es_integration=args.elasticsearch
    )

    # Exécuter l'action appropriée
    if args.real_time:
        # Mode de surveillance en temps réel
        converter.monitor_real_time_logs(interval=args.interval)
    else:
        # Mode de traitement par lots (existant)
        converter.convert()

if __name__ == "__main__":
    main()


