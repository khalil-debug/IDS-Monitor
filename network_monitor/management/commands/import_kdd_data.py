import os
import gzip
import urllib.request
import pandas as pd
import numpy as np
from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
from network_monitor.models import NetworkEvent

class Command(BaseCommand):
    help = 'Importe et analyse les données KDD Cup 1999 pour améliorer la détection'

    KDD_FEATURES = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
    ]

    KDD_ATTACK_TYPES = {
        'normal': 'normal',
        'back': 'dos',
        'buffer_overflow': 'u2r',
        'ftp_write': 'r2l',
        'guess_passwd': 'r2l',
        'imap': 'r2l',
        'ipsweep': 'probe',
        'land': 'dos',
        'loadmodule': 'u2r',
        'multihop': 'r2l',
        'neptune': 'dos',
        'nmap': 'probe',
        'perl': 'u2r',
        'phf': 'r2l',
        'pod': 'dos',
        'portsweep': 'probe',
        'rootkit': 'u2r',
        'satan': 'probe',
        'smurf': 'dos',
        'spy': 'r2l',
        'teardrop': 'dos',
        'warezclient': 'r2l',
        'warezmaster': 'r2l'
    }

    DATASET_URL = "http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data.gz"
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            help='Limiter le nombre d\'enregistrements à importer (pour le test)',
            default=10000
        )
        parser.add_argument(
            '--analyze-only',
            action='store_true',
            help='Analyser sans importer les données'
        )
        parser.add_argument(
            '--import-to-db',
            action='store_true',
            help='Importer les exemples d\'attaques dans la base de données pour référence'
        )

    def handle(self, *args, **options):
        limit = options.get('limit')
        analyze_only = options.get('analyze_only')
        import_to_db = options.get('import_to_db')
        
        self.stdout.write(self.style.SUCCESS(f'Traitement du jeu de données KDD Cup 1999 (limite: {limit} entrées)'))
        
        data_dir = os.path.join(settings.BASE_DIR, 'data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
            
        local_file = os.path.join(data_dir, 'kddcup.data.gz')
        if not os.path.exists(local_file):
            self.stdout.write('Téléchargement du jeu de données KDD Cup...')
            urllib.request.urlretrieve(self.DATASET_URL, local_file)
            self.stdout.write(self.style.SUCCESS('Téléchargement terminé'))
            
        self.stdout.write('Chargement des données...')
        data = self._load_kdd_data(local_file, limit)
        
        self._analyze_kdd_data(data)
        
        if import_to_db and not analyze_only:
            self._import_to_db(data)
            
    def _load_kdd_data(self, filepath, limit):
        """Charge les données KDD Cup dans un DataFrame pandas"""
        try:
            with gzip.open(filepath, 'rt') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    lines.append(line.strip())
                    
            data = []
            for line in lines:
                values = line.split(',')
                if len(values) == len(self.KDD_FEATURES):
                    data.append(values)
                    
            df = pd.DataFrame(data, columns=self.KDD_FEATURES)
            
            # Convert all numeric columns to float type
            numeric_cols = ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 
                           'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                           'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
                           'num_access_files', 'num_outbound_cmds', 'count', 'srv_count',
                           'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                           'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
                           'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                           'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                           'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
                           'dst_host_srv_rerror_rate']
                           
            for col in numeric_cols:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                
            df['attack_type'] = df['label'].apply(lambda x: x.strip('.').lower())
            df['attack_category'] = df['attack_type'].apply(
                lambda x: self.KDD_ATTACK_TYPES.get(x, 'unknown'))
                
            return df
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Erreur lors du chargement des données: {e}'))
            return pd.DataFrame()
            
    def _analyze_kdd_data(self, data):
        """Analyse et affiche des statistiques sur le jeu de données KDD Cup"""
        if data.empty:
            self.stdout.write(self.style.ERROR('Aucune donnée à analyser'))
            return
            
        self.stdout.write('\nAnalyse du jeu de données KDD Cup:')
        self.stdout.write('-' * 50)
        
        self.stdout.write(f'Nombre total d\'entrées: {len(data)}')
        
        attack_counts = data['attack_type'].value_counts()
        self.stdout.write('\nDistribution des types d\'attaques:')
        for attack, count in attack_counts.items():
            percentage = (count / len(data)) * 100
            self.stdout.write(f'  {attack}: {count} ({percentage:.1f}%)')
            
        category_counts = data['attack_category'].value_counts()
        self.stdout.write('\nDistribution des catégories d\'attaques:')
        for category, count in category_counts.items():
            percentage = (count / len(data)) * 100
            self.stdout.write(f'  {category}: {count} ({percentage:.1f}%)')
            
        self.stdout.write('\nStatistiques sur les tentatives de connexion échouées:')
        failed_logins = data['num_failed_logins'].describe()
        for stat, value in failed_logins.items():
            self.stdout.write(f'  {stat}: {value}')
            
        self.stdout.write('\nCorrélation entre variables clés:')
        # Ensure these columns are numeric for correlation calculation
        corr_cols = ['duration', 'src_bytes', 'dst_bytes', 'count']
        data_corr = data[corr_cols].copy()
        corr_matrix = data_corr.corr()
        for i, row in enumerate(corr_matrix.values):
            feature1 = corr_matrix.index[i]
            for j, corr in enumerate(row):
                feature2 = corr_matrix.columns[j]
                if i < j:
                    self.stdout.write(f'  Corrélation {feature1} - {feature2}: {corr:.3f}')
                    
        self.stdout.write('\nCaractéristiques des attaques DoS:')
        dos_data = data[data['attack_category'] == 'dos']
        if not dos_data.empty:
            dos_stats = dos_data[['count', 'srv_count', 'src_bytes']].describe()
            for stat, row in dos_stats.items():
                self.stdout.write(f'  {stat}:')
                for metric, value in row.items():
                    self.stdout.write(f'    {metric}: {value:.2f}')
                    
        # Extraction des seuils de détection
        self.stdout.write('\nSeuils de détection suggérés:')
        
        # Seuil pour DoS: nombre élevé de connexions
        dos_count_threshold = dos_data['count'].quantile(0.75) if not dos_data.empty else 0
        self.stdout.write(f'  Seuil pour DoS (connexions): >= {dos_count_threshold:.0f}')
        
        # Seuil pour scan de ports: nombreux services différents
        probe_data = data[data['attack_category'] == 'probe']
        probe_diff_srv_threshold = probe_data['diff_srv_rate'].quantile(0.75) if not probe_data.empty else 0
        self.stdout.write(f'  Seuil pour scan de ports (taux de services différents): >= {probe_diff_srv_threshold:.2f}')
        
        # Seuil pour brute force: tentatives de connexion échouées
        r2l_data = data[data['attack_category'] == 'r2l']
        brute_force_threshold = r2l_data['num_failed_logins'].quantile(0.75) if not r2l_data.empty else 0
        self.stdout.write(f'  Seuil pour brute force (connexions échouées): >= {brute_force_threshold:.0f}')
            
    def _import_to_db(self, data):
        """Importe des exemples d'attaques dans la base de données pour référence"""
        self.stdout.write('\nImportation des exemples d\'attaques dans la base de données...')
        
        # Échantillonner quelques entrées de chaque catégorie
        samples = []
        for category in data['attack_category'].unique():
            category_data = data[data['attack_category'] == category]
            # Prendre au maximum 10 échantillons de chaque catégorie
            samples.append(category_data.sample(min(10, len(category_data))))
        
        # Combiner les échantillons
        samples_df = pd.concat(samples)
        
        # Pour chaque échantillon, créer un événement factice
        events_created = 0
        for _, row in samples_df.iterrows():
            try:
                # Mapper le type d'attaque KDD en type d'événement IDS
                event_type = self._map_kdd_to_event_type(row['attack_category'])
                
                # Déterminer la sévérité basée sur le type d'attaque
                severity = self._determine_severity(row['attack_category'])
                
                # Créer un événement factice
                event = NetworkEvent.objects.create(
                    source_ip='192.168.1.100',
                    destination_ip='192.168.1.1',
                    source_port=1024,
                    destination_port=80,
                    protocol=row['protocol_type'].upper(),
                    event_type=event_type,
                    severity=severity,
                    description=f"Exemple d'attaque {row['attack_type']} (KDD Cup 1999)",
                    is_threat=True,
                    packet_info={
                        'kdd_features': {
                            'duration': float(row['duration']),
                            'src_bytes': float(row['src_bytes']),
                            'dst_bytes': float(row['dst_bytes']),
                            'count': float(row['count']),
                            'num_failed_logins': float(row['num_failed_logins']),
                            'attack_type': row['attack_type'],
                            'attack_category': row['attack_category']
                        }
                    }
                )
                events_created += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Erreur lors de la création d\'un événement: {e}'))
                
        self.stdout.write(self.style.SUCCESS(f'Importation terminée: {events_created} événements créés'))
        
    def _map_kdd_to_event_type(self, kdd_category):
        """Convertit une catégorie d'attaque KDD en type d'événement IDS"""
        mapping = {
            'dos': 'ddos',
            'probe': 'port_scan',
            'r2l': 'brute_force',
            'u2r': 'suspicious_packet',
            'normal': 'connection'
        }
        return mapping.get(kdd_category, 'other')
        
    def _determine_severity(self, kdd_category):
        """Détermine la sévérité basée sur la catégorie d'attaque KDD"""
        mapping = {
            'dos': 'high',
            'probe': 'medium',
            'r2l': 'high',
            'u2r': 'critical',
            'normal': 'low'
        }
        return mapping.get(kdd_category, 'medium') 