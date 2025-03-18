import random
import time
import ipaddress
import socket
import threading
from django.core.management.base import BaseCommand
from django.utils import timezone

class Command(BaseCommand):
    help = 'Simule différentes attaques réseau pour tester le système IDS'

    def add_arguments(self, parser):
        parser.add_argument(
            '--target',
            type=str,
            help='Adresse IP cible (par défaut: localhost)',
            default='127.0.0.1'
        )
        parser.add_argument(
            '--port',
            type=int,
            help='Port cible (par défaut: 80)',
            default=80
        )
        parser.add_argument(
            '--duration',
            type=int,
            help='Durée de la simulation en secondes',
            default=60
        )
        parser.add_argument(
            '--attack-type',
            type=str,
            choices=['all', 'port-scan', 'ddos', 'brute-force'],
            help='Type d\'attaque à simuler',
            default='all'
        )
        parser.add_argument(
            '--intensity',
            type=str,
            choices=['low', 'medium', 'high'],
            help='Intensité de l\'attaque',
            default='medium'
        )

    def handle(self, *args, **options):
        target = options.get('target')
        port = options.get('port')
        duration = options.get('duration')
        attack_type = options.get('attack_type')
        intensity = options.get('intensity')
        
        # Configuration de l'intensité
        intensity_settings = {
            'low': {'threads': 2, 'delay': 1.0, 'ports': 10, 'packets': 5},
            'medium': {'threads': 5, 'delay': 0.5, 'ports': 50, 'packets': 20},
            'high': {'threads': 10, 'delay': 0.1, 'ports': 100, 'packets': 50}
        }
        settings = intensity_settings[intensity]
        
        self.stdout.write(self.style.SUCCESS(
            f'Démarrage de la simulation d\'attaque {"(" + attack_type + ")" if attack_type != "all" else ""} '
            f'avec intensité {intensity}'
        ))
        self.stdout.write(f'Cible: {target}:{port}, Durée: {duration}s')
        
        # Définir le temps de fin
        end_time = time.time() + duration
        
        # Démarrer les attaques appropriées
        threads = []
        
        if attack_type in ['all', 'port-scan']:
            t = threading.Thread(
                target=self._simulate_port_scan,
                args=(target, settings, end_time),
                daemon=True
            )
            threads.append(t)
            t.start()
            self.stdout.write('Simulation de scan de ports démarrée')
            
        if attack_type in ['all', 'ddos']:
            t = threading.Thread(
                target=self._simulate_ddos,
                args=(target, port, settings, end_time),
                daemon=True
            )
            threads.append(t)
            t.start()
            self.stdout.write('Simulation d\'attaque DDoS démarrée')
            
        if attack_type in ['all', 'brute-force']:
            t = threading.Thread(
                target=self._simulate_brute_force,
                args=(target, settings, end_time),
                daemon=True
            )
            threads.append(t)
            t.start()
            self.stdout.write('Simulation de tentative de brute-force démarrée')
            
        # Attendre jusqu'à la fin du temps spécifié
        try:
            remaining = duration
            while time.time() < end_time:
                # Mettre à jour toutes les 5 secondes
                time.sleep(min(5, remaining))
                remaining = int(end_time - time.time())
                if remaining > 0:
                    self.stdout.write(f'Simulation en cours... {remaining}s restantes')
                    
            self.stdout.write(self.style.SUCCESS('Temps écoulé. Arrêt des simulations...'))
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nSimulation interrompue par l\'utilisateur'))
            
        # Attendre que tous les threads se terminent
        for t in threads:
            t.join(timeout=2.0)
            
        self.stdout.write(self.style.SUCCESS('Simulation terminée'))
            
    def _simulate_port_scan(self, target, settings, end_time):
        """Simule un scan de ports sur la cible"""
        try:
            delay = settings['delay']
            ports_per_scan = settings['ports']
            
            while time.time() < end_time:
                # Générer un ensemble de ports à scanner
                ports = random.sample(range(1, 65535), min(ports_per_scan, 1000))
                
                for port in ports:
                    if time.time() >= end_time:
                        break
                        
                    try:
                        # Tenter d'établir une connexion pour simuler un scan
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.1)  # Court timeout pour ne pas bloquer
                        s.connect((target, port))
                        s.close()
                    except:
                        pass  # Ignorer les erreurs, c'est normal pour un scan
                        
                    # Ajouter un délai pour contrôler l'intensité
                    time.sleep(delay)
                    
                # Pause entre les séries de scans
                time.sleep(delay * 5)
                
        except Exception as e:
            print(f"Erreur lors de la simulation de scan de ports: {e}")
            
    def _simulate_ddos(self, target, port, settings, end_time):
        """Simule une attaque DDoS sur la cible"""
        try:
            delay = settings['delay']
            packets_per_burst = settings['packets']
            
            while time.time() < end_time:
                # Envoyer une rafale de paquets
                for _ in range(packets_per_burst):
                    if time.time() >= end_time:
                        break
                        
                    try:
                        # Créer et envoyer un paquet
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)  # Court timeout
                        s.connect((target, port))
                        # Envoyer des données aléatoires
                        s.send(b'X' * random.randint(1, 100))
                        s.close()
                    except:
                        pass  # Ignorer les erreurs
                        
                    # Petit délai entre les paquets
                    time.sleep(delay * 0.1)
                    
                # Pause entre les rafales
                time.sleep(delay)
                
        except Exception as e:
            print(f"Erreur lors de la simulation d'attaque DDoS: {e}")
            
    def _simulate_brute_force(self, target, settings, end_time):
        """Simule une attaque de brute-force sur des services courants"""
        try:
            delay = settings['delay']
            # Ports couramment ciblés pour les attaques de brute-force
            target_services = [22, 23, 3389, 21, 25, 110, 143]
            
            # Choisir un service au hasard
            service_port = random.choice(target_services)
            
            # Liste de noms d'utilisateur et mots de passe courants pour la simulation
            usernames = ['admin', 'root', 'user', 'test', 'guest', 'administrator', 'oracle', 'webadmin']
            passwords = ['password', '123456', 'admin', 'root', 'qwerty', 'welcome', 'abc123', 'password123']
            
            while time.time() < end_time:
                # Sélectionner un nom d'utilisateur et mot de passe aléatoires
                username = random.choice(usernames)
                password = random.choice(passwords)
                
                try:
                    # Simuler une tentative de connexion
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    s.connect((target, service_port))
                    # Envoyer des données simulant une tentative de connexion
                    auth_string = f"{username}:{password}".encode()
                    s.send(auth_string)
                    s.close()
                except:
                    pass  # Ignorer les erreurs
                
                # Délai entre les tentatives
                time.sleep(delay)
                
        except Exception as e:
            print(f"Erreur lors de la simulation de brute-force: {e}") 