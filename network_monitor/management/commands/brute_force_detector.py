import time
import logging
from collections import defaultdict
from django.core.management.base import BaseCommand
from django.utils import timezone
from network_monitor.models import NetworkEvent, Alert, BlockedIP

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Détecte les tentatives de brute-force en analysant les fréquences de connexions'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.check_stop = lambda: False

    def add_arguments(self, parser):
        parser.add_argument(
            '--threshold',
            type=int,
            help='Nombre de tentatives échouées avant de déclencher une alerte',
            default=5
        )
        parser.add_argument(
            '--window',
            type=int,
            help='Fenêtre de temps en secondes pour l\'analyse',
            default=60
        )
        parser.add_argument(
            '--ports',
            type=str,
            help='Ports sensibles à surveiller (séparés par des virgules)',
            default='22,23,3389,445,21,25,110,143'
        )
        parser.add_argument(
            '--run-once',
            action='store_true',
            help='Exécuter une seule analyse puis terminer'
        )

    def handle(self, *args, **options):
        threshold = int(options.get('threshold', 5))
        window = int(options.get('window', 60))
        
        ports_str = options.get('ports', '22,23,3389,445,21,25,110,143')
        try:
            ports = [int(p.strip()) for p in ports_str.split(',')]
        except (ValueError, AttributeError):
            self.stdout.write(self.style.WARNING(f'Invalid ports format: {ports_str}, using default ports'))
            ports = [22, 23, 3389, 445, 21, 25, 110, 143]
            
        run_once = bool(options.get('run_once', False))
        
        self.stdout.write(self.style.SUCCESS(
            f'Démarrage du détecteur de brute-force (seuil: {threshold}, fenêtre: {window}s, ports: {ports})'
        ))
        
        connection_attempts = defaultdict(list)
        
        try:
            while True:
                if self.check_stop():
                    self.stdout.write(self.style.WARNING('Détection arrêtée par l\'utilisateur'))
                    break
                
                window_start = timezone.now() - timezone.timedelta(seconds=window)
                
                recent_failed_connections = NetworkEvent.objects.filter(
                    timestamp__gte=window_start,
                    destination_port__in=ports,
                    protocol__in=['TCP', 'SSH'],
                    description__icontains='failed'
                ).order_by('timestamp')
                
                for event in recent_failed_connections:
                    connection_attempts[event.source_ip].append(event.timestamp)
                
                current_time = timezone.now()
                for ip, timestamps in list(connection_attempts.items()):
                    timestamps = [ts for ts in timestamps if (current_time - ts).total_seconds() <= window]
                    connection_attempts[ip] = timestamps
                    
                    if len(timestamps) >= threshold:
                        self._create_brute_force_alert(ip, timestamps, window, threshold)
                        
                        del connection_attempts[ip]
                
                if run_once:
                    self.stdout.write(self.style.SUCCESS('Analyse terminée'))
                    break
                    
                time.sleep(10)
                
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Détection interrompue par l\'utilisateur'))
    
    def _create_brute_force_alert(self, source_ip, timestamps, window, threshold):
        """Créer une alerte pour une tentative de brute-force détectée"""
        try:
            attempt_rate = len(timestamps) / window
            severity = self._calculate_severity(attempt_rate)
            
            is_blocked = BlockedIP.objects.filter(ip_address=source_ip, active=True).exists()
            if is_blocked:
                self.stdout.write(self.style.WARNING(f'IP {source_ip} déjà bloquée, ignorée'))
                return
                
            event = NetworkEvent.objects.create(
                source_ip=source_ip,
                destination_ip='Multiple',
                source_port=None,
                destination_port=None,
                protocol='TCP',
                event_type='brute_force',
                severity=severity,
                description=f"Tentative de brute-force détectée: {len(timestamps)} tentatives en {window}s",
                is_threat=True,
                packet_info={
                    'attempt_count': len(timestamps),
                    'window': window,
                    'threshold': threshold,
                    'attempt_rate': attempt_rate,
                    'timestamps': [ts.isoformat() for ts in timestamps[-10:]]  # Limiter à 10 derniers
                }
            )
            
            Alert.objects.create(
                event=event,
                message=f"ALERTE: {severity.upper()} - Tentative de brute-force depuis {source_ip}: {len(timestamps)} tentatives en {window}s"
            )
            
            if attempt_rate > threshold * 2:
                BlockedIP.objects.create(
                    ip_address=source_ip,
                    reason=f"Blocage automatique suite à une tentative de brute-force (taux: {attempt_rate:.2f} tentatives/s)",
                    active=True
                )
                self.stdout.write(self.style.ERROR(f'IP {source_ip} automatiquement bloquée (taux élevé: {attempt_rate:.2f}/s)'))
            
            self.stdout.write(self.style.WARNING(
                f'Brute-force détecté - IP: {source_ip}, Tentatives: {len(timestamps)}, Taux: {attempt_rate:.2f}/s, Sévérité: {severity}'
            ))
            
        except Exception as e:
            logger.error(f"Erreur lors de la création d'une alerte brute-force: {e}")
    
    def _calculate_severity(self, attempt_rate):
        """Calculer la sévérité basée sur le taux de tentatives"""
        if attempt_rate < 0.1:
            return 'low'
        elif attempt_rate < 0.5:
            return 'medium'
        elif attempt_rate < 2.0:
            return 'high'
        else:
            return 'critical' 