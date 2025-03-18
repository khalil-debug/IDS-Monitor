import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from network_monitor.pdf_reports import generate_security_report

class Command(BaseCommand):
    help = 'Génère un rapport de sécurité PDF pour la période spécifiée'

    def add_arguments(self, parser):
        parser.add_argument(
            '--type',
            type=str,
            choices=['daily', 'weekly', 'monthly'],
            default='daily',
            help='Type de rapport à générer'
        )
        parser.add_argument(
            '--start',
            type=str,
            help='Date de début au format YYYY-MM-DD (optionnel)'
        )
        parser.add_argument(
            '--end',
            type=str,
            help='Date de fin au format YYYY-MM-DD (optionnel)'
        )

    def handle(self, *args, **options):
        report_type = options.get('type')
        
        start_date = None
        end_date = None
        
        if options.get('start'):
            try:
                start_date = datetime.datetime.strptime(options.get('start'), '%Y-%m-%d')
                start_date = timezone.make_aware(start_date)
            except ValueError:
                self.stdout.write(self.style.ERROR('Format de date de début invalide. Utilisez YYYY-MM-DD'))
                return
                
        if options.get('end'):
            try:
                end_date = datetime.datetime.strptime(options.get('end'), '%Y-%m-%d')
                end_date = timezone.make_aware(end_date.replace(hour=23, minute=59, second=59))
            except ValueError:
                self.stdout.write(self.style.ERROR('Format de date de fin invalide. Utilisez YYYY-MM-DD'))
                return
        
        self.stdout.write(self.style.SUCCESS(f'Génération du rapport {report_type} en cours...'))
        
        try:
            report_path = generate_security_report(
                report_type=report_type,
                start_date=start_date,
                end_date=end_date
            )
            
            self.stdout.write(self.style.SUCCESS(f'Rapport généré avec succès: {report_path}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Erreur lors de la génération du rapport: {e}')) 