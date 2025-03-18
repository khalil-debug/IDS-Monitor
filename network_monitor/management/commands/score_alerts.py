from django.core.management.base import BaseCommand
from network_monitor.alert_scoring import score_alerts

class Command(BaseCommand):
    help = 'Calcule et applique les scores NIST à toutes les alertes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--recent-only',
            action='store_true',
            help='Ne traiter que les alertes des dernières 24 heures'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Calculer les scores sans mettre à jour la base de données'
        )

    def handle(self, *args, **options):
        recent_only = options.get('recent_only', False)
        dry_run = options.get('dry_run', False)
        
        self.stdout.write(self.style.SUCCESS(
            f"Calcul des scores NIST pour {'les alertes récentes' if recent_only else 'toutes les alertes'}"
        ))
        
        # Calculer et appliquer les scores
        stats = score_alerts(
            recent_only=recent_only,
            update_db=not dry_run
        )
        
        # Afficher les statistiques
        self.stdout.write("\nRésultats du scoring:")
        self.stdout.write("-" * 40)
        self.stdout.write(f"Total des alertes traitées: {stats['total']}")
        
        if stats['total'] > 0:
            self.stdout.write("\nDistribution par catégorie:")
            for category in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                count = stats.get(category, 0)
                percentage = (count / stats['total']) * 100 if stats['total'] > 0 else 0
                self.stdout.write(f"{category}: {count} ({percentage:.1f}%)")
                
        if dry_run:
            self.stdout.write(self.style.WARNING("\nMode dry-run: aucune modification n'a été appliquée à la base de données")) 