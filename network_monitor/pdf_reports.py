import os
import logging
import tempfile
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from .models import NetworkEvent, Alert, BlockedIP

# Configurer le logger
logger = logging.getLogger(__name__)

class SecurityReportGenerator:
    """
    Classe pour générer des rapports de sécurité au format PDF
    """
    def __init__(self, start_date=None, end_date=None, report_type='daily'):
        self.end_date = end_date or timezone.now()
        
        if start_date:
            self.start_date = start_date
        else:
            if report_type == 'daily':
                self.start_date = self.end_date - timedelta(days=1)
            elif report_type == 'weekly':
                self.start_date = self.end_date - timedelta(days=7)
            elif report_type == 'monthly':
                self.start_date = self.end_date - timedelta(days=30)
            else:
                self.start_date = self.end_date - timedelta(days=1)
                
        self.report_type = report_type
        self.styles = getSampleStyleSheet()
        self.report_dir = self._ensure_report_dir()
    
    def _ensure_report_dir(self):
        """Assurer que le répertoire de rapports existe"""
        reports_dir = os.path.join(settings.BASE_DIR, 'reports')
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        return reports_dir
    
    def generate_report(self):
        """Générer le rapport complet"""
        filename = f"security_report_{self.report_type}_{self.end_date.strftime('%Y%m%d')}.pdf"
        filepath = os.path.join(self.report_dir, filename)
        
        # Collecte des données
        self.events = NetworkEvent.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        ).order_by('-timestamp')
        
        self.alerts = Alert.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        ).order_by('-timestamp')
        
        self.blocked_ips = BlockedIP.objects.filter(
            added__gte=self.start_date,
            added__lte=self.end_date
        ).order_by('-added')
        
        # Création des graphiques
        event_type_chart = self._create_event_type_chart()
        severity_chart = self._create_severity_chart()
        timeline_chart = self._create_timeline_chart()
        
        # Préparer le document
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        elements = []
        
        # Le titre et la date
        title_style = ParagraphStyle(
            'TitleStyle', parent=self.styles['Heading1'],
            alignment=TA_CENTER,
            fontSize=18,
            spaceAfter=12
        )
        elements.append(Paragraph(f"Rapport de Sécurité {self.report_type.capitalize()}", title_style))
        elements.append(Paragraph(
            f"Période: {self.start_date.strftime('%d/%m/%Y')} - {self.end_date.strftime('%d/%m/%Y')}",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 0.25*inch))
        
        # Les statistiques
        elements.append(Paragraph("Résumé des Événements de Sécurité", self.styles['Heading2']))
        stats_data = [
            ["Métrique", "Valeur"],
            ["Total des événements", str(self.events.count())],
            ["Menaces détectées", str(self.events.filter(is_threat=True).count())],
            ["Alertes générées", str(self.alerts.count())],
            ["Nouvelles adresses IP bloquées", str(self.blocked_ips.count())],
            ["Événements critiques", str(self.events.filter(severity='critical').count())],
            ["Événements à haute sévérité", str(self.events.filter(severity='high').count())],
        ]
        stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.25*inch))
        
        # Les graphiques
        if event_type_chart:
            elements.append(Paragraph("Distribution des Types d'Événements", self.styles['Heading2']))
            elements.append(Image(event_type_chart, width=6*inch, height=3*inch))
            elements.append(Spacer(1, 0.25*inch))
            
        if severity_chart:
            elements.append(Paragraph("Distribution des Niveaux de Sévérité", self.styles['Heading2']))
            elements.append(Image(severity_chart, width=6*inch, height=3*inch))
            elements.append(Spacer(1, 0.25*inch))
            
        if timeline_chart:
            elements.append(Paragraph("Chronologie des Événements", self.styles['Heading2']))
            elements.append(Image(timeline_chart, width=6*inch, height=3*inch))
            elements.append(Spacer(1, 0.25*inch))
        
        # Top 5 des menaces
        elements.append(Paragraph("Top 5 des Menaces Détectées", self.styles['Heading2']))
        top_threats = self.events.filter(is_threat=True).order_by('-timestamp')[:5]
        if top_threats:
            threat_data = [["Timestamp", "Type", "Source IP", "Sévérité", "Description"]]
            for threat in top_threats:
                threat_data.append([
                    threat.timestamp.strftime('%d/%m/%Y %H:%M:%S'),
                    threat.event_type,
                    threat.source_ip,
                    threat.severity.upper(),
                    threat.description[:50] + ('...' if len(threat.description) > 50 else '')
                ])
            threat_table = Table(threat_data, colWidths=[1.2*inch, 0.8*inch, 1*inch, 0.8*inch, 2.7*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            elements.append(threat_table)
        else:
            elements.append(Paragraph("Aucune menace détectée durant cette période", self.styles['Normal']))
        elements.append(Spacer(1, 0.25*inch))
        
        # IPs bloquées récemment
        elements.append(Paragraph("Adresses IP Bloquées Récemment", self.styles['Heading2']))
        if self.blocked_ips:
            blocked_data = [["IP", "Date de blocage", "Raison"]]
            for ip in self.blocked_ips[:10]:
                blocked_data.append([
                    ip.ip_address,
                    ip.added.strftime('%d/%m/%Y %H:%M:%S'),
                    ip.reason[:50] + ('...' if len(ip.reason) > 50 else '')
                ])
            blocked_table = Table(blocked_data, colWidths=[1.5*inch, 1.5*inch, 3.5*inch])
            blocked_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            elements.append(blocked_table)
        else:
            elements.append(Paragraph("Aucune adresse IP bloquée durant cette période", self.styles['Normal']))
            
        # Recommandations
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph("Recommandations de Sécurité", self.styles['Heading2']))
        
        # Générer des recommandations basées sur les événements
        recommendations = self._generate_recommendations()
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
            
        # Pied de page
        elements.append(Spacer(1, 0.5*inch))
        footer_text = f"Rapport généré le {timezone.now().strftime('%d/%m/%Y à %H:%M:%S')} par le Système IDS Monitoring"
        elements.append(Paragraph(footer_text, self.styles['Italic']))
        
        elements.append(Spacer(1, 0.5*inch))
        watermark_text = "Généré par Khalil Trigui (@khalil-debug)"
        elements.append(Paragraph(watermark_text, self.styles['Italic']))
        
        doc.build(elements)
        logger.info(f"Rapport généré avec succès: {filepath}")
        
        return filepath
    
    def _create_event_type_chart(self):
        """Créer un graphique montrant la distribution des types d'événements"""
        if not self.events.exists():
            return None
            
        event_types = {}
        for event in self.events:
            if event.event_type in event_types:
                event_types[event.event_type] += 1
            else:
                event_types[event.event_type] = 1
                
        # Créer un DataFrame pandas
        df = pd.DataFrame(list(event_types.items()), columns=['Type', 'Count'])
        
        # Créer le graphique
        plt.figure(figsize=(8, 6))
        plt.pie(df['Count'], labels=df['Type'], autopct='%1.1f%%', startangle=90)
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.title('Distribution des Types d\'Événements')
        
        # Sauvegarder l'image
        img_path = os.path.join(tempfile.gettempdir(), 'event_type_chart.png')
        plt.savefig(img_path, format='png')
        plt.close()
        
        return img_path
    
    def _create_severity_chart(self):
        """Créer un graphique montrant la distribution des niveaux de sévérité"""
        if not self.events.exists():
            return None
            
        severities = {}
        for event in self.events:
            if event.severity in severities:
                severities[event.severity] += 1
            else:
                severities[event.severity] = 1
                
        # Créer un DataFrame pandas
        df = pd.DataFrame(list(severities.items()), columns=['Severity', 'Count'])
        
        # Définir les couleurs en fonction de la sévérité
        colors = {
            'low': '#4CAF50',      # Green
            'medium': '#FF9800',   # Orange
            'high': '#F44336',     # Red
            'critical': '#B71C1C'  # Dark red
        }
        
        # Ordonner par sévérité
        severity_order = ['low', 'medium', 'high', 'critical']
        df['Severity'] = pd.Categorical(df['Severity'], categories=severity_order, ordered=True)
        df = df.sort_values('Severity')
        
        # Créer le graphique
        plt.figure(figsize=(8, 6))
        bars = plt.bar(df['Severity'], df['Count'])
        
        # Appliquer les couleurs
        for bar, severity in zip(bars, df['Severity']):
            bar.set_color(colors.get(severity, '#607D8B'))  # Default to blue-grey
            
        plt.title('Distribution des Niveaux de Sévérité')
        plt.xlabel('Niveau de Sévérité')
        plt.ylabel('Nombre d\'Événements')
        
        # Sauvegarder l'image
        img_path = os.path.join(tempfile.gettempdir(), 'severity_chart.png')
        plt.savefig(img_path, format='png')
        plt.close()
        
        return img_path
    
    def _create_timeline_chart(self):
        """Créer un graphique montrant la chronologie des événements"""
        if not self.events.exists():
            return None
            
        # Extraire les timestamps et les convertir en datetime pandas
        timestamps = [event.timestamp for event in self.events]
        dates = pd.to_datetime([ts.strftime('%Y-%m-%d %H:%M:%S') for ts in timestamps])
        
        # Regrouper par intervalle de temps approprié selon le type de rapport
        if self.report_type == 'daily':
            # Regrouper par heure
            freq = 'H'
            xlabel = 'Heure'
        elif self.report_type == 'weekly':
            # Regrouper par jour
            freq = 'D'
            xlabel = 'Jour'
        else:  # mensuel
            # Regrouper par jour
            freq = 'D'
            xlabel = 'Date'
            
        # Compter les événements par intervalle
        events_count = pd.Series(np.ones(len(dates)), index=dates).resample(freq).sum().fillna(0)
        
        # Créer le graphique
        plt.figure(figsize=(10, 5))
        plt.plot(events_count.index, events_count.values, marker='o')
        plt.title('Chronologie des Événements de Sécurité')
        plt.xlabel(xlabel)
        plt.ylabel('Nombre d\'Événements')
        plt.grid(True)
        plt.tight_layout()
        
        # Sauvegarder l'image
        img_path = os.path.join(tempfile.gettempdir(), 'timeline_chart.png')
        plt.savefig(img_path, format='png')
        plt.close()
        
        return img_path
    
    def _generate_recommendations(self):
        """
        Générer des recommandations de sécurité basées sur les types d'événements détectés
        """
        recommendations = []
        
        # Vérifier les types d'événements pour générer des recommandations pertinentes
        event_types = set(self.events.values_list('event_type', flat=True))
        
        if 'port_scan' in event_types:
            recommendations.append(
                "Détection de scans de ports: Configurez votre pare-feu pour limiter la visibilité des ports non utilisés et envisagez l'utilisation d'un système IPS pour bloquer automatiquement les scans répétés."
            )
            
        if 'ddos' in event_types:
            recommendations.append(
                "Détection de tentatives de DDoS: Implémentez des solutions de limitation de débit pour réduire l'impact des attaques DDoS et envisagez un service de protection DDoS auprès de votre fournisseur."
            )
            
        if 'brute_force' in event_types:
            recommendations.append(
                "Tentatives de brute-force détectées: Activez l'authentification à deux facteurs sur tous les services exposés et implémentez des politiques de verrouillage de compte après plusieurs échecs consécutifs."
            )
            
        if 'suspicious_packet' in event_types:
            recommendations.append(
                "Paquets suspects détectés: Examinez la configuration de vos services réseau et mettez à jour vos règles de filtrage pour bloquer les modèles de trafic anormaux."
            )
            
        # Ajouter des recommandations générales
        if self.events.filter(severity__in=['high', 'critical']).exists():
            recommendations.append(
                "Des événements à haute sévérité ont été détectés. Réalisez un audit de sécurité approfondi et appliquez les correctifs de sécurité les plus récents."
            )
            
        # Compléter avec des recommandations générales si nécessaire
        if not recommendations:
            recommendations.append(
                "Maintenez vos systèmes à jour avec les derniers correctifs de sécurité et continuez la surveillance des événements de sécurité."
            )
            
        recommendations.append(
            "Effectuez régulièrement des tests de pénétration et des évaluations de vulnérabilité pour identifier et corriger les faiblesses avant qu'elles ne soient exploitées."
        )
        
        return recommendations

# Fonction utilitaire pour générer un rapport depuis une commande ou une vue
def generate_security_report(report_type='daily', start_date=None, end_date=None):
    """
    Fonction utilitaire pour générer un rapport de sécurité
    
    Args:
        report_type: 'daily', 'weekly', or 'monthly'
        start_date: date de début optionnelle (datetime)
        end_date: date de fin optionnelle (datetime)
        
    Returns:
        Le chemin du fichier PDF généré
    """
    generator = SecurityReportGenerator(
        start_date=start_date,
        end_date=end_date,
        report_type=report_type
    )
    return generator.generate_report() 