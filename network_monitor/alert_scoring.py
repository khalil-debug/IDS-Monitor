"""
Module pour évaluer et scorer les alertes de sécurité selon les recommandations NIST.

Basé sur les concepts du NIST Special Publication 800-61 pour la gestion des incidents de sécurité.
"""

import math
import logging
from django.utils import timezone
from .models import NetworkEvent, Alert

logger = logging.getLogger(__name__)

class NISTAlertScorer:
    """
    Classe pour calculer le score de sévérité des alertes selon les recommandations NIST
    
    Utilise un modèle multi-facteurs évaluant:
    1. Impact fonctionnel
    2. Impact sur les informations
    3. Facilité de récupération
    4. Coordonnées d'impact (temps et espace)
    """
    
    # Classification des types d'événements par impact fonctionnel (échelle 0-100)
    FUNCTIONAL_IMPACT = {
        'port_scan': 30,            # Impact limité
        'suspicious_packet': 40,    # Impact modéré
        'brute_force': 70,          # Impact significatif
        'ddos': 90,                 # Impact élevé
        'connection': 10,           # Impact minimal
        'other': 50                 # Impact inconnu
    }
    
    # Classification par impact sur les informations (échelle 0-100)
    INFORMATION_IMPACT = {
        'port_scan': 20,            # Divulgation minimale
        'suspicious_packet': 30,    # Divulgation limitée
        'brute_force': 80,          # Divulgation potentiellement significative
        'ddos': 30,                 # Divulgation limitée
        'connection': 10,           # Aucune divulgation
        'other': 40                 # Divulgation incertaine
    }
    
    # Classification par facilité de récupération (échelle 0-100, plus le nombre est élevé, plus c'est difficile)
    RECOVERABILITY = {
        'port_scan': 10,            # Récupération simple
        'suspicious_packet': 20,    # Récupération facile
        'brute_force': 60,          # Récupération modérée
        'ddos': 70,                 # Récupération difficile
        'connection': 5,            # Récupération immédiate
        'other': 40                 # Récupération incertaine
    }
    
    # Multiplicateurs de sévérité basés sur les sévérités définies dans le modèle
    SEVERITY_MULTIPLIER = {
        'low': 0.5,
        'medium': 1.0,
        'high': 1.5,
        'critical': 2.0
    }
    
    def __init__(self):
        self.weights = {
            'functional_impact': 0.35,    # 35% du score
            'information_impact': 0.25,   # 25% du score
            'recoverability': 0.15,       # 15% du score
            'time': 0.15,                 # 15% du score
            'scope': 0.10                 # 10% du score
        }
    
    def score_event(self, event):
        """
        Calcule le score NIST pour un événement de sécurité
        
        Args:
            event: Objet NetworkEvent à scorer
            
        Returns:
            dict: Dictionnaire contenant le score global et les sous-scores
        """
        try:
            # Récupérer les scores de base
            functional_impact = self.FUNCTIONAL_IMPACT.get(event.event_type, 50)
            information_impact = self.INFORMATION_IMPACT.get(event.event_type, 40)
            recoverability = self.RECOVERABILITY.get(event.event_type, 40)
            
            # Facteur temporel: événements plus récents sont plus critiques
            time_factor = self._calculate_time_factor(event.timestamp)
            
            # Facteur de portée: détermine si l'événement est isolé ou part d'une attaque plus large
            scope_factor = self._calculate_scope_factor(event)
            
            # Appliquer le multiplicateur de sévérité
            severity_multiplier = self.SEVERITY_MULTIPLIER.get(event.severity, 1.0)
            
            # Calculer les sous-scores pondérés
            weighted_functional = functional_impact * self.weights['functional_impact']
            weighted_information = information_impact * self.weights['information_impact']
            weighted_recovery = recoverability * self.weights['recoverability']
            weighted_time = time_factor * self.weights['time'] * 100  # Normaliser à l'échelle 0-100
            weighted_scope = scope_factor * self.weights['scope'] * 100  # Normaliser à l'échelle 0-100
            
            # Calculer le score total
            base_score = (weighted_functional + weighted_information + 
                         weighted_recovery + weighted_time + weighted_scope)
            
            # Appliquer le multiplicateur de sévérité
            final_score = base_score * severity_multiplier
            
            # Limiter le score à 100
            final_score = min(100, final_score)
            
            # Arrondir à un entier
            final_score = round(final_score)
            
            return {
                'score': final_score,
                'category': self._get_score_category(final_score),
                'components': {
                    'functional_impact': functional_impact,
                    'information_impact': information_impact,
                    'recoverability': recoverability,
                    'time_factor': time_factor * 100,  # Normaliser pour l'affichage
                    'scope_factor': scope_factor * 100,  # Normaliser pour l'affichage
                    'severity_multiplier': severity_multiplier
                }
            }
        except Exception as e:
            logger.error(f"Erreur lors du calcul du score: {e}")
            return {
                'score': 50,  # Score par défaut
                'category': 'Medium',
                'components': {},
                'error': str(e)
            }
    
    def _calculate_time_factor(self, timestamp):
        """Calcule le facteur temporel (0-1) basé sur la fraîcheur de l'événement"""
        now = timezone.now()
        delta = now - timestamp
        hours = delta.total_seconds() / 3600
        
        # Fonction de décroissance exponentielle pour le facteur temps
        # Les événements plus récents ont un facteur plus élevé
        # Un événement vieux de 24h aura un facteur d'environ 0.37
        # Un événement vieux de 48h aura un facteur d'environ 0.14
        return math.exp(-hours / 24)
    
    def _calculate_scope_factor(self, event):
        """Calcule le facteur de portée (0-1) basé sur l'étendue de l'attaque"""
        # Vérifier le nombre d'événements similaires récents de la même source
        one_hour_ago = timezone.now() - timezone.timedelta(hours=1)
        similar_events = NetworkEvent.objects.filter(
            source_ip=event.source_ip,
            event_type=event.event_type,
            timestamp__gte=one_hour_ago
        ).count()
        
        # Plus il y a d'événements similaires, plus le facteur de portée est élevé
        # Utiliser une fonction logarithmique pour limiter l'effet des grands nombres
        if similar_events > 0:
            return min(0.9, 0.2 + 0.3 * math.log10(similar_events))
        else:
            return 0.2  # Valeur de base pour un événement isolé
    
    def _get_score_category(self, score):
        """Convertit un score numérique en catégorie"""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Informational"

def score_alerts(recent_only=True, update_db=True):
    """
    Score all alerts or only recent ones
    
    Args:
        recent_only: Si True, ne score que les alertes des dernières 24h
        update_db: Si True, met à jour le score dans la base de données
        
    Returns:
        dict: Résumé des scores par catégorie
    """
    scorer = NISTAlertScorer()
    
    # Définir le filtre pour les alertes
    if recent_only:
        one_day_ago = timezone.now() - timezone.timedelta(days=1)
        alerts = Alert.objects.filter(timestamp__gte=one_day_ago)
    else:
        alerts = Alert.objects.all()
    
    # Compteurs pour les statistiques
    stats = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Informational': 0,
        'total': 0
    }
    
    # Traiter chaque alerte
    for alert in alerts:
        # Calculer le score
        score_data = scorer.score_event(alert.event)
        
        # Mettre à jour les stats
        category = score_data['category']
        stats[category] += 1
        stats['total'] += 1
        
        # Mettre à jour la base de données si demandé
        if update_db:
            # On suppose qu'un JSONField 'score_data' existe dans le modèle Alert
            # Si ce n'est pas le cas, il faudra modifier le modèle
            try:
                if not hasattr(alert, 'score_data') or not isinstance(alert.score_data, dict):
                    alert.score_data = {}
                alert.score_data['nist_score'] = score_data
                alert.save(update_fields=['score_data'])
            except Exception as e:
                logger.error(f"Erreur lors de la mise à jour du score pour l'alerte {alert.id}: {e}")
    
    return stats 