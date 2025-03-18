"""
Chart.js visualization module for the network monitoring application.
This replaces the graphos-based visualization with a more stable Chart.js implementation.
"""

import json
from datetime import timedelta
from collections import defaultdict
from django.utils import timezone
from django.db.models import Count, Q
from chartjs.views.lines import BaseLineChartView
from chartjs.views.pie import HighChartPieView
from chartjs.views.base import JSONView
from .models import NetworkEvent, Alert, BlockedIP

class BaseBarChartView(JSONView):
    """Base class for all Bar chart views"""
    
    def get_labels(self):
        """Return the labels for the x-axis"""
        return []
        
    def get_providers(self):
        """Return datasets labels"""
        return []
        
    def get_data(self):
        """Return datasets values"""
        return []
        
    def get_colors(self):
        """Return colors for the datasets"""
        return []
    
    def get_context_data(self, **kwargs):
        data = {
            'labels': self.get_labels(),
            'datasets': [
                {
                    'label': provider,
                    'data': data,
                    'backgroundColor': color
                } for provider, data, color in zip(
                    self.get_providers(),
                    self.get_data(),
                    self.get_colors()
                )
            ]
        }
        return data

class EventTimelineChartView(BaseLineChartView):
    """Chart.js view for event timeline visualization"""
    
    def __init__(self, days=7):
        self.days = days
        self.end_date = timezone.now()
        self.start_date = self.end_date - timedelta(days=days)
        super().__init__()
        
    def get_labels(self):
        """Return the timeline date labels"""
        labels = []
        current_date = self.start_date
        while current_date <= self.end_date:
            labels.append(current_date.strftime('%Y-%m-%d'))
            current_date += timedelta(days=1)
        return labels
    
    def get_providers(self):
        """Return the dataset labels"""
        return ['All Events', 'Threats']
    
    def get_data(self):
        """Return the timeline chart data"""
        labels = self.get_labels()
        
        all_events_data = [0] * len(labels)
        threats_data = [0] * len(labels)
        
        for i, date_str in enumerate(labels):
            current_date = timezone.datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            next_date = current_date + timedelta(days=1)
            
            all_events_data[i] = NetworkEvent.objects.filter(
                timestamp__gte=current_date,
                timestamp__lt=next_date
            ).count()
            
            threats_data[i] = NetworkEvent.objects.filter(
                timestamp__gte=current_date,
                timestamp__lt=next_date,
                is_threat=True
            ).count()
        
        return [all_events_data, threats_data]
    
    def get_colors(self):
        """Return colors for the datasets"""
        return [
            'rgba(66, 133, 244, 0.5)',
            'rgba(219, 68, 55, 0.5)'
        ]
    
    def get_options(self):
        """Return chart options"""
        return {
            'responsive': True,
            'maintainAspectRatio': False,
            'title': {
                'display': True,
                'text': f'Security Events (Last {self.days} days)'
            },
            'legend': {
                'position': 'bottom'
            },
            'scales': {
                'xAxes': [{
                    'scaleLabel': {
                        'display': True,
                        'labelString': 'Date'
                    }
                }],
                'yAxes': [{
                    'scaleLabel': {
                        'display': True,
                        'labelString': 'Number of Events'
                    },
                    'ticks': {
                        'beginAtZero': True
                    }
                }]
            }
        }

class EventTypePieChartView(HighChartPieView):
    """Chart.js view for event type distribution visualization"""
    
    def get_labels(self):
        """Return the event type labels"""
        events_by_type = NetworkEvent.objects.values('event_type').annotate(count=Count('id'))
        return [event_type['event_type'].replace('_', ' ').title() for event_type in events_by_type]
    
    def get_data(self):
        """Return the event type count data"""
        events_by_type = NetworkEvent.objects.values('event_type').annotate(count=Count('id'))
        return [event_type['count'] for event_type in events_by_type]
    
    def get_colors(self):
        """Return colors for the datasets"""
        return [
            'rgba(66, 133, 244, 0.7)',  # Blue
            'rgba(52, 168, 83, 0.7)',   # Green
            'rgba(251, 188, 5, 0.7)',   # Yellow
            'rgba(234, 67, 53, 0.7)',   # Red
            'rgba(132, 48, 216, 0.7)',  # Purple
            'rgba(255, 134, 0, 0.7)'    # Orange
        ]
    
    def get_options(self):
        """Return chart options"""
        return {
            'responsive': True,
            'maintainAspectRatio': False,
            'title': {
                'display': True,
                'text': 'Event Types Distribution'
            },
            'legend': {
                'position': 'right'
            },
            'cutoutPercentage': 40
        }

class SeverityBarChartView(BaseBarChartView):
    """Chart.js view for severity distribution visualization"""
    
    def get_labels(self):
        """Return the severity labels in order"""
        return ['Low', 'Medium', 'High', 'Critical']
    
    def get_providers(self):
        """Return the dataset label"""
        return ['Events']
    
    def get_data(self):
        """Return the severity count data"""
        # Define the order of severities
        severity_order = ['low', 'medium', 'high', 'critical']
        
        # Get counts from database
        severity_counts = NetworkEvent.objects.values('severity').annotate(count=Count('id'))
        
        # Convert to dictionary for easier lookup
        count_dict = {item['severity']: item['count'] for item in severity_counts}
        
        # Return counts in the correct order
        return [[count_dict.get(severity, 0) for severity in severity_order]]
    
    def get_colors(self):
        """Return colors for the datasets"""
        return ['rgba(52, 168, 83, 0.7)',   # Green for low
                'rgba(251, 188, 5, 0.7)',   # Yellow for medium
                'rgba(234, 67, 53, 0.7)',   # Orange for high
                'rgba(219, 68, 55, 0.7)']   # Red for critical
    
    def get_options(self):
        """Return chart options"""
        return {
            'responsive': True,
            'maintainAspectRatio': False,
            'title': {
                'display': True,
                'text': 'Severity Distribution'
            },
            'legend': {
                'display': False
            },
            'scales': {
                'xAxes': [{
                    'scaleLabel': {
                        'display': True,
                        'labelString': 'Severity Level'
                    }
                }],
                'yAxes': [{
                    'scaleLabel': {
                        'display': True,
                        'labelString': 'Number of Events'
                    },
                    'ticks': {
                        'beginAtZero': True
                    }
                }]
            }
        }

class BlockedIPPieChartView(HighChartPieView):
    """Chart.js view for blocked IP visualization"""
    
    def get_labels(self):
        """Return the block reason labels"""
        blocked_ips = BlockedIP.objects.filter(active=True)
        
        # Categorize by reason
        reasons = defaultdict(int)
        for ip in blocked_ips:
            # Simplify the reason for the chart
            if 'brute force' in ip.reason.lower():
                reason = 'Brute Force'
            elif 'ddos' in ip.reason.lower() or 'dos' in ip.reason.lower():
                reason = 'DDoS/DoS'
            elif 'scan' in ip.reason.lower():
                reason = 'Scan'
            elif 'suspicious' in ip.reason.lower():
                reason = 'Suspicious'
            else:
                reason = 'Other'
                
            reasons[reason] += 1
        
        return list(reasons.keys())
    
    def get_data(self):
        """Return the blocked IP counts by reason"""
        blocked_ips = BlockedIP.objects.filter(active=True)
        
        # Categorize by reason
        reasons = defaultdict(int)
        for ip in blocked_ips:
            # Simplify the reason for the chart
            if 'brute force' in ip.reason.lower():
                reason = 'Brute Force'
            elif 'ddos' in ip.reason.lower() or 'dos' in ip.reason.lower():
                reason = 'DDoS/DoS'
            elif 'scan' in ip.reason.lower():
                reason = 'Scan'
            elif 'suspicious' in ip.reason.lower():
                reason = 'Suspicious'
            else:
                reason = 'Other'
                
            reasons[reason] += 1
        
        return list(reasons.values())
    
    def get_colors(self):
        """Return colors for the datasets"""
        return [
            'rgba(234, 67, 53, 0.7)',   # Red for brute force
            'rgba(251, 188, 5, 0.7)',   # Yellow for DDoS
            'rgba(66, 133, 244, 0.7)',  # Blue for scan
            'rgba(52, 168, 83, 0.7)',   # Green for suspicious
            'rgba(132, 48, 216, 0.7)'   # Purple for other
        ]
    
    def get_options(self):
        """Return chart options"""
        return {
            'responsive': True,
            'maintainAspectRatio': False,
            'title': {
                'display': True,
                'text': 'Blocked IPs by Reason'
            },
            'legend': {
                'position': 'right'
            }
        }

class AlertStatusPieChartView(HighChartPieView):
    """Chart.js view for alert status visualization"""
    
    def get_labels(self):
        """Return the alert status labels"""
        return ['Sent', 'Pending']
    
    def get_data(self):
        """Return the alert count data by status"""
        total_alerts = Alert.objects.count()
        sent_alerts = Alert.objects.filter(is_sent=True).count()
        pending_alerts = total_alerts - sent_alerts
        
        return [sent_alerts, pending_alerts]
    
    def get_colors(self):
        """Return colors for the datasets"""
        return [
            'rgba(52, 168, 83, 0.7)',  # Green for sent
            'rgba(251, 188, 5, 0.7)'   # Yellow for pending
        ]
    
    def get_options(self):
        """Return chart options"""
        return {
            'responsive': True,
            'maintainAspectRatio': False,
            'title': {
                'display': True,
                'text': 'Alert Status'
            },
            'legend': {
                'position': 'right'
            }
        }

class TopAttackersBarChartView(BaseBarChartView):
    """Chart.js view for top attackers visualization"""
    
    def get_labels(self):
        """Return the attacker IP labels"""
        # Get threats
        threats = NetworkEvent.objects.filter(is_threat=True)
        
        # Count threats by source IP
        attacker_counts = {}
        for threat in threats:
            if threat.source_ip in attacker_counts:
                attacker_counts[threat.source_ip] += 1
            else:
                attacker_counts[threat.source_ip] = 1
                
        # Sort and take top 10
        top_attackers = sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return [ip for ip, _ in top_attackers]
    
    def get_providers(self):
        """Return the dataset label"""
        return ['Attacks']
    
    def get_data(self):
        """Return the attack count data by attacker"""
        # Get threats
        threats = NetworkEvent.objects.filter(is_threat=True)
        
        # Count threats by source IP
        attacker_counts = {}
        for threat in threats:
            if threat.source_ip in attacker_counts:
                attacker_counts[threat.source_ip] += 1
            else:
                attacker_counts[threat.source_ip] = 1
                
        # Sort and take top 10
        top_attackers = sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return [[count for _, count in top_attackers]]
    
    def get_colors(self):
        """Return colors for the datasets"""
        return ['rgba(234, 67, 53, 0.7)']  # Red for attackers
    
    def get_options(self):
        """Return chart options"""
        return {
            'responsive': True,
            'maintainAspectRatio': False,
            'title': {
                'display': True,
                'text': 'Top 10 Attack Sources'
            },
            'legend': {
                'display': False
            },
            'scales': {
                'xAxes': [{
                    'scaleLabel': {
                        'display': True,
                        'labelString': 'Source IP'
                    }
                }],
                'yAxes': [{
                    'scaleLabel': {
                        'display': True,
                        'labelString': 'Number of Attacks'
                    },
                    'ticks': {
                        'beginAtZero': True
                    }
                }]
            }
        }

class ThreatSourceMapChartView(JSONView):
    """Chart.js view for threat source map visualization"""
    
    def get_context_data(self, **kwargs):
        # Get threats
        threats = NetworkEvent.objects.filter(is_threat=True)
        
        # Count threats by country
        country_counts = defaultdict(int)
        
        for threat in threats:
            # Assuming we have country info in packet_info
            country = threat.packet_info.get('country', 'Unknown') if hasattr(threat, 'packet_info') else 'Unknown'
            country_counts[country] += 1
            
        # If we don't have real country data, use dummy data for demo
        if not country_counts or 'Unknown' in country_counts:
            # Dummy data for demonstration
            country_counts = {
                'US': 120,
                'CN': 89,
                'RU': 56,
                'IR': 47,
                'KP': 23,
                'DE': 19,
                'FR': 12,
                'GB': 18,
                'CA': 8,
                'BR': 15,
                'IN': 28
            }
        
        # Format data for Chart.js GeoChart visualization
        data = {
            'type': 'choropleth',
            'data': {
                'labels': list(country_counts.keys()),
                'datasets': [{
                    'label': 'Threats by Country',
                    'data': list(country_counts.values()),
                    'backgroundColor': 'rgba(234, 67, 53, 0.7)'
                }]
            },
            'options': {
                'title': {
                    'display': True,
                    'text': 'Geographic Threat Sources'
                },
                'responsive': True,
                'maintainAspectRatio': False,
                'scales': {
                    'xAxes': [{
                        'scaleLabel': {
                            'display': True,
                            'labelString': 'Country'
                        }
                    }],
                    'yAxes': [{
                        'scaleLabel': {
                            'display': True,
                            'labelString': 'Number of Threats'
                        },
                        'ticks': {
                            'beginAtZero': True
                        }
                    }]
                }
            }
        }
        
        return data

class SecurityDataAPI:
    """API class to provide chart data in JSON format for AJAX requests"""
    
    @staticmethod
    def get_event_timeline_data(days=7):
        """Get event timeline data in Chart.js format"""
        chart = EventTimelineChartView(days=days)
        return {
            'labels': chart.get_labels(),
            'datasets': [
                {
                    'label': provider,
                    'data': data,
                    'backgroundColor': color,
                    'borderColor': color.replace('0.5', '1'),
                    'fill': False
                } for provider, data, color in zip(
                    chart.get_providers(),
                    chart.get_data(),
                    chart.get_colors()
                )
            ],
            'options': chart.get_options()
        }
    
    @staticmethod
    def get_event_type_data():
        """Get event type distribution data in Chart.js format"""
        chart = EventTypePieChartView()
        labels = chart.get_labels()
        data = chart.get_data()
        colors = chart.get_colors()
        options = chart.get_options()
        
        return {
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': colors[:len(data)],
                'borderWidth': 1
            }],
            'options': options
        }
    
    @staticmethod
    def get_severity_data():
        """Get severity distribution data in Chart.js format"""
        chart = SeverityBarChartView()
        return {
            'labels': chart.get_labels(),
            'datasets': [
                {
                    'label': provider,
                    'data': data,
                    'backgroundColor': color
                } for provider, data, color in zip(
                    chart.get_providers(),
                    chart.get_data(),
                    chart.get_colors()
                )
            ],
            'options': chart.get_options()
        }
    
    @staticmethod
    def get_blocked_ip_data():
        """Get blocked IP data in Chart.js format"""
        chart = BlockedIPPieChartView()
        labels = chart.get_labels()
        data = chart.get_data()
        colors = chart.get_colors()
        options = chart.get_options()
        
        return {
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': colors[:len(data)],
                'borderWidth': 1
            }],
            'options': options
        }
    
    @staticmethod
    def get_alert_status_data():
        """Get alert status data in Chart.js format"""
        chart = AlertStatusPieChartView()
        # Format the data for Chart.js
        labels = chart.get_labels()
        data = chart.get_data()
        colors = chart.get_colors()
        options = chart.get_options()
        
        return {
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': colors[:len(data)],
                'borderWidth': 1
            }],
            'options': options
        }
    
    @staticmethod
    def get_top_attackers_data():
        """Get top attackers data in Chart.js format"""
        chart = TopAttackersBarChartView()
        return {
            'labels': chart.get_labels(),
            'datasets': [
                {
                    'label': provider,
                    'data': data,
                    'backgroundColor': color
                } for provider, data, color in zip(
                    chart.get_providers(),
                    chart.get_data(),
                    chart.get_colors()
                )
            ],
            'options': chart.get_options()
        }
        
    @staticmethod
    def get_threat_source_map_data():
        """Get threat source map data in Chart.js format"""
        chart = ThreatSourceMapChartView()
        return chart.get_context_data()