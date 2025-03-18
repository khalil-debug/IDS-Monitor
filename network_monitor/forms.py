from django import forms
from .models import BlockedIP, Agent, DetectionRule

class BlockIPForm(forms.ModelForm):
    """Form for adding a new IP to the block list"""
    class Meta:
        model = BlockedIP
        fields = ['ip_address', 'reason', 'active']
        widgets = {
            'reason': forms.Textarea(attrs={'rows': 3}),
        }

class AgentForm(forms.ModelForm):
    """Form for creating and configuring agents"""
    
    class Meta:
        model = Agent
        fields = [
            'name', 'description', 'platform', 'endpoint_hostname', 
            'endpoint_ip', 'collection_interval', 'enabled'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'endpoint_hostname': forms.TextInput(attrs={'class': 'form-control'}),
            'endpoint_ip': forms.TextInput(attrs={'class': 'form-control'}),
            'collection_interval': forms.NumberInput(attrs={'class': 'form-control'}),
        }
        
    # Add a non-model field for JSON configuration
    config_json = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 10, 'class': 'form-control'}),
        required=False,
        help_text="Advanced configuration in JSON format"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # If we have an instance with config, populate the config_json field
        if self.instance.pk and self.instance.config:
            import json
            self.initial['config_json'] = json.dumps(self.instance.config, indent=2) 

class DetectionRuleForm(forms.ModelForm):
    """Form for creating and editing detection rules"""
    
    class Meta:
        model = DetectionRule
        fields = [
            'name', 'description', 'enabled', 'rule_type', 
            'pattern', 'metric', 'threshold', 'time_window',
            'deviation_factor', 'severity', 'should_alert', 
            'alert_message_template'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'rule_type': forms.Select(attrs={'class': 'form-select'}),
            'pattern': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'metric': forms.TextInput(attrs={'class': 'form-control'}),
            'threshold': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'time_window': forms.NumberInput(attrs={'class': 'form-control'}),
            'deviation_factor': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.1'}),
            'severity': forms.Select(attrs={'class': 'form-select'}),
            'alert_message_template': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        }
    
    baseline_data_json = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 5, 'class': 'form-control'}),
        required=False,
        help_text="JSON object with baseline data for metrics"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Initialize baseline_data_json if we have an instance
        if self.instance.pk and self.instance.baseline_data:
            import json
            self.initial['baseline_data_json'] = json.dumps(self.instance.baseline_data, indent=2)
    
    def clean_baseline_data_json(self):
        """Validate and convert baseline data JSON"""
        json_data = self.cleaned_data.get('baseline_data_json')
        
        if not json_data:
            return None
            
        try:
            import json
            data = json.loads(json_data)
            return data
        except json.JSONDecodeError:
            raise forms.ValidationError("Invalid JSON format")
    
    def clean(self):
        """Validate form based on rule type"""
        cleaned_data = super().clean()
        rule_type = cleaned_data.get('rule_type')
        
        if rule_type == 'signature':
            # Validate signature-specific fields
            if not cleaned_data.get('pattern'):
                self.add_error('pattern', 'Pattern is required for signature-based rules')
                
        elif rule_type == 'threshold':
            # Validate threshold-specific fields
            if not cleaned_data.get('metric'):
                self.add_error('metric', 'Metric is required for threshold-based rules')
            if cleaned_data.get('threshold') is None:
                self.add_error('threshold', 'Threshold is required for threshold-based rules')
                
        elif rule_type == 'anomaly':
            # Validate anomaly-specific fields
            if not cleaned_data.get('baseline_data_json'):
                self.add_error('baseline_data_json', 'Baseline data is required for anomaly-based rules')
            if cleaned_data.get('deviation_factor') is None:
                self.add_error('deviation_factor', 'Deviation factor is required for anomaly-based rules')
                
        return cleaned_data
    
    def save(self, commit=True):
        """Save the form, including JSON data"""
        rule = super().save(commit=False)
        
        if 'baseline_data_json' in self.cleaned_data:
            rule.baseline_data = self.cleaned_data['baseline_data_json']
        
        if commit:
            rule.save()
        
        return rule 

class NotificationSettingsForm(forms.Form):
    """Form for configuring notification settings"""
    
    # General settings
    notification_channels = forms.MultipleChoiceField(
        choices=[
            ('telegram', 'Telegram'),
            ('email', 'Email'),
            ('webhook', 'Webhook')
        ],
        widget=forms.CheckboxSelectMultiple(),
        required=False,
        help_text="Select which notification channels to use"
    )
    
    notify_severity_levels = forms.MultipleChoiceField(
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical')
        ],
        widget=forms.CheckboxSelectMultiple(),
        required=False,
        help_text="Select which severity levels trigger notifications"
    )
    
    # Telegram settings
    telegram_enabled = forms.BooleanField(
        required=False,
        label="Enable Telegram notifications"
    )
    
    telegram_bot_token = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text="Bot token from BotFather"
    )
    
    telegram_chat_id = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text="Chat ID for the bot to send messages to"
    )
    
    # Email settings
    email_enabled = forms.BooleanField(
        required=False,
        label="Enable Email notifications"
    )
    
    email_host = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text="SMTP server hostname"
    )
    
    email_port = forms.IntegerField(
        required=False,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        initial=587,
        help_text="SMTP server port"
    )
    
    email_host_user = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        help_text="SMTP username"
    )
    
    email_host_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        help_text="SMTP password"
    )
    
    email_use_tls = forms.BooleanField(
        required=False,
        initial=True,
        label="Use TLS encryption"
    )
    
    email_recipients = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        help_text="List of email addresses, one per line"
    )
    
    # Webhook settings
    webhook_enabled = forms.BooleanField(
        required=False,
        label="Enable Webhook notifications"
    )
    
    webhook_url = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={'class': 'form-control'}),
        help_text="URL to send webhook notifications to"
    )
    
    # Server URL
    server_url = forms.URLField(
        required=False,
        widget=forms.URLInput(attrs={'class': 'form-control'}),
        help_text="URL of this server for links in notifications (e.g., http://your-ids-server.com)"
    )
    
    # Throttling settings
    max_notifications_per_hour = forms.IntegerField(
        required=False,
        min_value=1,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text="Maximum number of notifications per hour"
    )
    
    throttle_similar_alerts = forms.BooleanField(
        required=False,
        label="Throttle similar alerts"
    )
    
    similar_alert_window = forms.IntegerField(
        required=False,
        min_value=60,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text="Time window in seconds to throttle similar alerts"
    )
    
    def clean_email_recipients(self):
        """Convert email recipients from text to list"""
        recipients = self.cleaned_data.get('email_recipients', '')
        if not recipients:
            return []
        
        # Split by newline and remove empty lines
        return [email.strip() for email in recipients.split('\n') if email.strip()] 