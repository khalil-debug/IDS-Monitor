from django import template
import json

register = template.Library()

@register.filter(name='add_class')
def add_class(value, arg):
    """Add a CSS class to a form field"""
    return value.as_widget(attrs={'class': arg})

@register.filter(name='pprint')
def pprint_filter(value):
    """Pretty print a JSON object or dictionary"""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return value
    
    if isinstance(value, dict):
        return json.dumps(value, indent=2, sort_keys=True)
    
    return value 