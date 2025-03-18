from django.contrib import admin
from .models import NetworkEvent, Alert, BlockedIP

@admin.register(NetworkEvent)
class NetworkEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'source_ip', 'destination_ip', 'protocol', 'severity', 'is_threat')
    list_filter = ('event_type', 'severity', 'protocol', 'is_threat', 'timestamp')
    search_fields = ('source_ip', 'destination_ip', 'description')
    readonly_fields = ('timestamp',)
    fieldsets = (
        ('Basic Information', {
            'fields': ('timestamp', 'event_type', 'severity', 'description', 'is_threat')
        }),
        ('Network Details', {
            'fields': ('source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol')
        }),
        ('Advanced', {
            'fields': ('packet_info',),
            'classes': ('collapse',)
        }),
    )

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'get_event_type', 'get_severity', 'is_sent', 'sent_timestamp')
    list_filter = ('is_sent', 'timestamp', 'event__event_type', 'event__severity')
    search_fields = ('message', 'event__source_ip', 'event__destination_ip')
    readonly_fields = ('timestamp',)
    
    def get_event_type(self, obj):
        return obj.event.event_type
    get_event_type.short_description = 'Event Type'
    get_event_type.admin_order_field = 'event__event_type'
    
    def get_severity(self, obj):
        return obj.event.severity
    get_severity.short_description = 'Severity'
    get_severity.admin_order_field = 'event__severity'

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'added', 'active')
    list_filter = ('active', 'added')
    search_fields = ('ip_address', 'reason')
    readonly_fields = ('added',)
