from django.contrib import admin
from .models import Plugin, Vulnerability

# Register your models here.
admin.site.register(Plugin)
admin.site.register(Vulnerability)