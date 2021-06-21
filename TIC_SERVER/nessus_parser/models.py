from django.db import models
from django.utils import timezone

###################################################
#  File: models.py                                #
#                                                 #
#  This file is used to hold all database tables  #
###################################################

#################################################
#  Class: Plugin                                #
#  Used for: define the plugins database table  #
#################################################

class Plugin(models.Model):
    PLUGIN_TYPES = [
        ('NaN', 'Not classified'),
        ('OSP', 'Operative System Patch'),
        ('C', 'Config'),
        ('CY', 'Cypher'),
        ('PV', 'Product Vulnerability'),
        ('OOS', 'Out of Support')
    ]
    plugin_id = models.IntegerField(primary_key=True)
    plugin_name = models.CharField(max_length=200)  
    plugin_category = models.CharField(max_length=3, choices=PLUGIN_TYPES, default=PLUGIN_TYPES[0])

#########################################################
#  Class: Vulnerability                                 #
#  Used for: define the vulnerabilities database table  #
#########################################################

class Vulnerability(models.Model):
    vuln_type = models.CharField(max_length=5)
    app_name = models.CharField(max_length=20)
    vuln_risk = models.CharField(max_length=1)
    year = models.IntegerField(default=timezone.now().year)
    number = models.IntegerField()
    plugin_name = models.CharField(max_length=75)
    date = models.DateField(default=timezone.now)