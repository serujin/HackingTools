from django.conf.urls import url, include
from . import views

####################################################
#  File: urls.py                                   #
#                                                  #
#  This file is used to map, name and define urls  #
####################################################

# The format to map an url is:
#    url(REGEX, views.METHOD_NAME, name="DESIRED_NAME")
#    the DESIRED_NAME is used to call the functions on the html templates

urlpatterns = [
    # Examples:
    # url(r'^blog/', include('blog.urls', namespace='blog')),
    url(r'^$', views.index, name='index'),
    url(r'^parser/', include('nessus_parser.urls')),
]