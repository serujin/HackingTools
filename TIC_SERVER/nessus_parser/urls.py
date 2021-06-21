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
    url(r'^$', views.parser, name='parser'),
    url(r'^parse', views.upload_file, name='conversor'), 
    url(r'^download', views.download_file, name='download'),
    url(r'^db_download', views.download_database, name='db_download'),
    url(r'^db_upload', views.load_database, name='db_upload'),
    url(r'^update', views.update_plugin, name='update'),
    url(r'^auth', views.update_auth, name='auth'),
]

handler404 = 'nessus_parser.views.handler404'
handler500 = 'nessus_parser.views.handler500'