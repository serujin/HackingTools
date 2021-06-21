from django.contrib import admin
from django.conf.urls import url, include
from django.views.generic import RedirectView

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
    url(r'^admin/', admin.site.urls), 
    url(r'^$', RedirectView.as_view(url='home/')),
    url(r'^home/', include('home.urls')),
]
