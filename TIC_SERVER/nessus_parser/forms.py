from nessus_parser.models import Plugin
from django import forms
from django.core.validators import RegexValidator

################################################
#  File: forms.py                              #
#                                              #
#  This file is used to hold all django forms  #
################################################

#######################################
#  Class: UploadFileForm              #
#  Used for: upload the .nessus file  #
#######################################

class UploadFileForm(forms.Form):
    file_name = forms.CharField(label='', validators=[RegexValidator('^[A-Za-z0-9-_]*$')], widget=forms.TextInput(attrs={
        'class': 'form-control',
        'placeholder': 'Nombre del fichero a generar (sin extensión)',
        'required': True
    }))
    files = forms.FileField(label='', allow_empty_file=False, widget=forms.ClearableFileInput(attrs={
        'class': 'form-control',
        'accept': '.nessus',
        'required': True,
        'multiple': True
    }))

###################################################
#  Class: PluginForm                              #
#  Used for: show/update plugins on plugins page  #
###################################################

class PluginForm(forms.ModelForm):
    class Meta:
        model = Plugin
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(PluginForm, self).__init__(*args, **kwargs)
        self.fields['plugin_id'].widget.attrs['readonly'] = True
        self.fields['plugin_name'].widget.attrs['readonly'] = True
        self.fields['plugin_id'].widget.attrs['class'] = 'input-group-text col-1'
        self.fields['plugin_name'].widget.attrs['class'] = 'input-group-text col-8'
        self.fields['plugin_category'].widget.attrs['class'] = 'category form-select col-3'
        self.fields['plugin_category'].widget.attrs[
            'onchange'] = 'update_plugin(this)'
        for key in self.fields:
            self.fields[key].label = ''
            self.fields[key].widget.attrs['style'] = 'display: inherit;'

##############################################
#  Class: UploadDBForm                       #
#  Used for: upload the .json database file  #
##############################################

class UploadDBForm(forms.Form):
    db_files = forms.FileField(label='', allow_empty_file=False, widget=forms.ClearableFileInput(attrs={
        'class': 'form-control',
        'accept': '.json',
        'required': True
    }))

#################################################
#  Class: AuthorizedHost                        #
#  Used for: show/update hosts on plugins page  #
#################################################

class AuthorizedHost(forms.Form):
    AUTH_OPTIONS = [
        ('SI', 'SI'),
        ('NO', 'NO')
    ]
    host = forms.CharField(max_length=20, label='', widget=forms.TextInput(attrs={
        'class': 'form-control text-center',
        'readonly': True
    }))
    is_authorized = forms.ChoiceField(choices=AUTH_OPTIONS, label='', widget=forms.Select(attrs={
        'class': 'form-control text-center',
        'onchange': 'update_host(this)'
    }))
