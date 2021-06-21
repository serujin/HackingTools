from django.shortcuts import render
from django.http import HttpResponse
from django.core import management
from .forms import UploadFileForm, PluginForm, UploadDBForm, AuthorizedHost
from .src.main import Parser
from io import BytesIO, StringIO
from .models import Plugin, Vulnerability
import json

######################################################
#  File: views.py                                    #                          
#                                                    #
#  This file has almost all the functions of django  #
######################################################

# Handler for 404 errors
def handler404(request, *args, **argv):
    return render(request, '404.html')

# Handler for 500 errors
def handler500(request, *args, **argv):
    return render(request, '500.html')

# This method returns the main page of the parser 
def parser(request, alert=False, alert_msg='', form=UploadFileForm(), db_form=UploadDBForm()):
    return render(request, 'parser.html', context={'form':form, 'db_form':db_form, 'alert':alert, 'alert_msg':alert_msg})

# This method loads the plugins page
def plugins(request, error=False):
    return render(request, 'plugins.html', context={'hosts_forms':get_hosts_to_classify(),'forms':get_plugins(), 'error':error}) 

# This method returns parser page but with an error
def wrong_format(request):
    return parser(request, alert=True, alert_msg='Entre los archivos subidos, hay uno o varios que no son adecuados, los archivos han de tener el formato generado por nessus (".nessus"), por favor revíselo.')

# This method checks if the upload file is valid
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            return parse_nessus(request)
        return parser(request, form=form)
    return parser(request)

# This method checks if the files are valid and scrap them if so
def parse_nessus(request):
    files = request.FILES.getlist('files')
    file_name = request.POST.get('file_name')
    scan_type = request.POST.get('select_scan_type')
    app_name = request.POST.get('app_name')
    if not check_files(files):
        return wrong_format(request)
    parser = Parser()
    parser.reset()
    parser.set_file_name(file_name)
    parser.set_scan_type(scan_type)
    parser.set_app_name(app_name)
    for file in files:
        parser.scrap_file(file)
    return plugins(request)

# This method checks if the files are valid
def check_files(files):
    file_names = []
    for file in files:
        if not is_a_valid_nessus_file(file):
            return False
        if file in file_names:
            return False
        file_names.append(file)
    return True

# This method is used to get plugins on the plugins page, if they are on the db, it loads from db, otherwise from the parser
def get_plugins():
    parser = Parser()
    plugins = parser.get_plugins()
    forms = []
    for plugin in plugins:
        try:
            add_plugin_from_db(forms, plugin)
        except:
            add_plugin_from_parser(forms, plugin)
    return forms

# This method gets a plugin from the database and then updates its category on the parser and into the plugins page
def add_plugin_from_db(forms, plugin):
    db_plugin = Plugin.objects.get(plugin_id=plugin.ID)
    forms.append(PluginForm(initial={'id':plugin.ID, 'plugin_id':plugin.ID, 'plugin_name':plugin.name, 'plugin_category':db_plugin.plugin_category}, auto_id=False))
    if plugin.category != db_plugin.plugin_category:
        update_plugin_from_db(plugin.ID, db_plugin.plugin_category)

# This method updates a plugin on the parser with the db information
def update_plugin_from_db(id, category):
    parser = Parser()
    parser.update_plugin(id, category)

# This method appends a plugin from the parser
def add_plugin_from_parser(forms, plugin):
    if plugin.category is None:
        forms.append(PluginForm(initial={'id':plugin.ID, 'plugin_id':plugin.ID, 'plugin_name':plugin.name}, auto_id=False))
    else:
        forms.append(PluginForm(initial={'id':plugin.ID, 'plugin_id':plugin.ID, 'plugin_name':plugin.name, 'plugin_category':plugin.category}, auto_id=False))

# This method checks if all plugins are classified before the download
def file_is_able_to_download():
    parser = Parser()
    for plugin in parser.plugin_manager.plugins:
        if plugin.category is None or plugin.category == 'NaN':
            return False
    return True

# This method is a simple call to update a plugin 
def update_plugin(request):
    if request.is_ajax and request.method == 'POST':
        parser = Parser()
        ID = request.POST['id']
        category = request.POST['category']
        parser.update_plugin(ID, category)
        try:
            db_plugin = Plugin.objects.get(plugin_id=ID)
            db_plugin.plugin_category = category
            db_plugin.save()
        except:
            pass
    return plugins(request, True)

# This method updates the db based on the parser data
def update_db():
    parser = Parser()
    for plugin in parser.get_plugins():
        p = Plugin()
        p.plugin_id=plugin.ID
        p.plugin_name=plugin.name
        p.plugin_category=plugin.category
        p.save()
        
# This method downloads the excel file
def download_file(request):
    if request.method == 'POST':
        parser = Parser()
        if not file_is_able_to_download():
            return plugins(request, error=True)
        update_db()
        workbook = BytesIO()
        insert_ids_into_db()
        parser.generate_file(workbook)
        workbook.seek(0)
        response = HttpResponse(workbook.read(), content_type='application/vnd.ms-excel')
        response['Content-Disposition'] = 'attachment; filename=' + parser.file_name + '.xlsx'
        return response

# This method is a simple call to update the host is_authorized field from the plugins page
def update_auth(request):
    if request.is_ajax and request.method == 'POST':
        parser = Parser()
        host_to_change = request.POST['host']
        auth = request.POST['auth']
        for host in parser.host_manager.hosts:
            if host.ip == host_to_change:
                host.is_authorized = auth
        return HttpResponse(status=200)

# This method inserts all ids on db if they are not duplicated
def insert_ids_into_db():
    for report in get_all_reports():
        insert_id_on_db(report)

# Simple getter
def get_all_reports():
    parser = Parser()
    reports = []
    for host in parser.host_manager.hosts:
        for report in host.critical_reports:
            reports.append(report)
        for report in host.high_reports:
            reports.append(report)
        for report in host.medium_reports:
            reports.append(report)
        for report in host.low_reports:
            reports.append(report)
    return reports

# This method inserts one id on db if it's not duplicated
def insert_id_on_db(report):
    vuln = report.report_id.split('-')
    v = Vulnerability.objects.filter(
        vuln_type = vuln[0],
        app_name = vuln[1],
        vuln_risk = vuln[2],
        number = int(vuln[4]),
        plugin_name = report.plugin.name
    ).count()
    if v == 0:
        vv = Vulnerability()
        vv.vuln_type = vuln[0]
        vv.app_name = vuln[1]
        vv.vuln_risk = vuln[2]
        vv.number = int(vuln[4])
        vv.plugin_name = report.plugin.name
        vv.save()

# This method packages the database on a json and downloads it
def download_database(request):
    db = StringIO()
    management.call_command('dumpdata', 'nessus_parser', format='json', stdout=db)
    db.seek(0)
    response = HttpResponse(db.read(), content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=front_hacking_db.json'
    return response

# This method reads a json and loads it in to the database
def load_database(request):
    if request.method == 'POST':
        form = UploadDBForm(request.POST, request.FILES)
        if form.is_valid():
            files = request.FILES.getlist('db_files')
            plugins = 0
            vulns = 0
            if check_db_files(files):
                for file in files:
                    for data in json.loads(file.read()):
                        if 'plugin_category' in data['fields']:
                            load_plugin_from_json(data)
                            plugins+=1
                        else:
                            load_vuln_from_json(data)
                            vulns+=1
                return parser(request, alert=True, alert_msg='Base de datos cargada con éxito. Cargados ' + str(plugins) + ' plugins y ' + str(vulns) + ' identificadores de vulnerabilidades.')
    return parser(request, db_form=form, alert=True, alert_msg='Ha habido un error al cargar la base de datos, por favor, consulta con un administrador si el problema persiste.')

# This method creates or updates a plugin on the database
def load_plugin_from_json(data):
    p, created = Plugin.objects.update_or_create(
        plugin_id = data['pk'],
        plugin_name = data['fields']['plugin_name'],
        plugin_category = data['fields']['plugin_category']
    )

# This method creates or updates a vulnerability on the database
def load_vuln_from_json(data):
    v, created = Vulnerability.objects.update_or_create(
        vuln_type = data['fields']['vuln_type'],
        app_name = data['fields']['app_name'],
        vuln_risk = data['fields']['vuln_risk'],
        year = data['fields']['year'],
        number = data['fields']['number'],
        plugin_name = data['fields']['plugin_name'],
        date = data['fields']['date']
    )

# This method checks the file to be loaded on the database
def check_db_files(files):
    for file in files:
        if file.size < 1:
            return False
        if file.name != "front_hacking_db.json":
            return False
    return True

# Simple getter from the database
def get_hosts_to_classify():
    parser = Parser()
    hosts = parser.host_manager.get_vulnerable_host_list()
    forms = []
    for host in hosts:
        forms.append(AuthorizedHost(initial={'host': host.ip, 'is_authorized': host.is_authorized}))
    return forms

# This method check if the nessus file is valid
def is_a_valid_nessus_file(file):
    if file.size < 1:
        return False
    name = file.name.split('.')
    if len(name) != 2:
        return False
    if name[1] != 'nessus':
        return False
    return True