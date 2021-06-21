from .constants import Constants
from .models import Item, Risk, Plugin, Report, Host
import pandas.io.formats.excel
import pandas
import datetime
from .constants import Constants

#################################################################################
#  File: manager.py                                                             #
#                                                                               #
#  This file has all managers that will manipulate the data, also this file is  #
#  used to be more organised                                                    #
#################################################################################

#######################################################################
#  Class: PluginManager                                               #
#  Used for: hold and modify all plugins data                         #
#######################################################################

class PluginManager:
    def __init__(self):
        self.ids = []
        self.plugins = []
    
    # This method will add plugins to the list if is not already saved on the list
    def add_plugin(self, plugin):
        if plugin.ID not in self.ids:
            self.ids.append(plugin.ID)
            self.plugins.append(plugin)

    # This method will change the category of one plugin by id
    def change_category(self, id, category):
        for plugin in self.plugins:
            if int(plugin.ID) == int(id):
                plugin.category = category

#######################################################################
#  Class: ItemManager                                                 #
#  Used for: hold all the items that will be used to retrieve data    # 
#  from the .nessus file                                              #
#######################################################################

class ItemManager:
    def __init__(self):
        self.items = []
        self.__init_items()
    
    # This method will init all the items declared on the constants class
    def __init_items(self):
        for text, tag in Constants.ITEMS.items():
            self.__add_item(text, tag)

    # This method just adds an item to the list
    def __add_item(self, text, tag):
        self.items.append(Item(text, tag))

#######################################################################
#  Class: RiskManager                                                 #
#  Used for: holds and manipulates the desired risks to be retrieved  # 
#  from .nessus                                                       #
#######################################################################

class RiskManager:
    def __init__(self):
        self.risks = []
        self.__init_risks()

    # This method will init all the risks declared on the constants class
    def __init_risks(self):
        for text, severity in Constants.RISKS.items():
            self.risks.append(Risk(text, severity))

    # This method gets all accepted risks
    def get_risks_to_find(self):
        to_return = []
        for risk in self.risks:
            to_return.append(risk.severity)
        return to_return

#######################################################################
#  Class: HostManager                                                 #
#  Used for: holds and manipulates the hosts data retrieved from      #
#  .nessus file                                                       #
#######################################################################

class HostManager:
    def __init__(self):
        self.hosts = []
        self.current_critical = 1
        self.current_high = 1
        self.current_medium = 1
        self.current_low = 1

    # This method add a host to the list
    def add_host(self, host):
        self.hosts.append(host)

    # This method gets all vulnerable hosts to show on plugins.html
    def get_vulnerable_host_list(self):
        to_return = []
        for host in self.hosts:
            c = len(host.critical_reports) > 0
            h = len(host.high_reports) > 0
            m = len(host.medium_reports) > 0
            l = len(host.low_reports) > 0
            if c or h or m or l:
                to_return.append(host)
        return to_return
        
    # This method gets all risks per type for the "resumen" page
    def get_risks_per_category(self):
        to_return = {
            'OOS':[0, 0, 0, 0],
            'PV':[0, 0, 0, 0], 
            'CY':[0, 0, 0, 0], 
            'C':[0, 0, 0, 0], 
            'OSP':[0, 0, 0, 0]
        }
        for host in self.hosts:
            for report in host.critical_reports:
                to_return[report.plugin.category][3] += 1
            for report in host.high_reports:
                to_return[report.plugin.category][2] += 1
            for report in host.medium_reports:
                to_return[report.plugin.category][1] += 1
            for report in host.low_reports:
                to_return[report.plugin.category][0] += 1
        return to_return
        
    # This method gets all open ports of a host
    def set_host_open_port(self, host, report):
        ports = ''
        for text in report.items['Plugin Output'].split():
            if text == 'Port':
                add = True
                continue
            if add:
                if not text in Constants.AVOID_PORTS:
                    ports += text + ', '    
                add = False
                #TODO CHECK IF FALSE POSITIVE
        for self_host in self.hosts:
            if self_host == host:
                if ',' in ports:
                    ports = ports[:-2]
                host.open_ports = ports


    # This method add the report passed by parameter to its list ordered by risk
    def add_report(self, scan_type, app_name, report):
        if report is not None:
            self.__set_report_id(scan_type, app_name, report)
            if report.risk == '1':
                self.__add_low_report(report)
                return
            if report.risk == '2':
                self.__add_medium_report(report)
                return
            if report.risk == '3':
                self.__add_high_report(report)
                return
            self.__add_critical_report(report)
    
    # This method sets an unique id for the report passed by parameter
    def __set_report_id(self, scan_type, app_name, report):
        st = scan_type + '-'
        an = app_name + '-'
        c = self.__get_risk_title(report.risk) + '-'
        y = str(datetime.date.today().year) + '-'
        n = str(self.get_number_for_id(report.risk)).zfill(3)
        report.report_id = st + an + c + y + n
    
    # This method add the report passed by parameter to low_reports list if the report is not equal to another, 
    # if so, it will append the port to the existing one
    def __add_low_report(self, report):
        host = self.__get_last_host()
        if len(host.low_reports) == 0:
            host.low_reports.append(report)
        else:
            added = False
            for rep in host.low_reports:
                if self.__reports_are_equals(report, rep):
                    rep.port += ', ' + report.port
                    added = True
            if not added:
                host.low_reports.append(report)
    
    # This method add the report passed by parameter to medium_reports list if the report is not equal to another, 
    # if so, it will append the port to the existing one
    def __add_medium_report(self, report):
        host = self.__get_last_host()
        if len(host.medium_reports) == 0:
            host.medium_reports.append(report)
        else:
            added = False
            for rep in host.medium_reports:
                if self.__reports_are_equals(report, rep):
                    rep.port += ', ' + report.port
                    added = True
            if not added:
                host.medium_reports.append(report)

    # This method add the report passed by parameter to high_reports list if the report is not equal to another, 
    # if so, it will append the port to the existing one
    def __add_high_report(self, report):
        host = self.__get_last_host()
        if len(host.high_reports) == 0:
            host.high_reports.append(report)
        else:
            added = False
            for rep in host.high_reports:
                if self.__reports_are_equals(report, rep):
                    rep.port += ', ' + report.port
                    added = True
            if not added:
                host.high_reports.append(report)

    # This method add the report passed by parameter to critical_reports list if the report is not equal to another, 
    # if so, it will append the port to the existing one
    def __add_critical_report(self, report):
        host = self.__get_last_host()
        if len(host.critical_reports) == 0:
            host.critical_reports.append(report)
        else:
            added = False
            for rep in host.critical_reports:
                if self.__reports_are_equals(report, rep):
                    rep.port += ', ' + report.port
                    added = True
            if not added:
                host.critical_reports.append(report)

    # This method checks if one report (r1) is equal to another report (r2)
    def __reports_are_equals(self, r1, r2):
        a = r1.protocol == r2.protocol
        b = r1.risk == r2.risk
        c = r1.items['Plugin Output'] == r2.items['Plugin Output']
        d = r1.plugin.name == r2.plugin.name
        return a and b and c and d

    # Simple getter
    def get_number_of_vulnerable_hosts(self):
        to_return = 0
        for host in self.hosts:
            c = len(host.critical_reports) > 0
            h = len(host.high_reports) > 0
            m = len(host.medium_reports) > 0
            l = len(host.low_reports) > 0
            if c or h or m or l:
                to_return += 1
        return to_return

    # Simple getter
    def get_number_of_total_hosts(self):
        return len(self.hosts)

    # Simple getter
    def get_number_of_vulns_per_risk_per_host(self):
        to_return = {}
        for host in self.hosts:
            to_return[host.ip] = ([
                len(host.low_reports),
                len(host.medium_reports),
                len(host.high_reports),
                len(host.critical_reports)
            ], host.open_ports)
        return to_return

    # Simple getter
    def get_number_of_type_of_vuln_per_host(self):
        to_return = {}
        for host in self.hosts:
            categories = {'OOS':0, 'PV':0, 'CY':0, 'C':0, 'OSP':0}
            for report in host.critical_reports:
                categories[report.plugin.category] += 1
            for report in host.high_reports:
                categories[report.plugin.category] += 1
            for report in host.medium_reports:
                categories[report.plugin.category] += 1
            for report in host.low_reports:
                categories[report.plugin.category] += 1
            to_return[host.ip] = categories
        return to_return

    # Simple getter
    def get_number_of_total_vulns(self):
        to_return = 0
        for host in self.hosts:
            l = len(host.low_reports)
            m = len(host.medium_reports)
            h = len(host.high_reports)
            c = len(host.critical_reports) 
            to_return += (l + m + h + c)
        return to_return

    # This method is used to update all plugins on the reports
    def update_plugins(self, plugins):
        for plugin in plugins:
            for host in self.hosts:
                for report in host.critical_reports:
                    if report.plugin.ID == plugin.ID:
                        report.plugin.category = plugin.category
                for report in host.high_reports:
                    if report.plugin.ID == plugin.ID:
                        report.plugin.category = plugin.category
                for report in host.medium_reports:
                    if report.plugin.ID == plugin.ID:
                        report.plugin.category = plugin.category
                for report in host.low_reports:
                    if report.plugin.ID == plugin.ID:
                        report.plugin.category = plugin.category
                    
    # Simple getter
    def __get_last_host(self):
        return self.hosts[-1]

    # Simple getter
    def __get_risk_title(self, severity):
        for key, value in Constants.RISKS.items():
            if value == int(severity):
                return key[0]

    # This method returns the current number of the risk 
    def get_number_for_id(self, risk):
        to_return = -1
        if risk == '1':
            to_return = self.current_low
            self.current_low += 1
        if risk == '2':
            to_return = self.current_medium
            self.current_medium += 1
        if risk == '3':
            to_return = self.current_high
            self.current_high += 1
        if risk == '4':
            to_return = self.current_critical
            self.current_critical += 1
        return to_return

#######################################################################
#  Class: ScrappingManager                                            #
#  Used for: help to retrieve information from the .nessus            #
#######################################################################

class ScrappingManager:
    def __init__(self, selected_items, accepted_risks):
        self.selected_items = selected_items
        self.accepted_risks = accepted_risks

    # This method returns a Host object from an xml host_item
    def get_host(self, host_item):
        ip = self.__extract_information(
            host_item, Constants.HOST[Constants.HOST_NAME])
        os = self.__extract_information(
            host_item, Constants.HOST[Constants.HOST_OS_NAME])
        return Host(ip, os)

    # This method returns None if the risk is not in accepted risks, otherwise it returns Report object from an xml report_item
    def get_report(self, report_item):
        risk = self.__extract_information(
            report_item, Constants.REPORT[Constants.RISK_NAME])
        plugin = self.__get_plugin(report_item)
        if int(risk) not in self.accepted_risks and plugin.ID != '10919':
            return None, None
        port = self.__extract_information(
            report_item, Constants.REPORT[Constants.PORT_NAME])
        protocol = self.__extract_information(
            report_item, Constants.REPORT[Constants.PROTOCOL_NAME])
        report = Report(port, protocol, risk, plugin)
        for item in self.selected_items:
            report.items[item.text] = self.__extract_information(report_item, item.tag)
        if plugin.ID == '10919':
           return report, True 
        return report, False

    # This method returns a Plugin object from an xml report_item
    def __get_plugin(self, report_item):
        ID = self.__extract_information(
            report_item, Constants.PLUGIN[Constants.PLUGIN_ID_NAME])
        name = self.__extract_information(
            report_item, Constants.PLUGIN[Constants.PLUGIN_NAME_NAME])
        return Plugin(ID, name)

    # This method returns the text from the tag passed by paramenter of the xml item passed by parameter
    def __extract_information(self, item, tag):
        info = item.get(tag)
        if info is None:
            info = item.find(tag)
        text = ' '
        if info is None:
            return text
        try:
            text = info.text
        except:
            text = info
        return text

#######################################################################
#  Class: XLSXFileManager                                             #
#  Used for: make all the necessary interactions with the excel file  #
#######################################################################

class XLSXFileManager:
    def __init__(self, buffer):
        self.writer = pandas.ExcelWriter(buffer, engine='xlsxwriter')
        self.book = self.writer.book
        self.formats = {}
        self.__create_formats()

    # This method initializes the excel formats
    def __create_formats(self):
        for name, xlsxformat in Constants.XLSX_FORMATS.items():
            self.formats[name] = self.book.add_format(xlsxformat.styling)

    # This method writes all the information into the worksheet passed by parameter
    def write_worksheet(self, worksheet):
        pandas.DataFrame().to_excel(
            self.writer, sheet_name=worksheet.name, index=False, header=False)
        page = self.__get_page_by_name(worksheet.name)
        if not worksheet.show_gridlines:
            page.hide_gridlines(2)
        self.__write_cells(page, worksheet.unique_cells)
        self.__write_merged_cells(page, worksheet.merged_cells)
        self.__write_graphs(page, worksheet.graphs)
        self.__change_columns_size(page, worksheet.column_sizing)

    # This method writes all the default_data into the worksheet passed by parameter
    def insert_defaults(self, worksheet, default_data):
        for unique_cell in default_data.default_unique_cells:
            worksheet.unique_cells.append(unique_cell)
        for merged_cell in default_data.default_merged_cells:
            worksheet.merged_cells.append(merged_cell)
        for graph in default_data.default_graphs:
            worksheet.graphs.append(graph)

    # This method saves the changes into the excel
    def close(self):
        self.writer.save()

    # This method writes all the cells passed by parameter on the worksheet passed by parameter
    def __write_cells(self, worksheet, cells):
        for cell in cells:
            self.__write_cell(worksheet, cell)

    # This method writes all the cells passed by parameter on the worksheet passed by parameter
    def __write_merged_cells(self, worksheet, cells):
        for cell in cells:
            self.__write_merged_cell(worksheet, cell)

    # This method writes all the cells passed by parameter on the worksheet passed by parameter
    def __write_graphs(self, worksheet, graphs):
        for graph in graphs:
            self.__write_graph(worksheet, graph)

    # This method changes all the column size passed by parameter on the worksheet passed by parameter
    def __change_columns_size(self, worksheet, columns):
        for column in columns:
            self.__change_column_size(worksheet, column)

    # This method write one cell passed by parameter on the worksheet passed by parameter
    def __write_cell(self, worksheet, cell):
        if isinstance(cell.value, int):
            worksheet.write_number(cell.y, cell.x, cell.value,
                              self.formats[cell.style_name])
        else:
            worksheet.write_string(cell.y, cell.x, cell.value,
                              self.formats[cell.style_name])

    # This method write one merged cell passed by parameter on the worksheet passed by parameter
    def __write_merged_cell(self, worksheet, cell):
        worksheet.merge_range(cell.y, cell.x, cell.end_y, cell.end_x,
                         cell.value, self.formats[cell.style_name])

    # This method write one graph passed by parameter on the worksheet passed by parameter
    def __write_graph(self, worksheet, graph):
        graph_info = graph.graph_info
        chart = self.book.add_chart({
            'type': graph_info['type'],
            'subtype': graph_info['subtype']
        })
        chart.set_title({'name': graph_info['title']})
        chart.set_legend({'position': graph_info['legend_position']})
        chart.set_x_axis({'label_position': graph_info['x_label']})
        if graph_info['x_label'] != 'none':
            chart.set_x_axis({'name_font': {'size': 1}})
        chart.set_size({
            'x_scale': graph_info['scale'][0],
            'y_scale': graph_info['scale'][1]
        })
        graph_series = graph.series
        for series in graph_series:
            chart.add_series(series)
        worksheet.insert_chart(graph_info['position'], chart)
    
    # This method changes one column size passed by parameter on the worksheet passed by parameter
    def __change_column_size(self, worksheet, column):
        worksheet.set_column(column.column, column.column, column.size)

    # Simple getter
    def __get_page_by_name(self, name):
      return self.writer.sheets[name]
