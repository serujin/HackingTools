from .manager import ItemManager, PluginManager, RiskManager, ScrappingManager, HostManager, XLSXFileManager
from .worksheets import ResumeWorksheet, ReportsWorksheet, HostsWorksheet
from .default_worksheets import ResumeDefaultData, ReportsDefaultData, HostsDefaultData
from .constants import Constants
import xml.etree.ElementTree as ET

#######################################################################
#  File: main.py                                                      #
#  Class: Parser                                                      #
#  Used for: manipulate all information of .nessus files and save it  #
#  to able django to use it                                           #                             
#                                                                     #
#  This file holds the main class of the parser and is the            #
#  only file called directly from django                              #
#######################################################################
######################################Apartado funcional de la aplicacion explicando todas las funcionalidades, con imagenes y demas DONE
######################################apartado explicativo del codigo  y como esta estructurado DONE
######################################Definnicion de las BBDD y su uso DONE
######################################explicacion de como montarlo en el servidor
######################################requisitos (python, libreria x, etc)

class Parser(object):
    # The singleton instance
    instance = None

    # This three methods are overwritten to create the singleton
    def __new__(cls):
        if not Parser.instance:
            Parser.instance = Parser.__Parser()
        return Parser.instance

    def __getattr__(self, key):
        return getattr(self.instance, key)

    def __setattr__(self, key, value):
        return setattr(self.instance, key, value)

    # An internal class that makes everything
    class __Parser:
        def __init__(self):
            self.reset()
        
        # This method resets all parser information, is called whenever a file is parsed to prevent bugs
        def reset(self):
            self.item_manager = ItemManager()
            self.risk_manager = RiskManager()
            self.host_manager = HostManager()
            self.plugin_manager = PluginManager()
            self.scrapper = ScrappingManager(self.item_manager.items, self.risk_manager.get_risks_to_find())
            self.file_name = ''
            self.scan_type = ''
            self.app_name = ''

        # This method will loop for all the interesting information in to the .nessus file passed by parameter
        def scrap_file(self, file):
            tree = ET.parse(file)
            for host_item in tree.findall(Constants.HOST_FILE_ROOT):
                host = self.scrapper.get_host(host_item)
                self.host_manager.add_host(host)
                for report_item in host_item.findall(Constants.REPORT_FILE_ROOT):
                    report, is_port_open_plugin = self.scrapper.get_report(report_item)
                    if report is not None:
                        if not is_port_open_plugin:
                            self.plugin_manager.add_plugin(report.plugin)
                            self.host_manager.add_report(self.scan_type, self.app_name, report)
                        else:
                            self.host_manager.set_host_open_port(host, report)
                        
        # Simple setter
        def set_scan_type(self, scan_type):
            self.scan_type = scan_type

        # Simple setter
        def set_app_name(self, app_name):
            self.app_name = str.upper(app_name)

        # Simple setter
        def set_file_name(self, name):
            self.file_name = name

        # This method will change the plugin category of the specified plugin by id
        def update_plugin(self, id, category):
            self.plugin_manager.change_category(id, category)

        # Simple getter
        def get_plugins(self):
            return self.plugin_manager.plugins

        # This method will create an excel on the buffer passed by parameter and then, it will introduce all data in to that excel
        def generate_file(self, buffer):
            self.host_manager.update_plugins(self.plugin_manager.plugins)
            xlsxfile = XLSXFileManager(buffer)
            # Creating the worksheets
            resume = ResumeWorksheet(self.host_manager.get_number_of_vulnerable_hosts())
            reports = ReportsWorksheet()
            hosts = HostsWorksheet()
            # Filling the worksheets with the default data
            xlsxfile.insert_defaults(resume, ResumeDefaultData())
            xlsxfile.insert_defaults(reports, ReportsDefaultData())
            xlsxfile.insert_defaults(hosts, HostsDefaultData())
            # Filling the worksheets with the .nessus extracted data
            resume.add_data(
                self.host_manager.get_number_of_total_hosts(), 
                self.host_manager.get_number_of_total_vulns(), 
                self.host_manager.get_number_of_vulnerable_hosts(), 
                self.host_manager.get_number_of_vulns_per_risk_per_host(), 
                self.host_manager.get_number_of_type_of_vuln_per_host(), 
                self.host_manager.get_risks_per_category()
            )
            self.add_reports(reports)
            hosts.add_hosts(
                self.host_manager.get_number_of_total_vulns(), 
                self.host_manager.get_number_of_vulns_per_risk_per_host(), 
                self.host_manager.get_number_of_type_of_vuln_per_host()
            )
            # Writing all the information into the excel
            xlsxfile.write_worksheet(resume)
            xlsxfile.write_worksheet(reports)
            xlsxfile.write_worksheet(hosts)
            # Closing the excel
            xlsxfile.close()

        # This method will just loop for all the reports to add them to the report_worksheet ('Informe' on the excel)
        def add_reports(self, report_worksheet):
            for host in self.host_manager.hosts:
                for report in host.critical_reports:
                    report_worksheet.add_report(host, report)
            for host in self.host_manager.hosts:
                for report in host.high_reports:
                    report_worksheet.add_report(host, report)
            for host in self.host_manager.hosts:
                for report in host.medium_reports:
                    report_worksheet.add_report(host, report)
            for host in self.host_manager.hosts:
                for report in host.low_reports:
                    report_worksheet.add_report(host, report)