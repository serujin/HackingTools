from .models import XLSXMergedCell, XLSXWorksheet, XLSXColumn, XLSXCell, XLSXGraph
from .constants import Constants

######################################################################
#  File: worksheets.py                                               #
#                                                                    #
#  This file is used to introduce data into the worksheets and some  #
#  formatting                                                        #
######################################################################

# This method returns the number passed by parameter divided by the total passed by parameter as a string formatted with a percentage
def percentage(number, total):
    if total == 0:
        return '{:.2%}'.format(0)
    return '{:.2%}'.format(number/total)

###########################################################
#  Class: ResumeWorksheet                                 #
#  Inherits from: XLSXWorksheet                           #
#  Used for: insert all data for the 'Resumen' worksheet  #
###########################################################

class ResumeWorksheet(XLSXWorksheet):
    # COLUMN_SIZING is a list of columns to be formatted 
    COLUMN_SIZING = [
        XLSXColumn(1, 25)
    ]

    def __init__(self, vulnerable_hosts):
        super().__init__('Resumen', False, self.COLUMN_SIZING)
        self.__init_graphs(vulnerable_hosts)

    # This method receives data from the Parser class to write all the data on the worksheet
    def add_data(self, t_h_n, t_v, v_h_n, v_p_r_p_h, t_p_r_p_h, r_p_c):
        low = 0
        mid = 0
        high = 0
        crit = 0
        osp = 0
        c = 0
        oos = 0
        cy = 0
        pv = 0
        for data in v_p_r_p_h.values():
            vulns = data[0]
            low += vulns[0]
            mid += vulns[1]
            high += vulns[2]
            crit += vulns[3]
        for types in t_p_r_p_h.values():
            osp += types['OSP']
            c += types['C']
            oos += types['OOS']
            cy += types['CY']
            pv += types['PV']
        self.__add_cell(t_h_n, 3, 1)
        self.__add_cell(v_h_n,3, 2)
        self.__add_cell(t_v, 3, 4)
        self.__add_cell(low, 2, 8)
        self.__add_cell(percentage(low, t_v), 3, 8)
        self.__add_cell(mid, 2, 9)
        self.__add_cell(percentage(mid, t_v), 3, 9)
        self.__add_cell(high, 2, 10)
        self.__add_cell(percentage(high, t_v), 3, 10)
        self.__add_cell(crit, 2, 11)
        self.__add_cell(percentage(crit, t_v), 3, 11)
        self.__add_cell(osp, 2, 15)
        self.__add_cell(percentage(osp, t_v), 3, 15)
        self.__add_cell(c, 2, 16)
        self.__add_cell(percentage(c, t_v), 3, 16)
        self.__add_cell(oos, 2, 17)
        self.__add_cell(percentage(oos, t_v), 3, 17)
        self.__add_cell(cy, 2, 18)
        self.__add_cell(percentage(cy, t_v), 3, 18)
        self.__add_cell(pv, 2, 19)
        self.__add_cell(percentage(pv, t_v), 3, 19)
        self.__add_merged_cell(r_p_c['OSP'][0], 2, 23)
        self.__add_merged_cell(r_p_c['OSP'][1], 4, 23)
        self.__add_merged_cell(r_p_c['OSP'][2], 6, 23)
        self.__add_merged_cell(r_p_c['OSP'][3], 8, 23)      
        self.__add_merged_cell(r_p_c['C'][0], 2, 24)
        self.__add_merged_cell(r_p_c['C'][1], 4, 24)
        self.__add_merged_cell(r_p_c['C'][2], 6, 24)
        self.__add_merged_cell(r_p_c['C'][3], 8, 24)
        self.__add_merged_cell(r_p_c['OOS'][0], 2, 25)
        self.__add_merged_cell(r_p_c['OOS'][1], 4, 25)
        self.__add_merged_cell(r_p_c['OOS'][2], 6, 25)
        self.__add_merged_cell(r_p_c['OOS'][3], 8, 25)
        self.__add_merged_cell(r_p_c['CY'][0], 2, 26)
        self.__add_merged_cell(r_p_c['CY'][1], 4, 26)
        self.__add_merged_cell(r_p_c['CY'][2], 6, 26)
        self.__add_merged_cell(r_p_c['CY'][3], 8, 26)
        self.__add_merged_cell(r_p_c['PV'][0], 2, 27)
        self.__add_merged_cell(r_p_c['PV'][1], 4, 27)
        self.__add_merged_cell(r_p_c['PV'][2], 6, 27)
        self.__add_merged_cell(r_p_c['PV'][3], 8, 27)

    # This method receives data to write a cell on the worksheet
    def __add_cell(self, value, x, y):
        self.unique_cells.append(XLSXCell(value, x, y, Constants.FORMAT_03))

    def __add_merged_cell(self, value, x, y):
        self.merged_cells.append(XLSXMergedCell(value, x, y, x + 1, y, Constants.FORMAT_03))

    # This method initializes the graphs of the worksheet
    def __init_graphs(self, vulnerable_hosts):
        vuln_graph = XLSXGraph('column', 1.067, 1.32, 'F2', 'Vulnerabilidades', x_label_position='none')
        vuln_graph.add_series('=Resumen!$C$12', name='=Resumen!$B$12', color='#FF0000', gap=300, overlap=-30)
        vuln_graph.add_series('=Resumen!$C$11', name='=Resumen!$B$11', color='#F79646', gap=300, overlap=-30)
        vuln_graph.add_series('=Resumen!$C$10', name='=Resumen!$B$10', color='#FFC000', gap=300, overlap=-30)
        vuln_graph.add_series('=Resumen!$C$9', name='=Resumen!$B$9', color='#00B050', gap=300, overlap=-30)

        x = max(vulnerable_hosts / 140, 1.975)
        y = max(vulnerable_hosts / 200, 1.39)

        vuln_per_host_graph = XLSXGraph('column', x, y, 'L22', 'Vulnerabilidades por host', subtype='stacked')
        vuln_per_host_graph.add_series('=Hosts!$F$5:$F$5', name='Low', color='#00B050', gap=100, show_labels=False, category='=Hosts!$B$5:$B$'+str(vulnerable_hosts + 4))
        vuln_per_host_graph.add_series('=Hosts!$H$5:$H$'+str(vulnerable_hosts + 4), name='Medium', color='#FFC000', gap=100, show_labels=False)
        vuln_per_host_graph.add_series('=Hosts!$J$5:$J$'+str(vulnerable_hosts + 4), name='High', color='#F79646', gap=100, show_labels=False)
        vuln_per_host_graph.add_series('=Hosts!$L$5:$L$'+str(vulnerable_hosts + 4), name='Critical', color='#FF0000', gap=100, show_labels=False)

        categories_graph = XLSXGraph('column', 1.067, 1.32, 'O2', 'Vulnerabilidades por categoría', x_label_position='none')
        categories_graph.add_series('=Resumen!$C$16', name='=Resumen!$B$16', color='#788B17', gap=300, overlap=-30)
        categories_graph.add_series('=Resumen!$C$17', name='=Resumen!$B$17', color='#A11B1B', gap=300, overlap=-30)
        categories_graph.add_series('=Resumen!$C$18', name='=Resumen!$B$18', color='#2ECC71', gap=300, overlap=-30)
        categories_graph.add_series('=Resumen!$C$19', name='=Resumen!$B$19', color='#8E44AD', gap=300, overlap=-30)
        categories_graph.add_series('=Resumen!$C$20', name='=Resumen!$B$20', color='#D99694', gap=300, overlap=-30)

        self.graphs.append(vuln_graph)
        self.graphs.append(vuln_per_host_graph)
        self.graphs.append(categories_graph)

###########################################################
#  Class: ReportsWorksheet                                #
#  Inherits from: XLSXWorksheet                           #
#  Used for: insert all data for the 'Informe' worksheet  #
###########################################################

class ReportsWorksheet(XLSXWorksheet):
    # COLUMN_SIZING is a list of columns to be formatted 
    COLUMN_SIZING = [
        XLSXColumn(0, 30),
        XLSXColumn(1, 30),
        XLSXColumn(2, 15),
        XLSXColumn(3, 10),
        XLSXColumn(4, 9),
        XLSXColumn(5, 8),
        XLSXColumn(6, 15),
        XLSXColumn(7, 10),
        XLSXColumn(8, 40),
        XLSXColumn(9, 10),
        XLSXColumn(10, 12),
        XLSXColumn(11, 30),
        XLSXColumn(12, 50),
        XLSXColumn(13, 50),
        XLSXColumn(14, 45),
        XLSXColumn(15, 70),
        XLSXColumn(16, 30),
        XLSXColumn(17, 25)
    ]

    def __init__(self):
        super().__init__('Informe', False, self.COLUMN_SIZING)
        self.current_y = 1

    # This method receives data to write a report on the worksheet
    def add_report(self, host, report):
        data = [
            report.report_id,
            report.plugin.name,
            host.ip,
            report.items['Servicio'],
            report.protocol,
            self.__get_port(report),
            report.items['CVE'],
            host.is_authorized,
            report.items['CVSS_trace'],
            report.items['CVSS'],
            self.__get_risk_title(report.risk),
            self.__get_category_name(report.plugin.category),
            report.items['Sinopsis'],
            report.items['Descripción'],
            report.items['Solución'],
            report.items['Plugin Output'],
            report.items['Referencias'],
            host.so
        ]
        for x, value in enumerate(data):
            if x == 7:
                if value == 'SI':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_16))
                else:
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_19))
            elif x == 10:
                if value == 'Low':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_16))
                elif value == 'Medium':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_17))
                elif value == 'High':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_18))
                elif value == 'Critical':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_19))
            elif x == 11:
                if value == 'Operative System Patch':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_20))
                elif value == 'Config':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_21))
                elif value == 'Cypher':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_22))
                elif value == 'Product Vulnerability':
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_23))
                else:
                    self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_24))
            else:
                self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_06))
        self.current_y += 1

    # This method returns an X if the port is 0, otherwise returns the port
    def __get_port(self, report):
        if report.port == '0':
            return 'X'
        return report.port

    # This method returns the name of the category from Constants class
    def __get_category_name(self, category):
        for key, name in Constants.PLUGIN_TYPES:
            if key == category:
                return name

    # This method returns the name of the risk from Constants class
    def __get_risk_title(self, severity):
        for key, value in Constants.RISKS.items():
            if value == int(severity):
                return key

#########################################################
#  Class: HostsWorksheet                                #
#  Inherits from: XLSXWorksheet                         #
#  Used for: insert all data for the 'Hosts' worksheet  #
#########################################################

class HostsWorksheet(XLSXWorksheet):
    # COLUMN_SIZING is a list of columns to be formatted 
    COLUMN_SIZING = [
        XLSXColumn( 1, 20),
        XLSXColumn( 2, 25),
        XLSXColumn(12, 12),
        XLSXColumn(13, 12),
        XLSXColumn(20, 12),
        XLSXColumn(21, 12)
    ]

    def __init__(self):
        super().__init__('Hosts', False, self.COLUMN_SIZING)
        self.current_y = 4

    # This method receives data from the Parser class to write all the data on the worksheet
    def add_hosts(self, t_v, v_p_r_p_h, t_p_r_p_h):
        data_dict = sorted(v_p_r_p_h.items(), key=lambda k:sum(k[1][0]), reverse=True)
        for host, data in data_dict:
            vulns = data[0]
            open_ports = data[1]
            self.__add_cell(host, 1)
            self.__add_cell(open_ports, 2)
            self.__add_cell(sum(vulns), 3)
            self.__add_cell(percentage(sum(vulns), t_v), 4)
            self.__add_cell(vulns[0], 5)
            self.__add_cell(percentage(vulns[0], t_v), 6)
            self.__add_cell(vulns[1], 7)
            self.__add_cell(percentage(vulns[1], t_v), 8)
            self.__add_cell(vulns[2], 9)
            self.__add_cell(percentage(vulns[2], t_v), 10)
            self.__add_cell(vulns[3], 11)
            self.__add_cell(percentage(vulns[3], t_v), 12)
            self.current_y += 1
        self.current_y = 4
        hosts = [info[0] for info in data_dict]
        for host in hosts:
            categories = t_p_r_p_h[host]
            self.__add_cell(categories['OSP'], 13)
            self.__add_cell(percentage(categories['OSP'], t_v), 14)
            self.__add_cell(categories['C'], 15)
            self.__add_cell(percentage(categories['C'], t_v), 16)
            self.__add_cell(categories['OOS'], 17)
            self.__add_cell(percentage(categories['OOS'], t_v), 18)
            self.__add_cell(categories['CY'], 19)
            self.__add_cell(percentage(categories['CY'], t_v), 20)
            self.__add_cell(categories['PV'], 21)
            self.__add_cell(percentage(categories['PV'], t_v), 22)
            self.current_y += 1

    # This method receives data to write a report on the worksheet
    def __add_cell(self, value, x):
        self.unique_cells.append(XLSXCell(value, x, self.current_y, Constants.FORMAT_03))