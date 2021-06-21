#########################################################################
#  File: models.py                                                      #
#  Class: Parser                                                        #                           
#                                                                       #
#  This file has all the classes that hold data, no methods, just data  #   
#########################################################################

class Item:
    def __init__(self, text, tag):
        self.text = text
        self.tag = tag

class Risk:
    def __init__(self, text, severity):
        self.text = text
        self.severity = severity

class Host:
    def __init__(self, ip, so):
        self.open_ports = ''
        self.ip = ip
        self.so = so
        self.is_authorized = 'NO'
        self.critical_reports = []
        self.high_reports = []
        self.medium_reports = []
        self.low_reports = []

class Report:
    def __init__(self, port, protocol, risk, plugin): 
        self.report_id = ''
        self.port = port
        self.protocol = protocol
        self.risk = risk
        self.plugin = plugin
        self.items = {}

class Plugin:
    def __init__(self, ID, name):
        self.ID = ID
        self.name = name
        self.category = None   

class XLSXCell:
    def __init__(self, value, x, y, style_name):
        self.x = x
        self.y = y
        self.value = value
        self.style_name = style_name

class XLSXMergedCell(XLSXCell):
    def __init__(self, value, start_x, start_y, end_x, end_y, style_name):
        super().__init__(value, start_x, start_y, style_name)
        self.end_x = end_x
        self.end_y = end_y

class XLSXGraph:
    def __init__(self, graph_type, scale_x, scale_y, position, title, subtype=None, x_label_position='low', legend_position='bottom'):
        self.graph_info = {
            'type': graph_type,
            'subtype': subtype,
            'title': title,
            'position': position,
            'scale': [scale_x, scale_y],
            'x_label': x_label_position,
            'legend_position': legend_position
        }
        self.series = []
    
    # This is the only method, needed to add series to the graph
    def add_series(self, values, name=None, color=None, gap=0, overlap=0, show_labels=True, category=None):
        self.series.append({
            'values': values,
            'name': name,
            'fill': {'color': color},
            'gap': gap,
            'overlap': overlap,
            'data_labels': {'value': show_labels},
            'categories': category
        })

class XLSXColumn:
    def __init__(self, column, size):
        self.column = column
        self.size = size

class XLSXFormat:
    def __init__(self, valign='vcenter', align='center', font_color='black', font_name='Calibri',
                 font_size=11, bold=False, text_wrap=False, bg_color='white', border=1, border_color='white'):
        self.styling = {
            'valign': valign,
            'align': align,
            'font_color': font_color,
            'font_name': font_name,
            'font_size': font_size,
            'bold': bold,
            'text_wrap': text_wrap,
            'bg_color': bg_color,
            'border': border,
            'border_color': border_color
        }
        
class XLSXWorksheetDefaultData:
    def __init__(self, default_unique_cells = [], default_merged_cells = [], default_graphs = []):
        self.default_unique_cells = default_unique_cells
        self.default_merged_cells = default_merged_cells
        self.default_graphs = default_graphs

class XLSXWorksheet:
    def __init__(self, name, show_gridlines, column_sizing):
        self.name = name
        self.unique_cells = []
        self.merged_cells = []
        self.graphs = []
        self.column_sizing = column_sizing
        self.show_gridlines = show_gridlines
