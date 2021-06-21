from .models import XLSXFormat

###########################################################
#  File: constants.py                                     #
#  Class: Constants                                       #
#  Used for: be more organized and clean                  #
#                                                         #
#  This file has all constants that the parser will need  #
###########################################################

class Constants:
    HOST_FILE_ROOT = 'Report/ReportHost'
    REPORT_FILE_ROOT = 'ReportItem'

    HOST_NAME = 'Host'
    HOST_OS_NAME = 'Tipo de SO'
    PORT_NAME = 'Port'
    PROTOCOL_NAME = 'Protocolo'
    RISK_NAME = 'Riesgo'
    PLUGIN_ID_NAME = 'ID del Plugin'
    PLUGIN_NAME_NAME = 'Nombre del Plugin'
    PLUGIN_FAMILY_NAME = 'Familia del Plugin' 

    FORMAT_01 = '1'
    FORMAT_02 = '2'
    FORMAT_03 = '3'
    FORMAT_04 = '4'
    FORMAT_05 = '5'
    FORMAT_06 = '6'
    FORMAT_07 = '7'
    FORMAT_08 = '8'
    FORMAT_09 = '9'
    FORMAT_10 = '10' 
    FORMAT_11 = '11'
    FORMAT_12 = '12'
    FORMAT_13 = '13'
    FORMAT_14 = '14'
    FORMAT_15 = '15'
    FORMAT_16 = '16'
    FORMAT_17 = '17'
    FORMAT_18 = '18'
    FORMAT_19 = '19'
    FORMAT_20 = '20'
    FORMAT_21 = '21'
    FORMAT_22 = '22'
    FORMAT_23 = '23'
    FORMAT_24 = '24'
    FORMAT_25 = '25' 
    FORMAT_26 = '26' 
    FORMAT_27 = '27'
    FORMAT_28 = '28' 
    FORMAT_29 = '29'
    FORMAT_30 = '30' 
    FORMAT_31 = '31'
    FORMAT_32 = '32' 
    FORMAT_33 = '33' 

    HOST = {
        HOST_NAME: 'HostProperties/tag/[@name=\'host-ip\']',
        HOST_OS_NAME: 'HostProperties/tag/[@name=\'operating-system\']'
    }

    REPORT = {
        PORT_NAME: 'port',
        PROTOCOL_NAME: 'protocol',
        RISK_NAME: 'severity'
    }

    PLUGIN = {
        PLUGIN_ID_NAME: 'pluginID',
        PLUGIN_NAME_NAME: 'pluginName',
        PLUGIN_FAMILY_NAME: 'pluginFamily'
    }

    ITEMS = {
        'Sinopsis': 'synopsis',
        'Descripción': 'description',
        'Solución': 'solution',
        'Plugin Output': 'plugin_output',
        'CVE': 'cve',
        'CVSS': 'cvss3_base_score',
        'Servicio': 'svc_name',
        'Referencias': 'see_also',
        'CVSS_trace': 'cvss3_vector'
    }

    RISKS = {
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 4
    }

    COLORS = {
        'blue_0': '#366092', # DB
        'blue_1': '#B8CCE4', # B
        'blue_2': '#EAEFF6', # LB
        'blue_3': '#4F81BD', # HDB
        'blue_4': '#788B17', # OSP 
        'green_0': '#9AAE04', # RPTITLE
        'green_1': '#00B050', # GREEN
        'green_2': '#2ECC71', # OOS
        'yellow': '#FFC000',
        'orange': '#F79646',
        'red_0': '#FF0000',
        'red_1': '#A11B1B', # CONFIG
        'purple': '#8E44AD', # CY
        'brown': '#D99694', # PV
        'low': '#385723',
        'medium': '#BF9000',
        'high': '#843C0C',
        'critical': '#CC0066',
        'low_bg': '#C5E0B3',
        'medium_bg': '#FFF2CC',
        'high_bg': '#F7CAAC',
        'critical_bg': '#FF8989',
        'OSP': '#788B17',
        'C': '#A11B1B',
        'CY': '#8E44AD',
        'PV': '#D99694',
        'OOS': '#2ECC71',
        'OSP_bg': '#E7F2B0',
        'C_bg': '#EC8C8C',
        'CY_bg': '#CAA2DA',
        'PV_bg': '#ECCBCA',
        'OOS_bg': '#ADEDC8'
    }

    PLUGIN_TYPES = [
        ('NaN', 'Not classified'),
        ('OSP', 'Operative System Patch'),
        ('C', 'Config'),
        ('CY', 'Cypher'),
        ('PV', 'Product Vulnerability'),
        ('OOS', 'Out of support')
    ]

    AVOID_PORTS = [
        '5060',
        '2000',
        '8008'
    ]

    # This dict initializes the format for the excell
    XLSX_FORMATS = {
        FORMAT_01: XLSXFormat(font_color='white', bold=True, bg_color=COLORS['blue_0']),
        FORMAT_02: XLSXFormat(bg_color=COLORS['blue_1']),
        FORMAT_03: XLSXFormat(bg_color=COLORS['blue_2']),
        FORMAT_04: XLSXFormat(font_color='white', bg_color=COLORS['blue_3']),
        FORMAT_05: XLSXFormat(font_color='white', font_name='Arial', font_size=9, bg_color=COLORS['green_0'], border_color='black'),
        FORMAT_06: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, bg_color='white', border_color='black'),
        FORMAT_07: XLSXFormat(font_color='white', bg_color=COLORS['green_1']),
        FORMAT_08: XLSXFormat(font_color='white', bg_color=COLORS['yellow']),
        FORMAT_09: XLSXFormat(font_color='white', bg_color=COLORS['orange']),
        FORMAT_10: XLSXFormat(font_color='white', bg_color=COLORS['red_0']),
        FORMAT_11: XLSXFormat(font_color='white', bg_color=COLORS['blue_4']),
        FORMAT_12: XLSXFormat(font_color='white', bg_color=COLORS['red_1']),
        FORMAT_13: XLSXFormat(font_color='white', bg_color=COLORS['green_2']),
        FORMAT_14: XLSXFormat(font_color='white', bg_color=COLORS['purple']),
        FORMAT_15: XLSXFormat(font_color='white', bg_color=COLORS['brown']),
        FORMAT_16: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['low'], bg_color=COLORS['low_bg'], border_color='black'),
        FORMAT_17: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['medium'], bg_color=COLORS['medium_bg'], border_color='black'),
        FORMAT_18: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['high'], bg_color=COLORS['high_bg'], border_color='black'),
        FORMAT_19: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['critical'], bg_color=COLORS['critical_bg'], border_color='black'),
        FORMAT_20: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['OSP'], bg_color=COLORS['OSP_bg'], border_color='black'),
        FORMAT_21: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['C'], bg_color=COLORS['C_bg'], border_color='black'),
        FORMAT_22: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['CY'], bg_color=COLORS['CY_bg'], border_color='black'),
        FORMAT_23: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['PV'], bg_color=COLORS['PV_bg'], border_color='black'),
        FORMAT_24: XLSXFormat(font_name='Arial', font_size=9, text_wrap=True, font_color=COLORS['OOS'], bg_color=COLORS['OOS_bg'], border_color='black'),
        FORMAT_25: XLSXFormat(font_color=COLORS['low'], bg_color=COLORS['low_bg']),
        FORMAT_26: XLSXFormat(font_color=COLORS['medium'], bg_color=COLORS['medium_bg']),
        FORMAT_27: XLSXFormat(font_color=COLORS['high'], bg_color=COLORS['high_bg']),
        FORMAT_28: XLSXFormat(font_color=COLORS['critical'], bg_color=COLORS['critical_bg']),
        FORMAT_29: XLSXFormat(font_color=COLORS['OSP'], bg_color=COLORS['OSP_bg']),
        FORMAT_30: XLSXFormat(font_color=COLORS['C'], bg_color=COLORS['C_bg']),
        FORMAT_31: XLSXFormat(font_color=COLORS['CY'], bg_color=COLORS['CY_bg']),
        FORMAT_32: XLSXFormat(font_color=COLORS['PV'], bg_color=COLORS['PV_bg']),
        FORMAT_33: XLSXFormat(font_color=COLORS['OOS'], bg_color=COLORS['OOS_bg'])
    }