from .models import XLSXWorksheetDefaultData, XLSXCell, XLSXMergedCell, XLSXGraph
from .constants import Constants 

#######################################################################
#  File: default_worksheets.py                                        #
#                                                                     #
#  This file is used to hold some classes to initialize all default   #
#  data on the worksheets                                             #
#######################################################################

#######################################################################
#  Class: ResumeDefaultData                                           #
#  Inherits from: XLSXWorksheetDefaultData                            #
#  Used for: initialize all default data for the 'Resumen' worksheet  #
#######################################################################

class ResumeDefaultData(XLSXWorksheetDefaultData):
    # UNIQUE_CELLS is a list of cells to be printed on the excel
    UNIQUE_CELLS = [
        XLSXCell(                'Riesgo', 1,  7, Constants.FORMAT_02),
        XLSXCell(                     'N', 2,  7, Constants.FORMAT_02),
        XLSXCell(                     '%', 3,  7, Constants.FORMAT_02),
        XLSXCell(                  'Bajo', 1,  8, Constants.FORMAT_02),
        XLSXCell(                 'Medio', 1,  9, Constants.FORMAT_02),
        XLSXCell(                  'Alto', 1, 10, Constants.FORMAT_02),
        XLSXCell(               'Crítico', 1, 11, Constants.FORMAT_02),
        XLSXCell(             'Categoría', 1, 14, Constants.FORMAT_02),
        XLSXCell(                     'N', 2, 14, Constants.FORMAT_02),
        XLSXCell(                     '%', 3, 14, Constants.FORMAT_02),
        XLSXCell(                     '%', 3, 14, Constants.FORMAT_02),
        XLSXCell('Operative System Patch', 1, 15, Constants.FORMAT_02),
        XLSXCell(                'Config', 1, 16, Constants.FORMAT_02),
        XLSXCell(        'Out of Support', 1, 17, Constants.FORMAT_02),
        XLSXCell(                'Cypher', 1, 18, Constants.FORMAT_02),
        XLSXCell( 'Product Vulnerability', 1, 19, Constants.FORMAT_02),
        XLSXCell('Operative System Patch', 1, 23, Constants.FORMAT_02),
        XLSXCell(                'Config', 1, 24, Constants.FORMAT_02),
        XLSXCell(        'Out of Support', 1, 25, Constants.FORMAT_02),
        XLSXCell(                'Cypher', 1, 26, Constants.FORMAT_02),
        XLSXCell( 'Product Vulnerability', 1, 27, Constants.FORMAT_02),
        XLSXCell(             'Categoría', 1, 22, Constants.FORMAT_02)
    ]
    # MERGED_CELLS is a list of merged cells to be printed on the excel
    MERGED_CELLS = [
        XLSXMergedCell(              'Hosts analizados', 1,  1, 2,  1, Constants.FORMAT_01),
        XLSXMergedCell(             'Hosts vulnerables', 1,  2, 2,  2, Constants.FORMAT_01),
        XLSXMergedCell(              'Vulnerabilidades', 1,  4, 2,  4, Constants.FORMAT_01),
        XLSXMergedCell(              'Vulnerabilidades', 1,  6, 3,  6, Constants.FORMAT_01),
        XLSXMergedCell('Vulnerabilidades por categoría', 1, 13, 3, 13, Constants.FORMAT_01),
        XLSXMergedCell(         'Riesgos por categoría', 1, 21, 9, 21, Constants.FORMAT_01),
        XLSXMergedCell(                          'Bajo', 2, 22, 3, 22, Constants.FORMAT_25),
        XLSXMergedCell(                         'Medio', 4, 22, 5, 22, Constants.FORMAT_26),
        XLSXMergedCell(                          'Alto', 6, 22, 7, 22, Constants.FORMAT_27),
        XLSXMergedCell(                       'Crítico', 8, 22, 9, 22, Constants.FORMAT_28)
    ]
    def __init__(self):
        super().__init__(self.UNIQUE_CELLS, self.MERGED_CELLS)
        
#######################################################################
#  Class: ReportsDefaultData                                          #
#  Inherits from: XLSXWorksheetDefaultData                            #
#  Used for: initialize all default data for the 'Informe' worksheet  #
#######################################################################

class ReportsDefaultData(XLSXWorksheetDefaultData):
    # UNIQUE_CELLS is a list of cells to be printed on the excel
    UNIQUE_CELLS = [
        XLSXCell(         'Identificador',  0, 0, Constants.FORMAT_05),
        XLSXCell(                'Título',  1, 0, Constants.FORMAT_05),
        XLSXCell(          'Dirección IP',  2, 0, Constants.FORMAT_05),
        XLSXCell(              'Servicio',  3, 0, Constants.FORMAT_05),
        XLSXCell(             'Protocolo',  4, 0, Constants.FORMAT_05),
        XLSXCell(                'Puerto',  5, 0, Constants.FORMAT_05),
        XLSXCell(                  'CVEs',  6, 0, Constants.FORMAT_05),
        XLSXCell(           'Autenticado',  7, 0, Constants.FORMAT_05),
        XLSXCell(        'Traza CVSS/3.0',  8, 0, Constants.FORMAT_05),
        XLSXCell(                  'CVSS',  9, 0, Constants.FORMAT_05),
        XLSXCell(                'Riesgo', 10, 0, Constants.FORMAT_05),
        XLSXCell('Tipo de Vulnerabilidad', 11, 0, Constants.FORMAT_05),
        XLSXCell(           'Descripción', 12, 0, Constants.FORMAT_05),
        XLSXCell(               'Impacto', 13, 0, Constants.FORMAT_05),
        XLSXCell(         'Recomendación', 14, 0, Constants.FORMAT_05),
        XLSXCell(         'Plugin Output', 15, 0, Constants.FORMAT_05),
        XLSXCell(           'Referencias', 16, 0, Constants.FORMAT_05),
        XLSXCell(     'Sistema Operativo', 17, 0, Constants.FORMAT_05)
    ]

    def __init__(self):
        super().__init__(self.UNIQUE_CELLS)

#####################################################################
#  Class: HostsDefaultData                                          #
#  Inherits from: XLSXWorksheetDefaultData                          #
#  Used for: initialize all default data for the 'Hosts' worksheet  #
#####################################################################

class HostsDefaultData(XLSXWorksheetDefaultData):
    # UNIQUE_CELLS is a list of cells to be printed on the excel
    UNIQUE_CELLS = [
        XLSXCell('IP',  1, 3, Constants.FORMAT_04),
        XLSXCell( 'N',  3, 3, Constants.FORMAT_04),
        XLSXCell( '%',  4, 3, Constants.FORMAT_04),
        XLSXCell( 'N',  5, 3, Constants.FORMAT_04),
        XLSXCell( '%',  6, 3, Constants.FORMAT_04),
        XLSXCell( 'N',  7, 3, Constants.FORMAT_04),
        XLSXCell( '%',  8, 3, Constants.FORMAT_04),
        XLSXCell( 'N',  9, 3, Constants.FORMAT_04),
        XLSXCell( '%', 10, 3, Constants.FORMAT_04),
        XLSXCell( 'N', 11, 3, Constants.FORMAT_04),
        XLSXCell( '%', 12, 3, Constants.FORMAT_04),
        XLSXCell( 'N', 13, 3, Constants.FORMAT_04),
        XLSXCell( '%', 14, 3, Constants.FORMAT_04),
        XLSXCell( 'N', 15, 3, Constants.FORMAT_04),
        XLSXCell( '%', 16, 3, Constants.FORMAT_04),
        XLSXCell( 'N', 17, 3, Constants.FORMAT_04),
        XLSXCell( '%', 18, 3, Constants.FORMAT_04),
        XLSXCell( 'N', 19, 3, Constants.FORMAT_04),
        XLSXCell( '%', 20, 3, Constants.FORMAT_04),
        XLSXCell( 'N', 21, 3, Constants.FORMAT_04),
        XLSXCell( '%', 22, 3, Constants.FORMAT_04)
    ]
    # MERGED_CELLS is a list of merged cells to be printed on the excel
    MERGED_CELLS = [
        XLSXMergedCell(                 'Hosts',  1, 1,  1, 2, Constants.FORMAT_04),
        XLSXMergedCell(      'Puertos Abiertos',  2, 1,  2, 3, Constants.FORMAT_04),
        XLSXMergedCell(      'Vulnerabilidades',  3, 1,  4, 2, Constants.FORMAT_04),
        XLSXMergedCell(                'Riesgo',  5, 1, 12, 1, Constants.FORMAT_04),
        XLSXMergedCell(                  'Bajo',  5, 2,  6, 2, Constants.FORMAT_07),
        XLSXMergedCell(                 'Medio',  7, 2,  8, 2, Constants.FORMAT_08),
        XLSXMergedCell(                  'Alto',  9, 2, 10, 2, Constants.FORMAT_09),
        XLSXMergedCell(               'Crítico', 11, 2, 12, 2, Constants.FORMAT_10),
        XLSXMergedCell(             'Categoría', 13, 1, 22, 1, Constants.FORMAT_04),
        XLSXMergedCell('Operative System Patch', 13, 2, 14, 2, Constants.FORMAT_11),
        XLSXMergedCell(                'Config', 15, 2, 16, 2, Constants.FORMAT_12),
        XLSXMergedCell(        'Out Of Support', 17, 2, 18, 2, Constants.FORMAT_13),
        XLSXMergedCell(                'Cypher', 19, 2, 20, 2, Constants.FORMAT_14),
        XLSXMergedCell( 'Product Vulnerability', 21, 2, 22, 2, Constants.FORMAT_15)
    ]
    def __init__(self):
        super().__init__(self.UNIQUE_CELLS, self.MERGED_CELLS)