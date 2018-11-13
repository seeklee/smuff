import configparser
import os

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

UPDATE = config.get('PARAMETER','UPDATE')
DATA_PATH = config.get('PATH','DATA_PATH')
BIPARTITE_GRAPH_PATH = config.get('PATH','BIPARTITE_GRAPH_PATH')
FILE_SIMILARITY_CSV_PATH = config.get('PATH','FILE_SIMILARITY_CSV_PATH')
MALWARE_PATH = config.get('PATH','MALWARE_PATH')
PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')
ATTRIBUTE_PATH = config.get('PATH','ATTRIBUTE_PATH')
REPORT_PATH = config.get('PATH','REPORT_PATH')
IDB_PATH = config.get('PATH','IDB_PATH')
FTP_PATH = config.get('PATH','FTP_PATH')


def make_basefolder():
    if not os.path.exists(BIPARTITE_GRAPH_PATH):
        try:
            os.makedirs(BIPARTITE_GRAPH_PATH)
        except:
            pass
    if not os.path.exists(FILE_SIMILARITY_CSV_PATH):
        try:
            os.makedirs(FILE_SIMILARITY_CSV_PATH)
        except:
            pass
    if not os.path.exists(DATA_PATH):
        try:
            os.makedirs(DATA_PATH)
        except:
            pass
    if not os.path.exists(MALWARE_PATH):
        try:
            os.makedirs(MALWARE_PATH)
        except:
            pass
    if not os.path.exists(PE32_MALWARE_PATH):
        try:
            os.makedirs(PE32_MALWARE_PATH)
        except:
            pass
    if not os.path.exists(ATTRIBUTE_PATH):
        try:
            os.makedirs(ATTRIBUTE_PATH)
        except:
            pass
    if not os.path.exists(REPORT_PATH):
        try:
            os.makedirs(REPORT_PATH)
        except:
            pass
    if not os.path.exists(IDB_PATH):
        try:
            os.makedirs(IDB_PATH)
        except:
            pass
    if not os.path.exists(FTP_PATH):
        try:
            os.makedirs(FTP_PATH)
        except:
            pass
if __name__ == '__main__':
    make_basefolder()
