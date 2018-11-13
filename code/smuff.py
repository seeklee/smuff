import report_parser
import make_bipartite
import search
import pickle
import configparser
import os
import shutil

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

UPDATE = config.get('PARAMETER','UPDATE')

ATTRIBUTE_LIST = config.get('PARAMETER','ATTRIBUTE_LIST').split(',')
DATA_PATH = config.get('PATH','DATA_PATH')
FTP_PATH = config.get('PATH','FTP_PATH')
REPORT_PATH = config.get('PATH','REPORT_PATH')
BIPARTITE_GRAPH_PATH = config.get('PATH','BIPARTITE_GRAPH_PATH')


def download_report():
    with open(DATA_PATH + '\\file_dir_dict.pickle', 'rb') as handle:
        file_dict = pickle.load(handle)
        files = os.listdir(FTP_PATH)
        for report_file in files:
            if report_file.split('.')[0] in file_dict:
                dir = file_dict[report_file.split('.')[0]]
                if not os.path.exists(os.path.join(REPORT_PATH,dir)):
                    try:
                        os.makedirs(os.path.join(REPORT_PATH,dir))
                    except:
                        pass
                shutil.move(os.path.join(FTP_PATH,report_file),os.path.join(REPORT_PATH,dir,report_file))



if __name__ == '__main__':
    download_report()
    print("리포트 이동완료")
    report_parser.report_parser()
    print("cuckoo attribute 추출완료")
    for attribute in ATTRIBUTE_LIST:
        if not os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, 'file_' + attribute + '_dict.pickle')) or \
           not os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, attribute + '_file_dict.pickle')) or \
           not os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, attribute + '_label_dict.pickle')):
                print("그래프 초기화중")
                make_bipartite.make_attribute_set()
                print("그래프 생성완료")
    search.make_weight()
    print("종료")