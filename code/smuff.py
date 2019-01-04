import make_bipartite
import search
import configparser
import os

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')


ATTRIBUTE_LIST = config.get('PARAMETER','ATTRIBUTE_LIST').split(',')         # 유사도 분석 및 파일 전처리를 통한 특징정보 추출을 할 경우  추출할 특징정보들을 입력해준다 (입력은 각각의 특징정보에 해당하는 확장자를 입력하고 "," 로 구분된다.)
BIPARTITE_GRAPH_PATH = config.get('PATH','BIPARTITE_GRAPH_PATH')            #  이분그래프가 저장되어 있는 폴더



if __name__ == '__main__':
    for attribute in ATTRIBUTE_LIST:
        if not os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, 'file_' + attribute + '_dict.pickle')) or \
           not os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, attribute + '_file_dict.pickle')) or \
           not os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, attribute + '_label_dict.pickle')):
                print("그래프 초기화중")
                make_bipartite.make_attribute_set()          # 3.이분 그래프를 생성한다.
                print("그래프 생성완료")
    search.make_weight()      # 4.유사도를 구한다.
    print("종료")