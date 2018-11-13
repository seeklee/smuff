import pickle
import hashlib
import os
import csv
import time
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

ATTRIBUTE_PATH = config.get('PATH','ATTRIBUTE_PATH')
BIPARTITE_GRAPH_PATH = config.get('PATH','BIPARTITE_GRAPH_PATH')
ATTRIBUTE_LIST = config.get('PARAMETER','ATTRIBUTE_LIST').split(',')

"""attribute 에 대한 bipartite 그래프 생성"""
def make_attribute_set():
    if not os.path.isdir(BIPARTITE_GRAPH_PATH):
        os.path.mkdir(BIPARTITE_GRAPH_PATH)
    for attribute in ATTRIBUTE_LIST:
        print(attribute + '에 대한 bipartite 그래프를 생성합니다.')
        start_time = time.time()
        make_att_set(ATTRIBUTE_PATH,attribute)
        end_time = time.time()
        print('total time: {}s'.format(int(end_time - start_time)))
        print('완료')

"""
    attribute 에 대한 bipartite 그래프 생성
"""

def make_att_set(path,attribute):
    group_list = os.listdir(path)
    file_att_list = dict()   # 키: 파일  값: 함수인 사전생성
    att_file_list = dict()   # 키: 함수  값: 파일인 사전생성
    file_label_list = dict()  # 키: 파일  값: 레이블인 사전생성
    for group in group_list:
        group_att_path = path + "/" + group + "/" + attribute
        if not os.path.exists(group_att_path):
           continue
        file_list = os.listdir(group_att_path)
        for file in file_list:
            file_path = file.split('.')
            with open(group_att_path + "/" + file, 'rb') as f:
                maldata = pickle.load(f)
            if maldata.__len__() < 1:   # 빈파일은 필터링
                continue
            file_label_list[file_path[0]] = group
            for func in maldata:
                if not func in att_file_list:    # {function : { filename : num1,filename2 : num2 ..} function2 : {} ...}
                    att_file_list[func] = dict()
                    att_file_list[func][file_path[0]] = 1
                else:
                    if file_path[0] in att_file_list[func]:
                        att_file_list[func][file_path[0]] += 1
                    else:
                        att_file_list[func][file_path[0]] = 1

                if not file_path[0] in file_att_list:         # {filename : { function : num1,function2 : num2 ..} filename2 : {} ...}
                    file_att_list[file_path[0]] = dict()
                    file_att_list[file_path[0]][func] = 1
                else:
                    if func in file_att_list[file_path[0]]:
                        file_att_list[file_path[0]][func] += 1
                    else:
                        file_att_list[file_path[0]][func] = 1

    with open(BIPARTITE_GRAPH_PATH + '\\' + attribute+'_label_dict.pickle', 'wb') as handle:    # 다음 사전을 pickle 파일로 저장한다.
        pickle.dump(file_label_list, handle)
    with open(BIPARTITE_GRAPH_PATH + '\\' + attribute+'_file_dict.pickle', 'wb') as handle:    # 다음 사전을 pickle 파일로 저장한다.
        pickle.dump(att_file_list, handle)
    print("특징개수",att_file_list.__len__())
    with open(BIPARTITE_GRAPH_PATH + '\\' + 'file_' + attribute + '_dict.pickle', 'wb') as handle2:
        pickle.dump(file_att_list, handle2)
    print("파일개수:", file_att_list.__len__())


if __name__ == "__main__":
    make_attribute_set()