import pickle
import csv
import os
import time
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

BIPARTITE_GRAPH_PATH = config.get('PATH','BIPARTITE_GRAPH_PATH')              # 이분그래프가 저장되어 있는 폴더
FILE_SIMILARITY_CSV_PATH = config.get('PATH','FILE_SIMILARITY_CSV_PATH')         # 유사도 결과 리포트가 저장되어 있는 폴더
ATTRIBUTE_LIST = config.get('PARAMETER','ATTRIBUTE_LIST').split(',')            # 유사도 분석 및 파일 전처리를 통한 특징정보 추출을 할 경우  추출할 특징정보들을 입력해준다 (입력은 각각의 특징정보에 해당하는 확장자를 입력하고 "," 로 구분된다.)
MAX_ATTRIBUTE = config.get('PARAMETER','MAX_ATTRIBUTE')                       # 유사도 분석을 할 파일들을 필터링 하기 위한 변수(1이상의 정수)  숫자가 낮을수록 필터링이 많이되어 속도가 빨라진다.
MIN_SIMILARITY = config.get('PARAMETER','MIN_SIMILARITY')                      # 출력 될 수 있는 최소 유사도 0 부터 1사이 숫자로 0이면 모든 유사도 분석에 대한 출력이 되고 1이면 유사도가 거의 똑같은 파일들이 출력이된다.
VIEW_DETAIL = config.get('PARAMETER','VIEW_DETAIL')                               # 결과 리포트 특징정보 세부 출력 유무(y 또는 n)
SEARCH_LABEL_LIST = config.get('PARAMETER','SEARCH_LABEL_LIST').split(',')             # 이분그래프 검색 또는 갱신할 레이블 이름(폴더 이름)


ATTRIBUTE_PATH = config.get('PATH','ATTRIBUTE_PATH')                           # 특징정보가 저장되어 있는 폴더
PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')                     # pe32검사후 파일이 저장되어 있는 폴더
IDB_PATH = config.get('PATH','IDB_PATH')                                      # idb 파일이 저장되어 있는 폴더
REPORT_PATH = config.get('PATH','REPORT_PATH')                                # 동적분석 리포트가 저장되어 있는 폴더
MALWARE_PATH = config.get('PATH','MALWARE_PATH')                             # 분석 파일이 저장되어 있는 폴더

UPDATE = config.get('PARAMETER','UPDATE')                                # 이분 그래프 갱신 유무(y 또는 n)

""" 
    
    학습모델 생성후 단순히 검색을 위한

"""

def make_weight():
    file_list = os.listdir(BIPARTITE_GRAPH_PATH)
    if SEARCH_LABEL_LIST[0] == '':                             #SEARCH_LABEL_LIST 옵션이 비어있을때 전체 그룹으로 설정
        search_labels = os.listdir(ATTRIBUTE_PATH)
    else:
        search_labels = SEARCH_LABEL_LIST
    for search_label in search_labels:
        for attribute in ATTRIBUTE_LIST:
            if os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, 'file_'+ attribute + '_dict.pickle')):
                with open(os.path.join(BIPARTITE_GRAPH_PATH, 'file_'+ attribute + '_dict.pickle'), 'rb') as handle:        # 이분 그래프 로드
                    file_dict = pickle.load(handle)
            else:
                print("그래프가 없습니다!")
                continue

            if os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, attribute+'_file_dict.pickle')):
                with open(os.path.join(BIPARTITE_GRAPH_PATH, attribute+'_file_dict.pickle'), 'rb') as handle2:            # 이분 그래프 로드
                    attribute_dict = pickle.load(handle2)
            else:
                print("그래프가 없습니다!")
                continue

            if os.path.exists(os.path.join(BIPARTITE_GRAPH_PATH, attribute + '_label_dict.pickle')):
                with open(os.path.join(BIPARTITE_GRAPH_PATH, attribute + '_label_dict.pickle'), 'rb') as handle:          # 이분 그래프 로드
                    group_dict = pickle.load(handle)
            else:
                print("그래프가 없습니다!")
                continue

            print("bipartite 그래프 불러오기")
            print("파일개수:", file_dict.__len__())
            print("특징개수:", attribute_dict.__len__())

            if attribute+'_file_dict.pickle' and 'file_'+attribute+'_dict.pickle' in file_list:    #  이분 그래프가 존재하는지 확인한다
                print(attribute, '실행중')
                start_time = time.time()
                SEARCH_FILE_ATTRIBUTE_PATH = os.path.join(ATTRIBUTE_PATH,search_label,attribute)
                if not os.path.exists(SEARCH_FILE_ATTRIBUTE_PATH):                              # 검색하려는 파일의 특징정보가 있는지 확인
                    print('preprocessing 과정이 필요합니다.')
                    continue
                print("새로운 데이터 불러오기","(",search_label,")")
                sfile_dict, satt_dict = make_att_set(SEARCH_FILE_ATTRIBUTE_PATH)                # 새로운 데이터에 대한 bipartite그래프 생성
                print("새로운 파일개수:", sfile_dict.__len__())
                print("새로운 특징개수:", satt_dict.__len__())
                print("새로운 데이터 불러오기 완료")
                print("분석 시작")
                attribute_compare(sfile_dict,file_dict,attribute_dict,group_dict,attribute,search_label)      # 유사성 분석
                print("분석 종료")
                if UPDATE == 'y' or  UPDATE == 'Y':
                    print('그래프 업데이트 시작')
                    update_bipartite(file_dict,attribute_dict, group_dict, sfile_dict, satt_dict,attribute,search_label)  # 새로운 데이터에 대한 bipartite 그래프 업데이트
                    print('그래프 업데이트 완료')
                print(attribute, '완료')
                end_time = time.time()
                print('total time: {}s'.format(int(end_time - start_time)))
            else:
                print(attribute+'_file_dict.pickle',' 또는 ','file_'+ attribute +'_dict.pickle',' 파일이 없습니다.')


"""

    attribute의 가중치를 구하고 유사도를 구하는 함수
    sfile_dict: 새롭게 입력되는 파일의 bipartite 그래프  
    file_dict:  사전 키:파일이름  값:특징정보
    attribute_dict:  사전  키:특징정보  값:파일이름
    group_dict: 사전 키: 파일  값: 레이블
    attribute: 특정정보 종류
    search_label: 검색하려는 레이블

"""
def attribute_compare(sfile_dict,file_dict,attribute_dict,group_dict,attribute,search_label):
    for search_file in sfile_dict:
        pair_info = dict()
        candidate_file_set = set()
        for y in sfile_dict[search_file].keys():  # 파일의 해당되는 attribute를 검색
            if y in attribute_dict:
                if len(attribute_dict[y].keys()) > int(MAX_ATTRIBUTE) :
                    continue
                else:
                    for z in attribute_dict[y].keys():   # 해당 attribute를 가지고 있는 파일들을 검색한다.
                        candidate_file_set.add(z)
        for candidate_file in candidate_file_set:     # 파일 후보군들의 attribute를 비교하여 교집합과 합집합을 구한다.
            if candidate_file == search_file:
                continue
            attribute_intersection = file_dict[candidate_file].keys() & sfile_dict[search_file].keys()
            attribute_union = file_dict[candidate_file].keys() | sfile_dict[search_file].keys()
            inter_pair_weight = 0.0
            union_pair_weight = 0.0
            for element in attribute_intersection:  # attribute 들의 weight 값을 구한다.  attribute를 참조하고 있는 파일의 역수의 제곱 IDF의 제곱
                if element in attribute_dict:
                    weight = attribute_dict[element].__len__()
                else:
                    weight = 1
                if not weight == 0:
                    inter_pair_weight += (1 / (weight*weight))
            for element in attribute_union:
                if element in attribute_dict:
                    weight = attribute_dict[element].__len__()
                else:
                    weight = 1
                if not weight == 0:
                    union_pair_weight += (1 / (weight*weight))
            pairname = search_file + '||' + candidate_file
            similarity = inter_pair_weight / union_pair_weight   # 최종 유사도
            if similarity > float(MIN_SIMILARITY):               # 출력되는 최소 유사도 조건
                if VIEW_DETAIL == 'y':                           # 세부 정보 출력 여부
                    pair_info[pairname] = [inter_pair_weight / union_pair_weight, attribute_intersection]
                else:
                    pair_info[pairname] = [inter_pair_weight / union_pair_weight]
        if pair_info.__len__() > 0:                # 유사한 파일이 한개라도 있을경우 출력
            make_csv(group_dict,pair_info,search_file,attribute,search_label)

"""
    특징정보에 대한 이분 그래프 생성
    path : 특징정보가 저장되어있는 폴더경로
    attribute : 이분그래프를 생성할 특징정보종류
"""

def make_att_set(path):
    file_list = os.listdir(path)
    file_att_list = dict()   # 키: 파일  값: 특징정보인 사전생성
    att_file_list = dict()   # 키: 특징정보  값: 파일인 사전생성
    for file in file_list:
        file_path = file.split('.')
        with open(os.path.join(path,file), 'rb') as f:
            maldata = pickle.load(f)
        if maldata.__len__() < 1:   # 빈파일은 필터링
            continue
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

    return file_att_list,att_file_list


"""

    유사도 분석 최종 출력 부분 csv 형태로 출력
    
"""
def make_csv(group_dict,pair_info,filename,attribute,search_label):
    if not os.path.isdir(FILE_SIMILARITY_CSV_PATH +'/'+ search_label):      # 결과 리포트 폴더가 없을시 생성
        os.mkdir(FILE_SIMILARITY_CSV_PATH +'/'+ search_label)
    if not os.path.isdir(FILE_SIMILARITY_CSV_PATH + '/' + search_label + '/' + attribute ):
        os.mkdir(FILE_SIMILARITY_CSV_PATH + '/' + search_label + '/' +attribute)
    with open(FILE_SIMILARITY_CSV_PATH + '/' + search_label + '/' +attribute +'/' + filename + '.csv', 'w', encoding='utf-8', newline='') as f:  # 결과 리포트 생성
        writer = csv.writer(f)
        writer.writerow(['file1', 'file2','file1gruop','file2group', 'similarity'])
        for i in pair_info:
            tmp = i.split('||')
            group2 = ''
            if tmp[0] == tmp[1]:
                continue
            if tmp[1] in group_dict:
                group2 = group_dict[tmp[1]]
            csv_list = [tmp[0], tmp[1], search_label, group2, pair_info[i][0]]
            if VIEW_DETAIL == 'y':
                for x in pair_info[i][1]:
                    csv_list.append(x)
                writer.writerow(csv_list)
            else:
                writer.writerow(csv_list)

"""

    bipartite 그래프 업데이트 
    
"""

def update_bipartite(file_dict,attribute_dict, group_dict, sfile_dict, satt_dict,attribute,search_label):
    print("이전 bipartite 파일개수",file_dict.__len__())
    for x in sfile_dict:                      #기존 bipartite 그래프에 없는 요소 추가
        if x not in file_dict:
            file_dict[x] = sfile_dict[x]
    print("이후 bipartite 파일개수",file_dict.__len__())
    print("이전 bipartite 특징개수", attribute_dict.__len__())
    for x in satt_dict:                       #기존 bipartite 그래프에 있는 요소 추가
        if x in attribute_dict:
            attribute_dict[x] = {**attribute_dict[x],**satt_dict[x]}
        else:
            attribute_dict[x] = satt_dict[x]
    print("이후 bipartite 특징개수", attribute_dict.__len__())
    for x in sfile_dict:                      #기존 bipartite 그래프에 없는 그룹 추가
        if x in group_dict:
            print(x,":파일레이블이 중복됩니다!","(",group_dict[x],",",search_label,")")
        group_dict[x] = search_label


    with open(BIPARTITE_GRAPH_PATH + '\\' + attribute+'_label_dict.pickle', 'wb') as handle:    # 다음 사전을 pickle 파일로 저장한다.
        pickle.dump(group_dict, handle)
    with open(BIPARTITE_GRAPH_PATH + '\\' + attribute+'_file_dict.pickle', 'wb') as handle:
        pickle.dump(attribute_dict, handle)
    with open(BIPARTITE_GRAPH_PATH + '\\' + 'file_' + attribute + '_dict.pickle', 'wb') as handle:
        pickle.dump(file_dict, handle)

if __name__ == "__main__":
    make_weight()