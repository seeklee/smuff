import json
import os
import pickle
import multiprocessing as mp
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

REPORT_PATH = config.get('PATH','REPORT_PATH')                          # 동적분석 리포트가 저장되어 있는 폴더
ATTRIBUTE_PATH = config.get('PATH','ATTRIBUTE_PATH')                         # 특징정보가 저장되어 있는 폴더
ATTRIBUTE_LIST = config.get('PARAMETER','ATTRIBUTE_LIST').split(',')              # 유사도 분석 및 파일 전처리를 통한 특징정보 추출을 할 경우  추출할 특징정보들을 입력해준다 (입력은 각각의 특징정보에 해당하는 확장자를 입력하고 "," 로 구분된다.)
N_GRAM = config.get('PARAMETER','N_GRAM')                             # API CALL SEQUENCE 에서 n-gram시 사용되는 윈도우의 크기(1이상의 정수)


"""
    동적분석 리포트들을 불러 온다.
"""
def get_report_path_list(path):
    ret = []
    for path, dir, files in os.walk(path):
        if not dir:
            for file in files:
                ret.append(os.path.join(path, file))

    return ret


def mutex(report):
    ret = []

    try:
        for mut in report["behavior"]["summary"]["mutex"]:                  # 동적분석 리포트 파싱부분
            ret.append(mut)

        ret.append(report["target"]["file"]["yara"]["meta"]["description"])
    except:
        return ret

    return ret


"""
    PDB_path 를 부분부분 쪼개는 코드 
    
    예)E:\ban\data\fh_feature\benign   -> E, ban, data, fh_feature, benign
"""
def pdb_shingling(ret):
    pdb_shingle = list()
    for pdb_string in ret:
        pdb_string = pdb_string.split('.')[0]
        pdb_dir = pdb_string.split('\\')
        pdb_shingle += pdb_dir
    return pdb_shingle

def pdb(report):
    ret = []

    try:
        if len(report["static"]["pdb_path"])>0 and report["static"]["pdb_path"].split('.')[-1] == 'pdb' :         # 동적분석 리포트 파싱부분
            ret.append(report["static"]["pdb_path"])
    except:
        pass

    return pdb_shingling(ret)   #PDB_path 를 부분부분 쪼개는 코드

def strings(report):
    ret = []
    try:
        if len(report["strings"]) > 0:                      # 동적분석 리포트 파싱부분
            for string in report["strings"]:
                ret.append(string)
    except:
        return ret

    return ret


def ip(report):
    ret = []

    dst_num = len(report["network"]["tcp"])                   # 동적분석 리포트 파싱부분
    for i in range(0, dst_num + 1):
        try:
            ret.append(report["network"]["tcp"][i]["dst"])
        except IndexError:
            return ret

    return ret


def apiset(report):
    ret = []

    try:
        processes = report["behavior"]["processes"]               # 동적분석 리포트 파싱부분
        for i in range(0, len(processes)):
            tmp = []
            if processes[i]["track"]:
                for j in range(0, len(processes[i]["calls"])):
                    tmp.append(processes[i]["calls"][j]["api"])
                ret.append(tmp)
    except:
        pass

    return ret

def api_sequence(report):
    ret = []
    lret = []
    apise = []
    try:
        processes = report["behavior"]["processes"]                  # 동적분석 리포트 파싱부분
        for i in range(0, len(processes)):
            tmp = []
            if processes[i]["track"]:
                for j in range(0, len(processes[i]["calls"])):
                    tmp.append(processes[i]["calls"][j]["api"])
                ret.append(tmp)
    except:
        pass
    for x in ret:
        lret += x
    for x in range(lret.__len__()-N_GRAM):          # api call sequence를 n-gram을 하여 저장한다.
        haha = ""
        for y in range(N_GRAM):
            haha += lret[x+y] + '_'
        apise.append(haha)
    return apise


def domain(report):
    ret = []

    try:
        domain_num = len(report["network"]["domains"])                # 동적분석 리포트 파싱부분
        if domain_num > 0:
            for i in range(0, domain_num + 1):
                ret.append(report["network"]["domains"][i]["domain"])
    except:
        return ret

    return ret


def parsing(path):
    dirname = path.split(os.sep)[-2]
    filename = path.split(os.sep)[-1]

    if path.split(os.sep)[-1] != "classify.csy":
        DAT_STRING_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"str", filename + ".str")                    # 특징정보가 저장될 경로를 설정한다.
        DAT_DOMAINS_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"dom", filename + ".dom")
        DAT_IP_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"ip", filename + ".ip")
        DAT_MUTEX_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"mut", filename + ".mut")
        DAT_API_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"apiset",  filename + ".apiset")
        DAT_PDB_PATH = os.path.join(ATTRIBUTE_PATH, dirname,"pdb", filename + ".pdb")
        DAT_APICS_PATH = os.path.join(ATTRIBUTE_PATH, dirname, "apics", filename + ".apics")

        if os.path.exists(DAT_STRING_PATH):                               # 이미 특징정보가 존재할 경우 생략
            return 0
        if os.path.exists(DAT_DOMAINS_PATH):
            return 0
        if os.path.exists(DAT_IP_PATH):
            return 0
        if os.path.exists(DAT_MUTEX_PATH):
            return 0
        if os.path.exists(DAT_API_PATH):
            return 0
        if os.path.exists(DAT_PDB_PATH):
            return 0
        if os.path.exists(DAT_APICS_PATH):
            return 0

        with open(path) as f:
            try:
                report = json.load(f)                                # 동적 분석 리포트를 불러온다.
                                                                     # 특징정보들을 동적 분석 리포트에서 추출한다.
                str_list = strings(report)                           # 문자열 추출
                domain_list = domain(report)                         # 도메인 추출
                ip_list = ip(report)                                 # IP 추출
                mut_list = mutex(report)                             # 뮤텍스 추출
                apiset_list = apiset(report)                         # API 집합 추출
                pdb_list = pdb(report)                               # PDB PATH 추출
                apics_list = api_sequence(report)                    # API CALL SEQUENCE 추출

                if len(str_list) > 0:
                    with open(DAT_STRING_PATH, 'wb') as str_dat:
                        pickle.dump(str_list, str_dat)               # 추출후 파일로 저장
                if len(domain_list) > 0:
                    with open(DAT_DOMAINS_PATH, 'wb') as dom_dat:
                        pickle.dump(domain_list, dom_dat)
                if len(ip_list) > 0:
                    with open(DAT_IP_PATH, 'wb') as ip_dat:
                        pickle.dump(ip_list, ip_dat)
                if len(mut_list) > 0:
                    with open(DAT_MUTEX_PATH, 'wb') as mut_dat:
                        pickle.dump(mut_list, mut_dat)
                if len(apiset_list) > 0:
                    with open(DAT_API_PATH, 'wb') as api_dat:
                        pickle.dump(apiset_list, api_dat)
                if len(pdb_list) > 0:
                    with open(DAT_PDB_PATH, 'wb') as pdb_dat:
                        pickle.dump(pdb_list, pdb_dat)
                if len(apics_list) > 0:
                    with open(DAT_APICS_PATH, 'wb') as apics_dat:
                        pickle.dump(apics_list, apics_dat)
                print("리포트 생성완료")

            except:
                print("report read error")
    print("Parsing Complete")


def run(PATH):
    report_list = get_report_path_list(PATH) # 동적분석 리포트들을 불러 온다.
    p = mp.Pool(os.cpu_count())
    p.map(parsing, report_list)   # 동적분석 리포트를 이용하여 특징정보를 추출한다.


"""

    특징정보별 폴더 생성

"""
def make_dir(REPORT_PATH):
    dirnames = os.listdir(REPORT_PATH)
    for dirname in dirnames:
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH, dirname)):
            os.mkdir(os.path.join(ATTRIBUTE_PATH, dirname))
        for attribute in ATTRIBUTE_LIST:
            if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,attribute)):
                os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,attribute))             # 폴더 생성

def report_parser():
    make_dir(REPORT_PATH)  # 특징정보를 저장할 폴더들을 생성한다.
    run(REPORT_PATH)       # 리포트를 이용하여 특징정보를 추출한다.


if __name__ == '__main__':
    report_parser()


