import configparser
import pe_test
import make_idb_ops
import os
import pickle
import upload

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')      # pe32검사후 파일이 저장되어 있는 폴더
DATA_PATH = config.get('PATH','DATA_PATH')                     # SMUFF의 데이터가 저장되어 있는 폴더

"""

    파일들의 공격그룹(폴더) 저장
    동적분석 요청후 리포트들을 공격 그룹별로 분류할때 이용된다.

"""

def colldata():
    dirs = os.listdir(PE32_MALWARE_PATH)           # 경로 안에 있는 폴더들을 검색
    filelist = dict()
    for dir in dirs:
        files = os.listdir(os.path.join(PE32_MALWARE_PATH,dir))  # 폴더 안에 있는 파일들을 검색
        for x in files:
            filelist[x.split('.')[0]] = dir
    with open(os.path.join(DATA_PATH, 'file_dir_dict.pickle'), 'wb') as handle:       # 파일 디렉토리 구조들을 pickle파일로 사전형태로 저장
        pickle.dump(filelist, handle)


"""

    파일 전처리 하는 단계
    1.파일이름 md5변환, exe32필터링
    2.파일들의 공격그룹 저장 (동적분석 리포트를 그룹분류 할 때 쓰임)    예) {파일이름 : 공격그룹, 파일이름 : 공격그룹}
    3.동적분석 요청
    4.정적분석을 통한 코드정보 추출

"""
if __name__ == '__main__':
    pe_test.pe_test()               # 1.파일이름 md5변환, exe32필터링
    colldata()                      # 2.파일들의 공격그룹 저장
    upload.upload_report()          # 3.동적분석 요청
    make_idb_ops.static_analysis()  # 4.정적분석을 통한 코드정보 추출
