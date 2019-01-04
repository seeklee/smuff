# -*-coding:utf-8-*-
import requests, os
import time
import multiprocessing as mp
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

REST_URL = config.get('CUCKOO','REST_URL')  # 쿠쿠 샌드박스로 리포트 요청하는 주소 http://ip:포트/경로
PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')   # pe32검사후 파일이 저장되어 있는 폴더
REPORT_PATH = config.get('PATH','REPORT_PATH')            # 동적분석 리포트가 저장되어 있는 폴더
CPU_COUNT = int(config.get('PARAMETER','CPU_COUNT'))        # 멀티 프로세싱으로 이용할 cpu 코어의 개수(1이상의 정수)



"""

    동적분석 요청 파일 목록들 불러오는 함수

"""
def explorer(root):
    ret = []

    for p, dir, files in os.walk(root):
        if not dir:
            for file in files:
                groupname = p.split(os.path.sep)[-1]
                filename = file.split('.')[0] +'.json'
                if not os.path.exists(os.path.join(REPORT_PATH,groupname,filename)):
                    ret.append(os.path.join(p, file))

    return ret

"""

    동적분석 요청을 위해 전송하는 함수

"""
def send_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_name = get_file_name(file_path)
            fs = {'file': (file_name, f)}
            r = requests.post(REST_URL, files=fs)
            if r.status_code == 200:
                print("{} is succeeded".format(file_name))
            else:
                print("{} is failed".format(file_name))
    except Exception as e:
        raise ValueError("연결이 되지 않습니다.")


def run(root):
    file_path_list = explorer(root)            # 동적분석 요청 파일 목록들 불러온다
    mp.freeze_support()
    p = mp.Pool(CPU_COUNT)                 # 멀티 프로세스 설정
    p.map(send_file, file_path_list)

def get_file_name ( file_path ) :
    return os.path.basename(file_path)


def upload_report():
    start = time.time()
    run(PE32_MALWARE_PATH)
    print("Time : {}".format(time.time() - start))

if __name__ == '__main__':
    upload_report()
