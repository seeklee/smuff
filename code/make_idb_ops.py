import os
import subprocess
import configparser
import multiprocessing as mp
import time
import shutil

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

IDA_PATH = config.get('IDA','IDA_PATH')  # ida pro가 설치되어있는 경로
IDB_PATH = config.get('PATH','IDB_PATH')   # idb 파일이 저장되어 있는 폴더
CPU_COUNT = int(config.get('PARAMETER','CPU_COUNT'))   # 멀티 프로세싱으로 이용할 cpu 코어의 개수(1이상의 정수)
IDA_SCRIPT_PATH = config.get('PATH','IDA_SCRIPT_PATH')   # ida script가 저장되어 있는 폴더

PE32_MALWARE_PATH = config.get('PATH', 'PE32_MALWARE_PATH')     # pe32검사후 파일이 저장되어 있는 폴더
ATTRIBUTE_PATH = config.get('PATH', 'ATTRIBUTE_PATH')          # 특징정보가 저장되어 있는 폴더

"""

    idapro를 이용하여 함수 특징정보와 기본블록 특징정보를 추출하는 코드 
    file_path: exe32bit 파일의 경로
    
"""
def make_idb_ops(file_path):
    # define file path
    file_name = file_path.split(os.path.sep)[-1].split('.')[0]        # 파일이름
    group_name = file_path.split(os.path.sep)[-2]                     # 그룹이름
    idb_save_path = os.path.join(IDB_PATH,group_name)                 # idb 파일 저장 경로
    ops_save_path = os.path.join(ATTRIBUTE_PATH,group_name)           # 특징정보 저장 경로
    if IDA_PATH.split('/')[-1] == 'idat.exe':
        idb_dst_path = os.path.join(idb_save_path, file_name) + '.idb'    # idb 파일 저장 경로
    else :
        idb_dst_path = os.path.join(idb_save_path, file_name) + '.i64'  # idb 파일 저장 경로

    # check file path
    if not os.path.exists(idb_save_path):
        try:
            os.makedirs(idb_save_path)
        except:
            pass
    if not os.path.exists(ops_save_path):
        try:
            os.makedirs(ops_save_path)
        except:
            pass

    if not os.path.exists(os.path.join(ops_save_path,'block')):
        try:
            os.makedirs(os.path.join(ops_save_path,'block'))
        except:
            pass
    if not os.path.exists(os.path.join(ops_save_path,'block_asm')):
        try:
            os.makedirs(os.path.join(ops_save_path,'block_asm'))
        except:
            pass
    if not os.path.exists(os.path.join(ops_save_path,'func')):
        try:
            os.makedirs(os.path.join(ops_save_path,'func'))
        except:
            pass
    if not os.path.exists(os.path.join(ops_save_path,'func_asm')):
        try:
            os.makedirs(os.path.join(ops_save_path,'func_asm'))
        except:
            pass

    if not (os.path.exists(ops_save_path + '/block/' + file_name + '.block') and os.path.exists(  # 특징정보(기본블록,함수) 파일이 존재 안 할 경우
            ops_save_path + '/func/' + file_name + '.func')):
        command = '"{ida_path}" -c -o"{idb_path}" -A -S"{script_path} {ops_path} {ops_path2}" -P+ "{file_path}"'.format(
            ida_path=IDA_PATH, idb_path=idb_dst_path, script_path=IDA_SCRIPT_PATH, ops_path=ops_save_path,
            ops_path2=file_name, file_path=file_path)  # ida pro를 이용하여 IDA 파일, 특징정보(기본블록,함수) 파일 생성하는 명령어
        curr_state = 'IDB+특징정보'
        try:
            subprocess.call(command, shell=True, )  # 명령어 실행 command: 명령어 shell: 앞 인자를 list->str 로 변환
            if os.path.exists(ops_save_path + '/block/' + file_name + '.block'):   # 특징정보가 생성되었는지 확인
                print("{0}의 {1}을 성공적으로 분석하였습니다.".format(file_name, curr_state))
            else:
                print("{0}의 {1}을 분석하는데 실패하였습니다.".format(file_name, curr_state))
        except:
            print("{}을 분석하는데 실패하였습니다.".format(file_name))
            pass
    else:
        print("{0}파일이 존재합니다..".format(file_name))



"""

    PE32_MALWARE_PATH의 파일목록들을 불러온다.

"""
def create_file_list ( root ) :
    ret_list = []
    for path, dirs, files in os.walk(root) :
        for file in files :
            full_file_path = os.path.join(path, file)
            ret_list.append(full_file_path)
    return ret_list

"""
    임시 파일들을 삭제하는 함수
"""

def delete_files(path):
    dir_list = os.listdir(path)
    try:
        for dir in dir_list:
            shutil.rmtree(os.path.join(path,dir))
    except:
        print("can not erase file")

def static_analysis():
    mp.freeze_support()
    p = mp.Pool(CPU_COUNT)

    print('*'*50)
    start_time = time.time()

    # idb-ops
    input_file_lists = create_file_list(PE32_MALWARE_PATH)              #  PE32_MALWARE_PATH의 파일목록들을 불러온다.
    print("Total File Count : {}".format(len(input_file_lists)))
    p.map(make_idb_ops, input_file_lists)                               #  파일들의 idb, 특징정보를 생성한다.
    delete_files(IDB_PATH)
    delete_files(PE32_MALWARE_PATH)
    print("elapsed time: {}".format(time.time() - start_time))

if __name__ == "__main__":
    static_analysis()
