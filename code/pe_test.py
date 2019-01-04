import os,hashlib
import pefile
from shutil import copyfile
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

# Information Path

# 악성코드가 있는 최상위 폴더
BASE_PATH = config.get('PATH', 'BASE_DIR_PATH')        # 위협그룹 분류 시스템의 최상위 폴더
PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')          # pe32검사후 파일이 저장되어 있는 폴더
MALWARE_PATH = config.get('PATH','MALWARE_PATH')          # 분석 파일이 저장되어 있는 폴더



def bool_check_pe32(PATH):


    try:
        pe = pefile.PE(PATH)   # pefile 라이브러리를 활용한다.

    except:
        print("{} <-- pefile fail".format(PATH))
        return False


    # PE인지 확인하기
    # 0x5a4d이면 pe파일인다.
    e_magic = hex(pe.DOS_HEADER.e_magic)

    # 64, 32비트 확인하기
    # 0x10b -- 32 비트 , 0x20b -- 64 비트
    magic = hex(pe.OPTIONAL_HEADER.Magic)

    #return e_magic == "0x5a4d"
    return e_magic == "0x5a4d" and magic == "0x10b"



# .으로 시작한 파일 제거
# pe32가 아닌 파일 제거
def bool_filering_file(PATH):
    filename = os.path.basename(PATH)
    if filename[0] == '.':
        return False
    if not bool_check_pe32(PATH):
        return False
    else:
        return True


"""

    파일의 md5검사

"""
def convert_to_md5(PATH):
    hash_md5 = hashlib.md5()
    with open(PATH, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):  # 파일 바이너리 코드 내용을 md5 해쉬값으로 만들다
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


"""

    

"""
def get_md5_filelist_dic():
    info_malware_dic = {}
    print("convert md5 !")
    fail_cnt = 0
    all_cnt = 0

    for path,dirs,files in os.walk(MALWARE_PATH):                  #  MALWARE_PATH의 파일목록을 불러온다.
        for file in files:
            if all_cnt%100 == 0:
                print("cnt : {}".format(all_cnt))

            all_cnt+=1
            filepath = os.path.join(path,file)
            if bool_filering_file(filepath):                      # pe32 파일인지 검사
                file_md5 = convert_to_md5(filepath)               # 파일의 md5 해쉬를 추출함

                if file_md5 not in info_malware_dic:              # 파일의 경로와 md5 해쉬값을 저장한다.
                    info_malware_dic[file_md5] = []

                info_malware_dic[file_md5].append(filepath)
            else:
                fail_cnt += 1

    print("cnt : {}".format(all_cnt))
    print("fail_cnt: {} ".format(fail_cnt))
    return info_malware_dic

"""

     MALWARE_PATH 디렉토리 구조와 똑같이 PE32_MALWARE_PATH에 생성해준다.

"""
def make_init_directorys():
    if not os.path.exists(PE32_MALWARE_PATH):
        os.mkdir(PE32_MALWARE_PATH)

    for dirname in os.listdir(MALWARE_PATH):
        if not os.path.exists(os.path.join(PE32_MALWARE_PATH,dirname)):
            os.mkdir(os.path.join(PE32_MALWARE_PATH,dirname))


"""

    pe32 필터링과 md5 해시값을 추출한 파일들을 PE32_MALWARE_PATH경로에 저장하는 함수
    
    info_malware_dic:  기존 파일의 경로와 md5값을 저장한 사전 

"""
def copy_file(info_malware_dic):
    file_size = len(info_malware_dic)
    i = 0
    for file_md5 in info_malware_dic:
        if i % 100 == 0:
            print("{}/{}".format(i,file_size))
        i+=1
        src_path = info_malware_dic[file_md5][0]
        if len(info_malware_dic[file_md5]) == 1:  # md5값이 중복되는 파일 필터링
            group = src_path.split(os.sep)[-2]
            dst_path = os.path.join(PE32_MALWARE_PATH,group)
            if not os.path.exists(os.path.join(dst_path,file_md5+".vir")):
                copyfile(src_path,os.path.join(dst_path,file_md5+".vir"))    # 파일을 저장한다.

    print("{}/{}".format(i, file_size))

def pe_test():
    make_init_directorys()     # MALWARE_PATH 디렉토리 구조와 똑같이 PE32_MALWARE_PATH에 생성해준다.
    copy_file(get_md5_filelist_dic())      # exe32 파일여부를 확인하고 파일이름을 md5해시값으로 변환하여 저장한다.

"""

    파일이름 md5변환, exe32필터링

"""
if __name__ == "__main__":
    pe_test()