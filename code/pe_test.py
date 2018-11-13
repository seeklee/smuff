import os,hashlib
import pefile,pickle
from shutil import copyfile
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

# Information Path

# 악성코드가 있는 최상위 폴더
BASE_PATH = config.get('PATH', 'BASE_DIR_PATH')
PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')
MALWARE_PATH = config.get('PATH','MALWARE_PATH')

def store_pickle(PATH,data):
    with open(PATH,'wb') as fw:
        pickle.dump(data,fw)

def get_pickle(PATH):
    with open(PATH,'rb') as fr:
        data = pickle.load(fr)
    return data
def bool_check_pe32(PATH):


    try:
        pe = pefile.PE(PATH)

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



def convert_to_md5(PATH):
    hash_md5 = hashlib.md5()
    with open(PATH, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_md5_filelist_dic():
    info_malware_dic = {}
    print("convert md5 !")
    fail_cnt = 0
    all_cnt = 0

    for path,dirs,files in os.walk(MALWARE_PATH):
        for file in files:
            if all_cnt%100 == 0:
                print("cnt : {}".format(all_cnt))

            all_cnt+=1
            filepath = os.path.join(path,file)
            if bool_filering_file(filepath):
                file_md5 = convert_to_md5(filepath)

                if file_md5 not in info_malware_dic:
                    info_malware_dic[file_md5] = []

                info_malware_dic[file_md5].append(filepath)
            else:
                fail_cnt += 1

    print("cnt : {}".format(all_cnt))
    print("fail_cnt: {} ".format(fail_cnt))
    #store_pickle(os.path.join(BASE_PATH,"malware_convert_info.pickle"),info_malware_dic)
    return info_malware_dic

def make_init_directorys():
    if not os.path.exists(PE32_MALWARE_PATH):
        os.mkdir(PE32_MALWARE_PATH)

    for dirname in os.listdir(MALWARE_PATH):
        if not os.path.exists(os.path.join(PE32_MALWARE_PATH,dirname)):
            os.mkdir(os.path.join(PE32_MALWARE_PATH,dirname))

    if not os.path.exists(os.path.join(PE32_MALWARE_PATH,"etc")):
        os.mkdir(os.path.join(PE32_MALWARE_PATH,"etc"))

def copy_file(info_malware_dic):
    file_size = len(info_malware_dic)
    i = 0
    for file_md5 in info_malware_dic:
        if i % 100 == 0:
            print("{}/{}".format(i,file_size))
        i+=1
        src_path = info_malware_dic[file_md5][0]
        ## 중복된 파일이 있다면 etc라는 파일에 복사
        if len(info_malware_dic[file_md5]) == 1:
            group = src_path.split(os.sep)[-2]
            dst_path = os.path.join(PE32_MALWARE_PATH,group)
            if not os.path.exists(os.path.join(dst_path,file_md5+".vir")):
                copyfile(src_path,os.path.join(dst_path,file_md5+".vir"))
        else:
            dst_path = os.path.join(PE32_MALWARE_PATH,"etc")
            if not os.path.exists(os.path.join(dst_path, file_md5+".vir")):
                copyfile(src_path, os.path.join(dst_path, file_md5+".vir"))

    print("{}/{}".format(i, file_size))
def pe_test():
    make_init_directorys()
    copy_file(get_md5_filelist_dic())
    # PATH = R"E:\smuff\data\malware_convert_info.pickle"
    # data =get_pickle(PATH)
    # print(data['2b35bfd4415b4def6d90d5591fb0e266'])
    #PATH = R"E:\smuff\data\Bluenoroff\99473a1796b34d17c2b05dee812c9d84.vir"
    # PATH = r"E:\smuff\data\Blackmoon\9dce4bac0d4cf568230312d4012871c9.vir"
    # with open(PATH,'rb') as fr:
    #     print(fr.readline())
    # pe = pefile.PE(PATH)
    # print(pe)

if __name__ == "__main__":
    pe_test()