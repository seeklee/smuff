import os
import subprocess
import configparser
import multiprocessing as mp
import time


config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

IDA_PATH = config.get('IDA','IDA_PATH')
IDB_PATH = config.get('PATH','IDB_PATH')
CPU_COUNT = int(config.get('PARAMETER','CPU_COUNT'))
IDA_SCRIPT_PATH = config.get('PATH','IDA_SCRIPT_PATH')

PE32_MALWARE_PATH = config.get('PATH', 'PE32_MALWARE_PATH')
ATTRIBUTE_PATH = config.get('PATH', 'ATTRIBUTE_PATH')


def make_idb_ops(file_path):
    # define file path
    file_name = file_path.split(os.path.sep)[-1].split('.')[0]
    group_name = file_path.split(os.path.sep)[-2]
    idb_save_path = os.path.join(IDB_PATH,group_name)
    ops_save_path = os.path.join(ATTRIBUTE_PATH,group_name)
    idb_dst_path = os.path.join(idb_save_path, file_name) + '.i64'

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


    # if exists idb(64bit)
    if os.path.exists(idb_dst_path):
        if os.path.exists(ops_save_path + '/block/' + file_name + '.block') and os.path.exists(
                ops_save_path + '/func/' + file_name + '.func'):
            print("{}는 이미 해당 idb와 ops 분석을 마쳤습니다.".format(file_name))
            return
        command = '"{ida_path}" -A -S"{script_path} {ops_path} {ops_path2}" "{idb_path}" '.format(ida_path=IDA_PATH, script_path=IDA_SCRIPT_PATH, ops_path=ops_save_path,ops_path2=file_name,idb_path=idb_dst_path)
        curr_state = 'OPS'
    else:  # make idb, ops
        command = '"{ida_path}" -c -o"{idb_path}" -A -S"{script_path} {ops_path} {ops_path2}" -P+ "{file_path}"'.format(ida_path=IDA_PATH, idb_path=idb_dst_path, script_path=IDA_SCRIPT_PATH, ops_path=ops_save_path,ops_path2=file_name, file_path=file_path)
        print(command)
        print(ops_save_path)
        curr_state = 'IDB+OPS'

    try:
        subprocess.call(command, shell=True, )  # shell: 앞 인자를 list->str 로 변환
        if os.path.exists(idb_dst_path):
            print("{0}의 {1}을 성공적으로 분석하였습니다.".format(file_name, curr_state))
            # os.remove(file_path)
        else:
            print("{0}의 {1}을 분석하는데 실패하였습니다.".format(file_name, curr_state))
    except:
        print("{}을 분석하는데 실패하였습니다.".format(file_name))

    pass

def create_file_list ( root ) :
    ret_list = []
    for path, dirs, files in os.walk(root) :
        for file in files :
            full_file_path = os.path.join(path, file)
            ret_list.append(full_file_path)
    return ret_list

def static_analysis():
    mp.freeze_support()
    p = mp.Pool(CPU_COUNT)

    print('*'*50)
    start_time = time.time()

    # idb-ops
    input_file_lists = create_file_list(PE32_MALWARE_PATH)
    print("Total File Count : {}".format(len(input_file_lists)))
    p.map(make_idb_ops, input_file_lists)
    print("elapsed time: {}".format(time.time() - start_time))

if __name__ == "__main__":
    static_analysis()
