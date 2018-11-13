# -*-coding:utf-8-*-
import requests, os, subprocess
import time, sys, pickle
import multiprocessing as mp
import configparser

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

REST_URL = "http://203.246.112.135:18090/tasks/create/file"
PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')
REPORT_PATH = config.get('PATH','REPORT_PATH')

# DIRECTORY = "/home/seclab/virussign_20170727"

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


def send_file(file_path):
    with open(file_path, 'rb') as f:
        file_name = get_file_name(file_path)
        fs = {'file': (file_name, f)}
        r = requests.post(REST_URL, files=fs)
        if r.status_code == 200:
            print("{} is succeeded".format(file_name))
        else:
            print("{} is failed".format(file_name))


def run(root, process_count=4):
    file_path_list = explorer(root)
    mp.freeze_support()
    p = mp.Pool(process_count)
    p.map(send_file, file_path_list)

def get_file_name ( file_path ) :
    return os.path.basename(file_path)

def upload_report():
    start = time.time()
    run(PE32_MALWARE_PATH)
    print("Time : {}".format(time.time() - start))

if __name__ == '__main__':
    upload_report()
