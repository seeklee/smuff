import configparser
import pe_test
import subprocess
import make_idb_ops
import os
import pickle
import upload

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

PE32_MALWARE_PATH = config.get('PATH','PE32_MALWARE_PATH')
DATA_PATH = config.get('PATH','DATA_PATH')


def colldata():
    dirs = os.listdir(PE32_MALWARE_PATH)
    filelist = dict()
    for dir in dirs:
        files = os.listdir(os.path.join(PE32_MALWARE_PATH,dir))
        for x in files:
            filelist[x.split('.')[0]] = dir
        with open(os.path.join(DATA_PATH, 'file_dir_dict.pickle'), 'wb') as handle:
            pickle.dump(filelist, handle)
    print(filelist)


if __name__ == '__main__':
    pe_test.pe_test()
    #colldata()
    make_idb_ops.static_analysis()
    #upload.upload_report()
