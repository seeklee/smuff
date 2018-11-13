import json
import sys, os
import pickle
from multiprocessing import Process
import multiprocessing as mp
import configparser
import hashlib

config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
config.read('config.ini')

REPORT_PATH = config.get('PATH','REPORT_PATH')
ATTRIBUTE_PATH = config.get('PATH','ATTRIBUTE_PATH')


# change the range



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
        for mut in report["behavior"]["summary"]["mutex"]:
            ret.append(mut)

        ret.append(report["target"]["file"]["yara"]["meta"]["description"])
    except:
        return ret

    return ret

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
        if len(report["static"]["pdb_path"])>0 and report["static"]["pdb_path"].split('.')[-1] == 'pdb' :
            ret.append(report["static"]["pdb_path"])
    except:
        pass

    return pdb_shingling(ret)

def strings(report):
    ret = []
    try:
        if len(report["strings"]) > 0:
            for string in report["strings"]:
                ret.append(string)
    except:
        return ret

    return ret


def ip(report):
    ret = []

    dst_num = len(report["network"]["tcp"])
    for i in range(0, dst_num + 1):
        try:
            ret.append(report["network"]["tcp"][i]["dst"])
        except IndexError:
            return ret

    return ret


def apiset(report):
    ret = []

    try:
        processes = report["behavior"]["processes"]
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
    ngram = 7
    try:
        processes = report["behavior"]["processes"]
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
    for x in range(lret.__len__()-ngram):
        haha = ""
        for y in range(ngram):
            haha += lret[x+y] + '_'
        #hashapi = hashlib.md5()
        #hashapi.update(haha.encode())
        #haha = hashapi.hexdigest()
        apise.append(haha)
    return apise


def domain(report):
    ret = []

    try:
        domain_num = len(report["network"]["domains"])
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
        DAT_STRING_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"str", filename + ".str")
        DAT_DOMAINS_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"dom", filename + ".dom")
        DAT_IP_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"ip", filename + ".ip")
        DAT_MUTEX_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"mut", filename + ".mut")
        DAT_API_PATH = os.path.join(ATTRIBUTE_PATH,dirname,"apiset",  filename + ".apiset")
        DAT_PDB_PATH = os.path.join(ATTRIBUTE_PATH, dirname,"pdb", filename + ".pdb")
        DAT_APICS_PATH = os.path.join(ATTRIBUTE_PATH, dirname, "apics", filename + ".apics")

        if os.path.exists(DAT_STRING_PATH):
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
                report = json.load(f)

                str_list = strings(report)
                domain_list = domain(report)
                ip_list = ip(report)
                mut_list = mutex(report)
                apiset_list = apiset(report)
                pdb_list = pdb(report)
                apics_list = api_sequence(report)

                # with open(DAT_API_PATH, 'wb') as api_dat:

                if len(str_list) > 0:
                    with open(DAT_STRING_PATH, 'wb') as str_dat:
                        pickle.dump(str_list, str_dat)
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
    report_list = get_report_path_list(PATH)
    p = mp.Pool(os.cpu_count())
    p.map(parsing, report_list)

def make_dir(REPORT_PATH):
    dirnames = os.listdir(REPORT_PATH)
    for dirname in dirnames:
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH, dirname)):
            os.mkdir(os.path.join(ATTRIBUTE_PATH, dirname))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"str")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"str"))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"dom")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"dom"))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"ip")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"ip"))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"mut")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"mut"))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"apiset")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"apiset"))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"pdb")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"pdb",))
        if not os.path.exists(os.path.join(ATTRIBUTE_PATH,dirname,"apics")):
            os.mkdir(os.path.join(ATTRIBUTE_PATH,dirname,"apics",))

def report_parser():
    make_dir(REPORT_PATH)
    run(REPORT_PATH)


if __name__ == '__main__':
    report_parser()


