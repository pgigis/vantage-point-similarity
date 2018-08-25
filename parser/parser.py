import re
import json

def dump_json(filename, data):
    with open("results/" + filename + '.json', 'w') as outfile:
        json.dump(data, outfile)


def read_file(fname):
    with open(fname) as f:
        content = f.readlines()
    content = [x.strip() for x in content] 

    srcIP_dstIP_regex = "[0-9]*[.][0-9]*[.][0-9]*[.][0-9]*"
    regex_srcIP_dstIP = re.compile(srcIP_dstIP_regex)
    ip_regex = "[0-9]*[.][0-9]*[.][0-9]*[.][0-9]*?[)]"
    rtt_regex = "[0-9]+[.][0-9]+[\/]*[[0-9]+[.][0-9]+[\/]*[0-9]+[.][0-9]+[\/]*[0-9]+[.][0-9]+[\/]*"

    data_ = {}
    data_['results'] = {}
    
    for i, line in enumerate(content):
        if(i == 0):
            res = re.findall(regex_srcIP_dstIP, line)
            data_['srcIP'], data_['dstIP'] = res[0], res[1]
        else:
            data_['results'][i] = {}
            res = re.findall(ip_regex, line)
            if len(res):
                data_['results'][i]['ip'] = res[0].replace(")", "")
            else:
                data_['results'][i]['ip'] = '*'
            res = re.findall(rtt_regex, line)
            if len(res):
                data_['results'][i]['rtts'] = res[0].split("/")

    dump_json(fname, data_)


def main():
    fname = "test.txt"
    read_file(fname)


main()