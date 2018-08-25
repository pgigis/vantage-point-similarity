import maxminddb
import shutil
import radix
import os
import numpy as np

class Hop():
    def __init(self, hop):
        self.idx = None
        self.dst_ip = None
        self.CC = None
        self.AS = None
        self.lat = None
        self.long = None
        self.probes = []

class MeasurementProfile():
    def __init__(self, parsed_profile):
        self.hops = None
        self.last_rtt = np.median(self.hops[-1].probes)

def load_caida_pfx2as(date):
    radix_tree = radix.Radix()

    for version in [('v4', 'rv2'), ('v6', 'rv6')]:

        pfx2as_filename = "routeviews-" + version[1] + "-" + date + "-1200.pfx2as"
        pfx2as_file_path = "pfx2as/" + version[0] + "/" + pfx2as_filename

        with gzip.open(pfx2as_file_path + ".gz", 'rt') as file_content:

            for line in file_content:
                line_ = line.strip().split()
                prefix = line_[0] + "/" + line_[1]
                rnode = radix_tree.add(prefix)

                if('_' in line_[2]):
                    rnode.data["moas"] = True
                    rnode.data["asn"] = line_[2].split('_')
                else:
                    rnode.data["moas"] = False
                    rnode.data["asn"] = line_[2]
    #Special cases
    if('rv2' in pfx2as_filename): # v4 case
        ## add RFC1918 et al for the heck of it
        r10 = radix_tree.add('10.0.0.0/8')
        r10.data['asn'] = '*' #rfc1918a
        r10.data["moas"] = False
        r172 = radix_tree.add('172.16.0.0/12')
        r172.data['asn'] = '*' #rfc1918b
        r172.data["moas"] = False
        r192 = radix_tree.add('192.168.0.0/16')
        r192.data['asn'] = '*' #rfc1918c
        r192.data["moas"] = False
        rcgn = radix_tree.add('100.64.0.0/10')
        rcgn.data['asn'] = '*' #rfc6598
        rcgn.data["moas"] = False

    elif('rv6' in pfx2as_filename): # v6 case
        ll = radix_tree.add('fe80::/64')
        ll.data['asn'] = '*' #v6_linklocal
        ll.data["moas"] = False

    return radix_tree

def get_cc(ip):
    return reader.get(ip)

def make_profile(measurement):
    print 'helo'

def main():
    reader = maxminddb.open_database('countriZ/GeoLite2-Country.mmdb')
    mmdb_path = '/home/codeZ/mlab/countriZ/GeoLite2-Country.mmdb'
    tr_files = '/home/codeZ/mlab/01'

    time = "0000"
    day = '01'
    month = '08'
    year = '2018'
    date = year + month + day

    radix_tree = load_caida_pfx2as(date)

    profiles = []
    #extract/parse
    for f in os.listdir(tr_files):
        parsed = MeasurementProfile(parse_tr(f))
        profile = make_profile(parsed)
        profiles.append(profile)

if __name__ == '__main__':
    main()
