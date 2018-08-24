import radix
import json
import pyasn
import gzip
import bz2
import ujson


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

def dump_json(filename, data):
    with open("results/" + filename + '.json', 'w') as outfile:
        json.dump(data, outfile, cls=SetEncoder)

def load_probe_ids_to_asns(filename):
    with open(filename + '.json', 'r') as f:
        probeId_to_ASN = json.load(f)
    return probeId_to_ASN

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

def find_border_ip_set(prb_id, list_of_ip_asn_tuples, probe_asn, probe_ip):
    ip_src_as = None
    ip_next_as = None
    check = False
    
    for i, hop in enumerate(list_of_ip_asn_tuples):
        ip_, as_, moas_ = hop[0], hop[1], hop[2]

        if '*' in as_:
            check = True
        elif probe_asn in as_:
            check = False

        if((probe_asn not in as_) and ('*' not in as_ )):
            if check == True:
                return (None, None)
            else:
                if(i >= 1):
                    probe_as_last_ip = list_of_ip_asn_tuples[i-1][0]
                else:
                    probe_as_last_ip = probe_ip

                return (probe_as_last_ip, ip_)

def parse_traceroutes(filename, radix_tree, probeIds):
    #Example entry in probeIds {asn_v4: 3434, asn_v6: 3443}
    
    v4_ = {} # v4 { "src_AS" : { "probeID" : { "tuples" : "last_origin_ip - nex_ip - target_ip " }, "last_probe_as_ips": set(), "next_probe_as_ips" : set(), "num_trac" : 0  }}
    v6_ = {}

    with bz2.open(filename + ".bz2", 'rt') as subset:
        print("Loaded " + filename)
        #Load traceroute file
        for traceroute in subset:
            decoded = ujson.loads(traceroute)
            
            if('prb_id' in decoded and "src_addr" in decoded and int(decoded['af']) in [4,6]):
                
                if int(decoded['af']) == 4 and str(decoded['prb_id']) in probeIds:
                    probe_asn = str(probeIds[str(decoded['prb_id'])]['asn_v4'])
                elif int(decoded['af']) == 6 and str(decoded['prb_id']) in probeIds:
                    probe_asn = str(probeIds[str(decoded['prb_id'])]['asn_v6'])
                else:
                    print("error " + str(decoded['prb_id']) + " not found in probeIds." )
                    continue

                # Translate IP-level path to AS-level path
                list_of_ip_asn_tuples = list()

                for hop in decoded["result"]:
                    if "error" in hop:
                        list_of_ip_asn_tuples.append( ("*", "*") )
                        
                    elif "error" in hop["result"][0] or "x" in hop["result"][0]:
                        list_of_ip_asn_tuples.append( ("*", "*") )
                        
                    else:
                        ip = hop["result"][0]['from']
                    
                        if (ip == "*"):
                            list_of_ip_asn_tuples.append( ("*", "*") )            
                        else:
                            match = radix_tree.search_best(ip)
                            
                            if match is None:
                                list_of_ip_asn_tuples.append( (ip, "*") )
                            else:
                                if match.data['moas'] == False:
                                    list_of_ip_asn_tuples.append( (ip, [str(match.data['asn'])]))
                                    if(str(match.data['asn']) != src_asn): # No need to analyze the full path
                                        break
                                else:
                                    list_of_ip_asn_tuples.append( (ip, match.data['asn']))

                if(int(decoded['af']) == 4): #v4 case
                    res_v4 = find_border_ip_set(str(decoded['prb_id']), list_of_ip_asn_tuples, probe_asn, str(decoded['src_addr']))

                    if src_asn not in v4_:
                        v4_[src_asn] = dict()
                    
                    if str(decoded['prb_id']) not in v4_[src_asn]:
                        v4_[src_asn][str(decoded['prb_id'])] = dict()
                        v4_[src_asn][str(decoded['prb_id'])]['tuples'] = set()
                        v4_[src_asn][str(decoded['prb_id'])]['last_probe_as_ips'] = set()
                        v4_[src_asn][str(decoded['prb_id'])]['next_probe_as_ips'] = set()
                        v4_[src_asn][str(decoded['prb_id'])]['num_trac'] = 0
                    
                    if(res_v4 != (None, None)):
                        v4_[src_asn][str(decoded['prb_id'])]['tuples'].add( str(res_v4[0] + "-" + res_v4[1] + "-" +  str(decoded['dst_addr'])) )
                        v4_[src_asn][str(decoded['prb_id'])]['last_probe_as_ips'].add(res_v4[0])
                        v4_[src_asn][str(decoded['prb_id'])]['next_as_ips'].add(res_v4[1])

                    v4_[src_asn][str(decoded['prb_id'])]['num_trac'] += 1


                else: #v6 case
                    res_v6 = find_border_ip_set(str(decoded['prb_id']), list_of_ip_asn_tuples, probe_asn, str(decoded['src_addr']))

                    if src_asn not in v6_:
                        v6_[src_asn] = dict()

                    if str(decoded['prb_id']) not in v6_[src_asn]:
                        v6_[src_asn][str(decoded['prb_id'])] = dict()
                        v6_[src_asn][str(decoded['prb_id'])]['tuples'] = set()
                        v6_[src_asn][str(decoded['prb_id'])]['last_probe_as_ips'] = set()
                        v6_[src_asn][str(decoded['prb_id'])]['next_probe_as_ips'] = set()
                        v6_[src_asn][str(decoded['prb_id'])]['num_trac'] = 0

                    if(res_v6 != (None, None)):
                        v6_[src_asn][str(decoded['prb_id'])]['tuples'].add( str(res_v6[0] + "-" + res_v6[1] + "-" +  str(decoded['dst_addr'])) )
                        v6_[src_asn][str(decoded['prb_id'])]['last_probeAS_ips'].add(res_v6[0])
                        v6_[src_asn][str(decoded['prb_id'])]['next_probe_as_ips'].add(res_v6[1])

                    v6_[src_asn][str(decoded['prb_id'])]['num_trac'] += 1

    return v4_, v6_


def main():
    time = "0000"
    day = '01'
    month = '04'
    year = '2018'

    date = year + month + day 

    probeIds_asns_filepath = "probeId_to_AS/" + date
    probeIds_asns = load_probe_ids_to_asns(probeIds_asns_filepath)

    radix_tree = load_caida_pfx2as(date)
    print("Loaded radix_tree")

    traceroute_dumps = "traceroute_dumps/"
    traceroute_filename = "traceroute-" + year + "-" + month + "-" + day + "T" + time
    traceroute_filename_path = traceroute_dumps + traceroute_filename
    results_v4, results_v6 = parse_traceroutes(traceroute_filename, radix_tree, probeIds_asns)

    dump_json(traceroute_filename + "_v4", results_v4)
    dump_json(traceroute_filename + "_v6", results_v6)



main()