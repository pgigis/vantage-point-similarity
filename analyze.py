import radix
import json
import pyasn
import gzip
import bz2
import ujson

def dump_json(filename):
    with open(filename + '.json', 'w') as outfile:
        json.dump(data, outfile)

def load_probe_ids_to_asns(filename):
    with open(filename + '.json', 'r') as f:
        probeId_to_ASN = json.load(f)
    return probeId_to_ASN

def load_caida_pfx2as(filename):
    radix_tree = radix.Radix()
    with gzip.open(filename + ".gz", 'rt') as f:
        file_content = f.readlines()
        
        for line in file_content:
            line_ = line.split()
            prefix = line_[0] + "/" + line_[1]
            rnode = radix_tree.add(prefix)

            if('_' in line_[2]):
                rnode.data["moas"] = True
                rnode.data["asn"] = line_[2].split('_')
            else:
                rnode.data["moas"] = False
                rnode.data["asn"] = line_[2]
    
    if('rv4' in filename):
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
    elif('rv6' in filename):
        ll = radix_tree.add('fe80::/64')
        ll.data['asn'] = '*' #v6_linklocal
        ll.data["moas"] = False
    
    return radix_tree

def parse_traceroutes(filename, radix_tree, probeIds):
    #Example entry in probeIds {asn_v4: 3434, asn_v6: 3443}
    
    v4_ = {}
    v6_ = {}

    with bz2.open(filename + ".bz2", 'rt') as subset:

        #Load traceroute file
        for traceroute in subset:
            decoded = json.loads(traceroute)

            if('prb_id' not in decoded or "src_addr" not in decoded or int(decoded['af']) not in [4,6]):
                continue 

            list_of_ip_asn_tuples = list()

            for hop in decoded["result"]:
                if "error" in hop:
                    list_of_ip_asn_tuples.append( ("*", "*", False) )
                    continue

                if "error" in hop["result"][0] or "x" in hop["result"][0]:
                    list_of_ip_asn_tuples.append( ("*", "*", False) )
                    continue

                ip = hop["result"][0]['from']
                
                if (ip == "*"):
                    list_of_ip_asn_tuples.append( ("*", "*", False) )
                    continue            
                else:
                    match = radix_tree.search_best(ip)
                    
                    if match is None:
                        list_of_ip_asn_tuples.append( (ip, "*", False) )
                    else:
                        if match.data['moas'] == False:
                            list_of_ip_asn_tuples.append( (ip, str(match.data['asn']), False))
                        else:
                            list_of_ip_asn_tuples.append( (ip, match.data['asn'], True)) 
            
            if(int(decoded['af']) == 4): #v4 case
                ip_src_as = None
                ip_next_as = None

                if str(decoded['prb_id']) in probeIds:
                    src_asn = str(probeIds[str(decoded['prb_id'])]['asn_v4'])
                else:
                    print("error " + str(decoded['prb_id']) + " not found in probeIds." )
                    continue

                skip_it = 0

                for i,hop in enumerate(list_of_ip_asn_tuples):
                    ip_, as_, moas_ = hop[0], hop[1], hop[2] 
                    if(src_asn == as_):
                        continue
                    else:
                        if(as_ != '*'):
                            if(i >= 1):
                                prev_hop = list_of_ip_asn_tuples[ i - 1 ]
                                prev_ip_, prev_as_, prev_moas_ = prev_hop[0], prev_hop[1], prev_hop[2]

                                if(prev_as_ == '*'):
                                    skip_it = 1
                                    break
                                elif(prev_as_ == src_asn):
                                    ip_src_as = prev_ip_
                                    ip_next_as = ip_
                                    break
                                else:
                                    print(list_of_ip_asn_tuples)
                                    print(str(decoded['prb_id']))
                                    print("error!--")
                        else:
                            continue

                if(skip_it == 1):
                    continue
                else:
                    if str(decoded['prb_id']) not in v4_:
                        v4_[str(decoded['prb_id'])] = dict()
                        v4_[str(decoded['prb_id'])]['tuples'] = set()
                        v4_[str(decoded['prb_id'])]['src_ips'] = set()
                        v4_[str(decoded['prb_id'])]['next_ips'] = set()
                    else:
                        v4_[str(decoded['prb_id'])]['tuples'].add( (ip_src_as, ip_next_as, str(decoded['dst_addr'])  ))
                        v4_[str(decoded['prb_id'])]['src_ips'].add(ip_src_as)
                        v4_[str(decoded['prb_id'])]['next_ips'].add(ip_next_as)

            else: #v6 case
                pass

    return v4_, v6_


def main():
    time = "0000"
    day = '01'
    month = '04'
    year = '2018'

    date = year + month + day 

    probeIds_asns_filepath = "probeId_to_AS/" + date
    probeIds_asns = load_probe_ids_to_asns(probeIds_asns_filepath)

    pfx2as_filename = "routeviews-rv2-" + date + "-1200.pfx2as"
    pfx2as_file_path = "pfx2as/" + pfx2as_filename
    radix_tree = load_caida_pfx2as(pfx2as_file_path)

    traceroute_dumps = "traceroute_dumps/"
    traceroute_filename = "traceroute-" + year + "-" + month + "-" + day + "T" + time
    traceroute_filename_path = traceroute_dumps + traceroute_filename
    results_v4, results_v6 = parse_traceroutes(traceroute_filename, radix_tree, probeIds_asns)

    dump_json(traceroute_filename + "_v4", results_v4)
    dump_json(traceroute_filename + "_v6", results_v6)



main()