import bz2
import json

def load_file(filename):
    with bz2.open(filename, "rt") as bz_file:
        for line in bz_file:
            return json.loads(line)

def parse_probe_data(probe_data):
    probeId_to_AS = {}
    if 'objects' in probe_data:
        for probe in probe_data['objects']:
            probeId_to_AS[probe['id']] = { 'asn_v4' : str(probe['asn_v4']), \
                'asn_v6' : str(probe['asn_v6'])
            }
        return probeId_to_AS

def dump_json(data, filename):
    with open(filename + '.json', 'w') as outfile:
        json.dump(data, outfile)

def main():

    dates = ['20180401', '20180402', '20180403', '20180404', '20180405', '20180406', '20180407']
    for date in dates:
        filename = date
        path_to_file = "probe_archive/" + filename + ".json.bz2"
        probe_data = load_file(path_to_file)
        probeId_to_AS = parse_probe_data(probe_data)
        dump_json(probeId_to_AS, filename)

main() 