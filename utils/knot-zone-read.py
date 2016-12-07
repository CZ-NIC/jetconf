# This script reads zone data from KnotDNS socket and converts them
# to YANG model compliant data tree in JSON formatting.
# Only SOA, A, AAAA, NS, MX, TXT, TLSA and CNAME records are currently
# supported.

import sys
import json

from typing import Dict, Any
from libknot.control import KnotCtl, KnotCtlType

# Edit this to match your actual KnotDNS control socket
KNOT_SOCKET = "/home/pspirek/knot-conf/knot.sock"


def main(args):
    if len(args) != 2:
        print("Usage: {} [domain]".format(args[0]))
        exit(1)

    domain = args[1]    # type: str
    if domain[-1] != '.':
        domain += "."

    ctl = KnotCtl()
    ctl.connect(KNOT_SOCKET)
    ctl.send_block("zone-read", zone=domain)
    resp = ctl.receive_block()  # type: Dict[str, Any]
    ctl.send(KnotCtlType.END)
    ctl.close()

    resp = resp[domain]

    zone_template = {
        "dns-zones:zone-data": {
            "zone": [
                {
                    "name": domain,
                    "class": "IN",
                    "default-ttl": 3600,
                    "SOA": {},
                    "rrset": []
                }
            ]
        }
    }

    zone_out = zone_template["dns-zones:zone-data"]["zone"][0]
    soa_out = zone_out["SOA"]

    soa = resp[domain]["SOA"]
    soa_data = soa["data"][0].split()

    try:
        soa_out["ttl"] = int(soa["ttl"])
        soa_out["mname"] = soa_data[0]
        soa_out["rname"] = soa_data[1]
        soa_out["serial"] = int(soa_data[2])
        soa_out["refresh"] = int(soa_data[3])
        soa_out["retry"] = int(soa_data[4])
        soa_out["expire"] = int(soa_data[5])
        soa_out["minimum"] = int(soa_data[6])
    except (IndexError, ValueError) as e:
        print(str(e))

    rrset_out = zone_out["rrset"]

    for owner, rrs in resp.items():
        # print("rrs={}".format(rrs))
        for rr_type, rr in rrs.items():
            # print("rr={}".format(rr))
            if rr_type not in ("A", "AAAA", "NS", "MX", "TXT", "TLSA", "CNAME"):
                continue

            ttl = int(rr["ttl"])
            rr_data_list = rr["data"]

            new_rr_out_rdata_list = []
            new_rr_out = {
                "owner": owner,
                "type": "iana-dns-parameters:" + rr_type,
                "ttl": ttl,
                "rdata": new_rr_out_rdata_list
            }

            id_int = 0
            for rr_data in rr_data_list:
                new_rr_out_rdata_values = {}
                new_rr_out_rdata = {
                    "id": str(id_int),
                    rr_type: new_rr_out_rdata_values
                }

                if rr_type in ("A", "AAAA"):
                    new_rr_out_rdata_values["address"] = rr_data
                elif rr_type == "NS":
                    new_rr_out_rdata_values["nsdname"] = rr_data
                elif rr_type == "MX":
                    rr_data = rr_data.split()
                    new_rr_out_rdata_values["preference"] = rr_data[0]
                    new_rr_out_rdata_values["exchange"] = rr_data[1]
                elif rr_type == "TXT":
                    new_rr_out_rdata_values["txt-data"] = rr_data.strip(" \"")
                elif rr_type == "TLSA":
                    cert_usage_enum = {
                        "0": "PKIX-TA",
                        "1": "PKIX-EE",
                        "2": "DANE-TA",
                        "3": "DANE-EE",
                        "255": "PrivCert"
                    }
                    sel_enum = {
                        "0": "Cert",
                        "1": "SPKI",
                        "255": "PrivSel"
                    }
                    match_type_enum = {
                        "0": "Full",
                        "1": "SHA2-256",
                        "2": "SHA2-512",
                        "255": "PrivMatch"
                    }
                    rr_data = rr_data.split()
                    new_rr_out_rdata_values["certificate-usage"] = cert_usage_enum[rr_data[0]]
                    new_rr_out_rdata_values["selector"] = sel_enum[rr_data[1]]
                    new_rr_out_rdata_values["matching-type"] = match_type_enum[rr_data[2]]
                    new_rr_out_rdata_values["certificate-association-data"] = rr_data[3]
                elif rr_type == "CNAME":
                    new_rr_out_rdata_values["cname"] = rr_data

                new_rr_out_rdata_list.append(new_rr_out_rdata)
                id_int += 1

            rrset_out.append(new_rr_out)

    print(json.dumps(zone_template, indent=4, sort_keys=True))

if __name__ == "__main__":
    main(sys.argv)
