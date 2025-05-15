#
# Built for XXXX by XX Cyber XXX.XXX|XXXX
#
import requests
import json
import sys
import time
import re
import socket
import urllib3
import datetime
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#------*****------#

misp_auth_key = ""
qradar_auth_key = ""
misp_server = ""
qradar_server = ""
frequency = 60 # In minutes
# frequecny default is 60m.

#------*****------#

misp_url = "https://" + misp_server + "/attributes/restSearch"


# EDIT TO GET OTHER DATA
# USE LAST_N_DAYS TO CONTROL WHAT IOCS ARE IMPORTED
last_n_days = "5d"
now = int(datetime.datetime.now().timestamp())

MISP_PData_list = (
    {"qradar_ref_set": "MISP_IOC_IP", "MISP_PData": {"last": last_n_days, "type": "ip-src", "category": "Network activity", "enforceWarninglist": "True",  "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_IP", "MISP_PData": {"last": last_n_days, "type": "ip-dst", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_CIDR", "MISP_PData": {"last": last_n_days, "type": "ip-src", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_CIDR", "MISP_PData": {"last": last_n_days, "type": "ip-dst", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_MD5", "MISP_PData": {"last": last_n_days, "type": "md5", "category": "Payload delivery", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_SHA256", "MISP_PData": {"last": last_n_days, "type": "sha256", "category": "Payload delivery", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_DOMAIN", "MISP_PData": {"last": last_n_days, "type": "domain", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},
    {"qradar_ref_set": "MISP_IOC_URL", "MISP_PData": {"last": last_n_days, "type": "url", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [2, 3, 4]}},

    {"qradar_ref_set": "MISP_IOC_IP_HIGH", "MISP_PData": {"last": last_n_days, "type": "ip-src", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_IP_HIGH", "MISP_PData": {"last": last_n_days, "type": "ip-dst", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_CIDR_HIGH", "MISP_PData": {"last": last_n_days, "type": "ip-src", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_CIDR_HIGH", "MISP_PData": {"last": last_n_days, "type": "ip-dst", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_MD5_HIGH", "MISP_PData": {"last": last_n_days, "type": "md5", "category": "Payload delivery", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_SHA256_HIGH", "MISP_PData": {"last": last_n_days, "type": "sha256", "category": "Payload delivery", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_DOMAIN_HIGH", "MISP_PData": {"last": last_n_days, "type": "domain", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [1]}},
    {"qradar_ref_set": "MISP_IOC_URL_HIGH", "MISP_PData": {"last": last_n_days, "type": "url", "category": "Network activity", "enforceWarninglist": "True", "threat_level_id": [1]}}
)


MISP_headers = {
    'authorization': misp_auth_key,
    'cache-control': "no-cache",
    }

QRadar_headers = {
    'sec': qradar_auth_key,
    'content-type': "application/json",
    }


def validate_refSet():
    for import_export_pair in MISP_PData_list:
        qradar_ref_set = import_export_pair["qradar_ref_set"]
        MISP_PData = import_export_pair["MISP_PData"]
        validate_refSet_url = "https://" + qradar_server + "/api/reference_data/sets/" + qradar_ref_set
        validate_response = requests.request("GET", validate_refSet_url, headers=QRadar_headers, verify=False)
        print (time.strftime("%H:%M:%S") + " -- " + "Validating if reference set " + qradar_ref_set + " exists")
        if validate_response.status_code == 200:
            print(time.strftime("%H:%M:%S") + " -- " + "Validating reference set " + qradar_ref_set + " - (Success) ")
            validate_response_data = validate_response.json()
            refSet_etype = (validate_response_data["element_type"])
            print(time.strftime("%H:%M:%S") + " -- " + "Identifying Reference set " + qradar_ref_set + " element type")
            print(time.strftime("%H:%M:%S") + " -- " + "Reference set element type = " + refSet_etype + " (Success) ")
            if refSet_etype == "IP" or refSet_etype == "CIDR":
                print (time.strftime("%H:%M:%S") + " -- " + "The QRadar Reference Set " + qradar_ref_set + " Element Type = \"IP\". Only IPs will be imported to QRadar and the other IOC types will be discarded")
                get_misp_data(refSet_etype, qradar_ref_set, MISP_PData)
            else:
                get_misp_data(refSet_etype, qradar_ref_set, MISP_PData)
        else:
            print(time.strftime("%H:%M:%S") + " -- " + "QRadar Reference Set does not exist, please verify if reference set exists in QRadar.")
            sys.exit()


def get_misp_data(refSet_etype, qradar_ref_set, MISP_PData):
    QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_ref_set
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, GET data from MISP on " + misp_server)
    misp_response = requests.request('POST', misp_url, json=MISP_PData, headers=MISP_headers, verify=False)
    json_data = misp_response.json()
    ioc_list = []
    if misp_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Success) ")
        for data in json_data["response"]["Attribute"]:
            ioc = (data['value'])
            # strip IOCs that were last seen longer than last_n_days
            try:
                ioc_lastseen_timestamp = int(datetime.datetime.fromisoformat(data['last_seen']).timestamp())
            except Exception:
                print(f"{time.strftime("%H:%M:%S")} -- IOC: {ioc} no last seen date from MISP, will add...")
                ioc_lastseen_timestamp = now
            ioc_timedelta = now - ioc_lastseen_timestamp
            ioc_acceptable_timedelta = int(str(last_n_days).strip("d")) * 86400
            if ioc_timedelta >= ioc_acceptable_timedelta:
                print(f"{time.strftime("%H:%M:%S")} -- IOC: {ioc} is older than {last_n_days}, will skip...")
                continue
            if refSet_etype == "CIDR":
                if "/" not in ioc:
                    continue
            if refSet_etype == "IP":
                if "/" in ioc:
                    continue
            if "|" in ioc:
                pipe_values = ioc.split("|")
                for value in pipe_values:
                    ioc_list.append(value)
                    print(f"split {pipe_values} to {value}")
                continue
            ioc_list.append(ioc)
        import_data = json.dumps(ioc_list)
        ioc_count = len(ioc_list)
        print(time.strftime("%H:%M:%S") + " -- " + str(ioc_count) + " IOCs imported")
        if refSet_etype == "IP":
            print(time.strftime("%H:%M:%S") + " -- " + "Trying to clean the IOCs to IP address, as " + qradar_ref_set + " element type = IP")
            r = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            ioc_cleaned = list(filter(r.match, ioc_list))
            ioc_cleaned_data = json.dumps(ioc_cleaned)
            ioc_count_cleaned = len(ioc_cleaned)
            print(time.strftime("%H:%M:%S") + " -- " + "(Success) Extracted " + str(ioc_count_cleaned) + " IPs from initial import.")
            qradar_post_IP(ioc_cleaned_data, ioc_count_cleaned, qradar_ref_set)
        else:
            qradar_post_all(import_data, ioc_count, qradar_ref_set)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Failed), Please check the network connectivity")
        sys.exit()


def qradar_post_IP(ioc_cleaned_data, ioc_count_cleaned, qradar_ref_set):
    QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_ref_set
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=ioc_cleaned_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "Imported " + str(ioc_count_cleaned) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure)")
      

def qradar_post_all(import_data, ioc_count, qradar_ref_set):
    QRadar_POST_url = "https://" + qradar_server + "/api/reference_data/sets/bulk_load/" + qradar_ref_set
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to QRadar ")
    qradar_response = requests.request("POST", QRadar_POST_url, data=import_data, headers=QRadar_headers, verify=False)
    if qradar_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + " (Finished) Imported " + str(ioc_count) + " IOCs to QRadar (Success)" )
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to QRadar (Failure)")


def socket_check_qradar():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to QRadar")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((qradar_server, int(443)))
    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to QRadar")
        socket_check_misp()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to QRadar, Please check connectivity before proceeding.")


def socket_check_misp():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to MISP")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((misp_server, int(443)))
    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to MISP")
        validate_refSet()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to MISP Server, Please check connectivity before proceeding.")

# todo: run script by scheduler


if __name__ == "__main__":
    validate_refSet()
