import pandas as pd
import requests
import time
import os
import json
import pprint
import nvdlib

def cvss_online(cve_id):
    try:
        nvdlib.read_timeout = 60
        cve = nvdlib.searchCVE(cveId=cve_id,verbose=True)[0]
    except IndexError:
        return "Invalid CVE ID"
    
    # Initialize variables with 'NF' for Not Found
    description = v2score = v2exploitability = v2severity = v2impactScore = 'NF'
    accessVector = accessComplexity = authentication = confidentialityImpact = integrityImpact = availabilityImpact = 'NF'
    
    try:
        description = cve.descriptions[0].value
    except AttributeError:
        pass
    
    try:
        v2score = cve.v2score
    except AttributeError:
        pass
    
    try:
        v2exploitability = cve.v2exploitability
    except AttributeError:
        pass
    
    try:
        v2severity = cve.v2severity
    except AttributeError:
        pass
    
    try:
        v2impactScore = cve.v2impactScore
    except AttributeError:
        pass
    
    try:
        cvss_data = cve.metrics.cvssMetricV2[0].cvssData
        accessVector = cvss_data.accessVector
        accessComplexity = cvss_data.accessComplexity
        authentication = cvss_data.authentication
        confidentialityImpact = cvss_data.confidentialityImpact
        integrityImpact = cvss_data.integrityImpact
        availabilityImpact = cvss_data.availabilityImpact
    except AttributeError:
        pass
    
    return {
        "cve": cve_id,
        "description": description,
        "baseScore": v2score,
        "exploitabilityScore": v2exploitability,
        "severity": v2severity,
        "impactScore": v2impactScore,
        "accessVector": accessVector,
        "accessComplexity": accessComplexity,
        "authentication": authentication,
        "confidentialityImpact": confidentialityImpact,
        "integrityImpact": integrityImpact,
        "availabilityImpact": availabilityImpact
    }
def update_database_with_new_cves(scan_results, db):
    scan_results = scan_results.drop_duplicates()
    scan_results = scan_results.loc[~scan_results['cve'].isin(db['cve']),['cve']]
    cve_list = scan_results['cve'].unique()
    new_cves = []
    for cve in cve_list:
        cve_info = cvss_online(cve)
        if cve_info != "Invalid CVE ID" or cve_info['description'] !='NF':
            new_cves.append(cve_info)
    new_cves_df = pd.DataFrame(new_cves)
    db = pd.concat([db, new_cves_df], ignore_index=True)

    return db
def map_scan_results_to_database(scan_results, db):
    result = pd.merge(scan_results, db, on='cve', how='left')
    result = result.fillna('NF')
    return result

def map_cve(NAMESPACE):
    print(f'Mapping {NAMESPACE}...')
    scan_results = pd.read_csv(f'./data/scanned/{NAMESPACE}.csv')
    db = pd.read_csv('./data/cve_id_db.csv',low_memory=False)
    db = update_database_with_new_cves(scan_results, db)
    result = map_scan_results_to_database(scan_results, db)
    db.to_csv('./data/cve_id_db.csv', index=False)
    result.to_csv(f'./data/mapped/{NAMESPACE}.csv', index=False)
    print(f'Mapping {NAMESPACE} completed, file saved in mapped folder!')