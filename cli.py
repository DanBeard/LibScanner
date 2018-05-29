#!/usr/bin/env python
from __future__ import print_function
"""
Command Line Interface for the CVE lookup. See README for more information
"""
import argparse
import cgi

# NIST url to link to CVEs
NIST_URL = "https://web.nvd.nist.gov/view/vuln/detail?vulnId="

parser = argparse.ArgumentParser(description="Lookup known vulnerabilities from yocto/RPM/SWID in the CVE."+
                                             " Output in JUnit style XML where a CVE = failure")
parser.add_argument("packages", help="The list of packages to run through the lookup", type=open)
parser.add_argument("db_loc", help="The folder that holds the CVE xml database files", type=str)
parser.add_argument("-f", "--format", help="The format of the packages", choices=["swid","rpm",'yocto','ls'], default=None)
parser.add_argument("-a", "--fail", help="Severity value [0-10] over which it will be a FAILURE", type=float, default=3)
parser.add_argument("-i", "--ignore_file", help="""A File containing a new-line delimited list of specific CVE's to ignore
 (e.g.  CVE-2015-7697 ) . These CVE's will show up as skipped in the report""", type=open)

args = parser.parse_args()

from cve_lookup import *
root = parse_dbs(args.db_loc)

errors, packages = get_package_dict(args.packages.read(), args.format)
cves = get_vulns(packages, root)

# get the ignore list
ignore_list = set()
ignored_control_lookup = {}
if args.ignore_file is not None:
    # first column is CVE, 2nd column is human readable description of control taken
    # eg: CVE-2015-7696 , Device shall never allow decompression of arbitrary zip files
    for line in args.ignore_file:
        cols = line.split(",") # split on ,
        if len(cols) > 0:
            cve_id = cols[0].strip()
            cve_control = "N/A"
            if len(cols) > 1:
                cve_control = cols[1]
            # add them to the list
            ignore_list.add(cve_id)
            ignored_control_lookup[cve_id] = cve_control


num_cves = sum(len(x) for x in cves.values())
num_failed_cves = sum(len([e for e in x if (e['@name'] not in ignore_list and float(e['@CVSS_score']) >= args.fail)]) for x in cves.values())

# print the xml header
print('<?xml version="1.0" encoding="UTF-8" ?>')
#print '<testsuites tests="{0}" failures="{0}" > '.format(num_cves)
print('<testsuite id="CVE TEST" name="CVE TEST" tests="{0}" failures="{1}">'.format(num_cves, num_failed_cves))
for package_name, info in cves.items():

    for e in info:
        print('<testcase id="{0}" name="{0}" classname="{1}" time="0">'.format(e['@name'], package_name))
        try:
            # always warn, but fail if we're above the failure threshold
            sev = "failure" if float(e['@CVSS_score']) >= args.fail else "warning"

            try:
                description = cgi.escape(e['desc']['descript']['#text'])
            except:
                description = ""

            # mark any CVEs in the ignore_list as skipped
            if e['@name'] in ignore_list:
                sev = "skipped"
                # append the mitigating control
                description += "\n\n Controlled by: " + ignored_control_lookup[e['@name']]

            print("<{0}> {6} ({1}) - {2} \n\n {3} {4} {5} </{0}>".format(sev, e['@CVSS_score'], description,
                                                                   e['@type'], "Published on: " + e['@published'],
                                                                   NIST_URL+e['@name'], e['@severity']))
        except Exception as e:
            print('<error>{0}</error>'.format(str(e)))

        print('</testcase>')

print("</testsuite>")
#print "</testsuites>"