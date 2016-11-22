#!/usr/bin/env python
"""
Command Line Interface for the CVE lookup. See README for more information
"""
import argparse

# NIST url to link to CVEs
NIST_URL = "https://web.nvd.nist.gov/view/vuln/detail?vulnId="

parser = argparse.ArgumentParser(description="Lookup known vulnerabilities from yocto/RPM/SWID in the CVE."+
                                             " Output in JUnit style XML where a CVE = failure")
parser.add_argument("packages", help="The list of packages to run through the lookup", type=open)
parser.add_argument("db_loc", help="The folder that holds the CVE xml database files", type=str)
parser.add_argument("-f", "--format", help="The format of the packages", choices=["swid","rpm",'yocto'], default="yocto")
parser.add_argument("-a", "--fail", help="Severity value [0-10] over which it will be a FAILURE", type=float, default=5)

args = parser.parse_args()

from cve_lookup import *
parse_dbs(args.db_loc)

errors, packages = get_package_dict(args.packages.read())
cves = get_vulns(packages)

num_cves = sum( len(x) for x in cves.values())

# print the xml header
print '<?xml version="1.0" encoding="UTF-8" ?>'
#print '<testsuites tests="{0}" failures="{0}" > '.format(num_cves)
print '<testsuite id="CVE TEST" name="CVE TEST" tests="{0}" failures="{0}">'.format(num_cves)
for name, info in cves.iteritems():

    for e in info:
        print '<testcase id="{0}" name="{0}" classname="{0}" time="0">'.format(e['@name'])
        try:
            # always warn, but fail if we're above the failure threshold
            sev = "failure" if float(e['@CVSS_score']) >= args.fail else "warning"
            description = ""
            try:
                description = e['desc']['descript']['#text']
            except:
                pass

            print "<{0}> {1} - {2} \n\n {3} {4} {5} </{0}>".format(sev, e['@CVSS_score'], description,
                                                                   e['@type'], "Published on: " + e['@published'],
                                                                   NIST_URL+e['@name'])
        except Exception as e:
            print '<error>{0}</error>'.format(str(e))

        print '</testcase>'

print "</testsuite>"
#print "</testsuites>"