import sys
import re
from collections import defaultdict

#preload XML
import xml.etree.ElementTree as ET
import re
with open("nvdcve-Modified.xml") as f:
    xmlstring = f.read()

xmlstring = re.sub(' xmlns="[^"]+"', '', xmlstring, count=1)
root = ET.fromstring(xmlstring)
#root = tree.getroot()
#namespace ="http://nvd.nist.gov/feeds/cve/1.2"

def etree_to_dict(t):
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.iteritems():
                dd[k].append(v)
        d = {t.tag: {k:v[0] if len(v) == 1 else v for k, v in dd.iteritems()}}
    if t.attrib:
        d[t.tag].update(('@' + k, v) for k, v in t.attrib.iteritems())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
              d[t.tag]['#text'] = text
        else:
            d[t.tag] = text
    return d


def get_package_dict(package_strs):
    packages = defaultdict(set)
    errors = []
    for x in package_strs:
        m = re.search(r'(.*/)*(.*)-(.*)-(.*?)\.(.*)', x)
        if m:
            (path, name, version, release, platform) = m.groups()
            path = path or ''
            verrel = version + '-' + release
            packages[name].add(version)
            #print "\t".join([path, name, verrel, version, release, platform])
        else:
            errors.append('ERROR: Invalid name: %s\n' % x)

    return errors, packages


def get_vulns(packages):
    result = defaultdict(list)
    for entry in root:
        for vuln_soft in entry.findall("vuln_soft"):
            for prod in vuln_soft.findall("prod"):
                if prod.attrib['name'] in packages:
                    vers = set([x.attrib['num'] for x in prod.findall("vers")])
                    intersection = set(vers).intersection(packages[prod.attrib['name']])
                    if len(intersection) > 0:
                        si = ' - ' + ','.join(intersection)
                        result[prod.attrib['name'] + si].append(etree_to_dict(entry)["entry"])
                        print result[prod.attrib['name'] + si]
                        print entry.attrib['name'] + "," + entry.attrib['severity'] + "," + prod.attrib['name'] + "," + str(intersection) + entry.find("desc/descript").text
    return result


#FLASK app
from flask import Flask
from flask import render_template
from flask import request
import json

app = Flask(__name__)

@app.route("/", methods=['POST', 'GET'])
def hello():
    if request.method == "GET":
        return render_template("index.html", vulns={}, package_str="", vuln_free=False, errors=[])
    else:
        print request.form["package_list"]
        errors, packages = get_package_dict(request.form["package_list"].split("\n"))
        print errors, packages
        vulns = get_vulns(packages)
        return render_template("index.html", vulns=vulns, package_str=request.form["package_list"],
                               vuln_free=len(vulns) == 0, errors=errors)


if __name__ == "__main__":
    app.run()