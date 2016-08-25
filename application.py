import sys
import re
from collections import defaultdict

# preload XML
import xml.etree.cElementTree as ET
import re
import glob

xmlstring = []
root = None
for filename in glob.glob('dbs/*.xml'):
    with open(filename) as f:
        db_string = f.read()# remove the annoying namespace
        db_string = re.sub(' xmlns="[^"]+"', '', db_string, count=1)
        #xmlstring.append(db_string)
        data = ET.fromstring(db_string)
        if root is None:
            root = data
        else:
            root.extend(data)


#root = ET.fromstring("\n".join(xmlstring))
# namespace ="http://nvd.nist.gov/feeds/cve/1.2"

def etree_to_dict(t):
    """
    Change the xml tree to an easy to use python dict
    :param t: the xml tree
    :return: a dict representation
    """
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


def get_packages_swid(package_list):
    """
    Get the packages from a swid string
    :param package_strs:
    :return:
    """

def get_packages_rpm(package_list):
    """
    Get the packages from an rpm string
    :param package_strs:
    :return:
    """
    package_strs = package_list.split("\n")
    packages = defaultdict(set)
    errors = []
    for x in package_strs:
        m = re.search(r'(.*/)*(.*)-(.*)-(.*?)\.(.*)', x)
        if m:
            (path, name, version, release, platform) = m.groups()
            path = path or ''
            verrel = version + '-' + release
            packages[name].add(version)
            # print "\t".join([path, name, verrel, version, release, platform])
        else:
            errors.append('ERROR: Invalid name: %s\n' % x)

    return errors, packages

def get_package_dict(package_list):
    """
    Get the packages from the string
    :param package_strs:
    :return:
    """
    if package_list.startswith("<?xml"):
        return get_packages_swid(package_list)
    else:
        return get_packages_rpm(package_list)


def get_vulns(packages):
    """
    Get the vulns from a list of packages returned by get_package_dict()
    :param packages:
    :return:
    """
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
from flask import Flask, redirect
from flask import render_template
from flask import request
import json

application = Flask(__name__)


@application.route("/", methods=['POST', 'GET'])
def home_redirect():
    return redirect("http://promenadesoftware.com/tools")


@application.route("/tool", methods=['POST', 'GET'])
def tool():
    if request.method == "GET":
        return render_template("index.html", vulns={}, package_str="", vuln_free=False, errors=[])
    else:
        errors, packages = get_package_dict(request.form["package_list"])
        vulns = get_vulns(packages)
        return render_template("index.html", vulns=vulns, package_str=request.form["package_list"],
                               vuln_free=len(vulns) == 0, errors=errors)


if __name__ == "__main__":
    application.run()