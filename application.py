from cve_lookup import *
#FLASK app
from flask import Flask, redirect
from flask import render_template
from flask import request
import json

# *.xml in the dbs/ folder
parse_dbs("dbs")

application = Flask(__name__)


# Redirect index to promenade for branding. It's how we pay the server hosting bills :)
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