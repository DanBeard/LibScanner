This is a simple flask app that parses RPM or SWID package lists and runs them through the NVD.

To get this working you will need to download a copy of the NVD here: https://nvd.nist.gov/download.cfm#CVE_FEED
and put the xml files in the dbs folder.

You can run download_xml.sh to do this for you automatically. 


The command line interface is similar but outputs a JUnit style XML document for automated continuous integration.
To get the package list of your install:

yocto - Follow the instructions in the yocto manual and paste the contents of installed-packages.txt below.
rpm - run 'rpm -qa' in the terminal and paste the ouput below
other - 'pip install swid_generator && swid_generator swid' in the terminal and paste the output below

run package-cve-lookup -h for more information on using the command line interface


