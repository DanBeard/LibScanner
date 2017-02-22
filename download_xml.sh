#!/usr/bin/env bash

mkdir -p dbs
cd dbs
rm *.xml

year=`date +"%Y"`
for i in $(seq -f "%04g" 2002 $year)
do
    wget https://nvd.nist.gov/download/nvdcve-$i.xml.gz
    gunzip nvdcve-$i.xml.gz
done

rm *.gz
