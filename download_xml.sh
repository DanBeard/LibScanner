#!/usr/bin/env bash

mkdir -p dbs
cd dbs
rm *.xml

for i in $(seq -f "%02g" 2 17)
do
    wget https://nvd.nist.gov/download/nvdcve-20$i.xml.gz
    gunzip nvdcve-20$i.xml.gz
done

rm *.gz
