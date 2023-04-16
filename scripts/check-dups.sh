#!/bin/bash
#
# This script checks if there are duplicate entries in the README file.
#

readme="README.md"

pwd=$(pwd)

if [[ "${pwd: -7}" == "scripts" ]];
then
    readme="../README.md"    
fi

links=$(cat $readme | egrep "\- \[" | wc -l)

uniqlinks=$(cat $readme | egrep "\- \[" | uniq | wc -l)

if [[ $links -eq $uniqlinks ]];
then
    echo "[ OK! ] NO DUPLICATES FOUND."
    echo "$links links in README."
else
    echo "[ ERR ] DUPLICATES FOUND!"
    cat $readme | egrep "\- \[" | uniq -c | egrep -iv "1 - ["
fi