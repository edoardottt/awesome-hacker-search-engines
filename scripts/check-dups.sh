#!/bin/bash
#
# https://github.com/edoardottt/awesome-hacker-search-engines
#
# This script checks if there are duplicate entries in the README file.
#

readme="README.md"

pwd=$(pwd)

if [[ "${pwd: -7}" == "scripts" ]];
then
    readme="../README.md"    
fi

# Function to extract links from a section and check for duplicates
check_section() {
    section=$1
    section_content=$(awk -v section="$section" '/^### / {p=0} {if(p)print} /^### '"$section"'/ {p=1}' "$readme")
    duplicate_links=$(echo "$section_content" | grep -oP '\[.*?\]\(\K[^)]+' | sort | uniq -d)
    if [[ -n $duplicate_links ]]; then
        echo "[ ERR ] DUPLICATE LINKS FOUND"
        echo "$duplicate_links"
        exit 1
    fi
}

# Get all unique section headings from the README file and handle spaces and slashes
sections=$(grep '^### ' "$readme" | sed 's/^### //' | sed 's/[\/&]/\\&/g')

# Call the function for each section
for section in $sections; do
    check_section "$section"
done
echo "[ OK! ] NO DUPLICATES FOUND."