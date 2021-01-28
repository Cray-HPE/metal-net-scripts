#!/bin/bash
echo "Running Lint for Python"
python3 -m ensurepip >/dev/null 2>&1
pip3 install -e .[lint] >/dev/null 2>&1

ALL_OK=1
for FILE in $(find */ | grep -e '\.py$'); do
    echo "Checking $FILE"
    if ! pycodestyle --ignore=E501 --show-source --show-pep8 --format=pylint "$FILE"; then ALL_OK=0; fi
done

if [ "$ALL_OK" == 0 ]; then exit 1; fi

