#!/bin/bash

printf 'powershell -ep bypass -WindowStyle Hidden -c '"'"
cat - | tr -d '\n' | sed 's/'"'"'/'"''"'/g'
printf "'"
