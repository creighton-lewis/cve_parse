#!/bin/bash
set -x 
target = "$1"
grep "hostname" "$1"
grep  "CVE" "$1"