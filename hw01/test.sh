#!/bin/bash

function log {
    logfile=$1
    echo ====$1====
    shift
    ./logger config.txt -o "`echo $logfile | sed s/^answers/outputs/`" -p ./logger.so $@
}

log $@