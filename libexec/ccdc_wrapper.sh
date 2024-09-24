#!/bin/bash
exec /usr/libexec/ccdc/ccdc.py "$@" > /var/log/ccdc_wrapper.log 2>&1
