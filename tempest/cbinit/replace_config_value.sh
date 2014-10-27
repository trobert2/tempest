#!/bin/bash

CONF_FILE_PATH=''

#section="$1"
key="$1"
value1="$2"

#output = sed '/\['$section'\]/,/\[/!d' | egrep -v "^#|^$" | grep $key

sed s/\<$key\>//g