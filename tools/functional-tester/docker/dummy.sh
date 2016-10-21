#! /bin/sh

if [ "$1" = "enable" ]; then
    curl -X POST '172.17.0.1:10080/api/v3/control?op=enableOrchestration'
elif [ "$1" = "disable" ]; then
    curl -X POST '172.17.0.1:10080/api/v3/control?op=disableOrchestration'
    
else
    echo "invalid argument: " $1
    exit 1
fi
