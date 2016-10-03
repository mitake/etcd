#! /bin/sh

iptables -p tcp --dport 9027 -A INPUT -j NFQUEUE --queue-num 42
/nmz inspectors ethernet -nfq-number 42 -orchestrator-url http://172.17.0.1:10080/api/v3 &
/etcd-agent -etcd-path ./etcd
