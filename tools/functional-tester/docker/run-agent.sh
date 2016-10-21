#! /bin/sh

sudo iptables -p tcp --dport 2379 -A INPUT -j NFQUEUE --queue-num 42
sudo /nmz inspectors ethernet -entity-id `hostname` -nfq-number 42 -orchestrator-url http://172.17.0.1:10080/api/v3 &
/etcd-agent -etcd-path ./etcd
