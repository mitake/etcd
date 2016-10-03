FROM ubuntu
RUN apt-get update
RUN apt-get install -y --no-install-recommends iptables sudo curl file iputils-ping telnet
ADD bin/etcd-agent /
ADD bin/etcd /
ADD bin/etcd-tester /
RUN mkdir /failure_archive
ADD run-agent.sh /
RUN apt-get install -y --no-install-recommends \
    libzmq3-dev libnetfilter-queue-dev \
    fuse \
    ## (Optional) Install pynmz nfqhook deps
    libnetfilter-queue1
ADD nmz /
ADD dummy.sh /
CMD ["/run-agent.sh"]
