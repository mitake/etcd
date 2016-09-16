// Copyright 2015 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/pkg/capnslog"
	"github.com/prometheus/client_golang/prometheus"
)

var plog = capnslog.NewPackageLogger("github.com/coreos/etcd", "etcd-tester")

func main() {
	endpointStr := flag.String("agent-endpoints", "localhost:9027", "HTTP RPC endpoints of agents. Do not specify the schema.")
	datadir := flag.String("data-dir", "agent.etcd", "etcd data directory location on agent machine.")
	stressKeyLargeSize := flag.Uint("stress-key-large-size", 32*1024+1, "the size of each large key written into etcd.")
	stressKeySize := flag.Uint("stress-key-size", 100, "the size of each small key written into etcd.")
	stressKeySuffixRange := flag.Uint("stress-key-count", 250000, "the count of key range written into etcd.")
	limit := flag.Int("limit", -1, "the limit of rounds to run failure set (-1 to run without limits).")
	stressQPS := flag.Int("stress-qps", 10000, "maximum number of stresser requests per second.")
	schedCases := flag.String("schedule-cases", "", "test case schedule")
	consistencyCheck := flag.Bool("consistency-check", true, "true to check consistency (revision, hash)")
	isV2Only := flag.Bool("v2-only", false, "'true' to run V2 only tester.")
	noFailure := flag.Bool("no-failure", false, "'true' to not inject failures.")
	noFailureInterval := flag.Int("no-failure-interval", 10, "interval for no failure mode in seconds.")
	checkOnly := flag.Bool("check-only", false, "'true' to check consistency only.")
	terminateAgents := flag.Bool("terminate-agents", true, "'true' to not terminate agents at the end of the tester command.")
	flag.Parse()

	c := &cluster{
		v2Only:               *isV2Only,
		datadir:              *datadir,
		stressQPS:            *stressQPS,
		stressKeyLargeSize:   int(*stressKeyLargeSize),
		stressKeySize:        int(*stressKeySize),
		stressKeySuffixRange: int(*stressKeySuffixRange),
	}

	if err := c.bootstrap(strings.Split(*endpointStr, ","), !*checkOnly); err != nil {
		plog.Fatal(err)
	}

	if *terminateAgents {
		defer c.Terminate()
	}

	// ensure cluster is fully booted to know failpoints are available
	c.WaitHealth()

	var failures []failure

	if !*noFailure {
		failures = []failure{
			newFailureKillAll(),
			newFailureKillMajority(),
			newFailureKillOne(),
			newFailureKillLeader(),
			newFailureKillOneForLongTime(),
			newFailureKillLeaderForLongTime(),
			newFailureIsolate(),
			newFailureIsolateAll(),
			newFailureSlowNetworkOneMember(),
			newFailureSlowNetworkLeader(),
			newFailureSlowNetworkAll(),
		}

		fpFailures, fperr := failpointFailures(c)
		if len(fpFailures) == 0 {
			plog.Infof("no failpoints found (%v)", fperr)
		}
		failures = append(failures, fpFailures...)
	}

	schedule := failures
	if schedCases != nil && *schedCases != "" {
		cases := strings.Split(*schedCases, " ")
		schedule = make([]failure, len(cases))
		for i := range cases {
			caseNum := 0
			n, err := fmt.Sscanf(cases[i], "%d", &caseNum)
			if n == 0 || err != nil {
				plog.Fatalf(`couldn't parse case "%s" (%v)`, cases[i], err)
			}
			schedule[i] = failures[caseNum]
		}
	}

	t := &tester{
		failures:          schedule,
		cluster:           c,
		limit:             *limit,
		consistencyCheck:  *consistencyCheck,
		noFailureInterval: time.Duration(*noFailureInterval) * time.Second,
	}

	if *checkOnly {
		err := t.checkConsistency(false)
		if err != nil {
			plog.Errorf("checking consistency failed: %s", err)
			os.Exit(1)
		}

		os.Exit(0)
	}

	sh := statusHandler{status: &t.status}
	http.Handle("/status", sh)
	http.Handle("/metrics", prometheus.Handler())
	go func() { plog.Fatal(http.ListenAndServe(":9028", nil)) }()

	t.runLoop()
}
