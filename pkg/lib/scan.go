package lib

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/analog-substance/nmapservices"
)

type ScanResult struct {
	Host  string
	Ports []ProbeResult
	Error error
}

var portsMap map[int]nmapservices.PortInfo
var ports []nmapservices.PortInfo

func scanHostsWorker(wg *sync.WaitGroup, hosts chan string, results chan ScanResult, timeoutTCPMillis int, topPorts int, rate int) {
	defer wg.Done()

	for host := range hosts {
		result := ScanResult{
			Host: host,
		}

		portChan := make(chan nmapservices.PortInfo)
		portResults := make(chan ProbeResult)

		ctx, cancel := context.WithCancel(context.Background())

		var wgPort sync.WaitGroup
		go func() {
			ticker := time.NewTicker(time.Second * 1)

			defer func() {
				ticker.Stop()
				wgPort.Wait()

				close(portResults)
			}()

			for {
				for i := 0; i < rate; i++ {
					port, ok := <-portChan
					if !ok {
						return
					}

					wgPort.Add(1)
					go func() {
						defer wgPort.Done()

						select {
						case <-ctx.Done():
						case portResults <- checkPort(host, timeoutTCPMillis, port.Port):
						}
					}()
				}
				<-ticker.C
			}
		}()

		go func() {
			defer close(portChan)
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case portChan <- port:
				}
			}
		}()

		for status := range portResults {
			if status.State == stateTimeout {
				continue
			}

			if status.IsHostDown() {
				result.Error = fmt.Errorf("host is down: %v", status.Err)
				break
			}

			// If the state is unknown, just append the error until this is more fleshed out
			if status.State == stateUnknown {
				err := status.Err
				if result.Error != nil {
					err = errors.Join(result.Error, err)
				}

				result.Error = err
				continue
			}

			if status.IsOpen() || status.IsClosed() {
				status.Service = portsMap[status.Port].Service
				result.Ports = append(result.Ports, status)
			}
		}
		cancel()

		sort.Slice(result.Ports, func(i, j int) bool {
			return result.Ports[i].Port < result.Ports[j].Port
		})

		results <- result
	}
}

func ScanHosts(hosts []string, timeoutTCPMillis int, topPorts int, threads int, rate int) chan ScanResult {
	results := make(chan ScanResult)

	go func() {
		defer close(results)

		ports = nmapservices.TopTCPPorts(topPorts)
		portsMap = make(map[int]nmapservices.PortInfo)

		for _, port := range ports {
			portsMap[port.Port] = port
		}

		hostChan := make(chan string)

		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go scanHostsWorker(&wg, hostChan, results, timeoutTCPMillis, topPorts, rate)
		}

		for _, host := range hosts {
			hostChan <- host
		}
		close(hostChan)
		wg.Wait()
	}()

	return results
}
