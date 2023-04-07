package lib

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/analog-substance/nmapservices"
)

type ScanResult struct {
	Host  string
	Ports []int
	Error error
}

func scanHostsWorker(wg *sync.WaitGroup, hosts chan string, results chan ScanResult, timeoutTCPMillis int, topPorts int, rate int) {
	defer wg.Done()

	ports := nmapservices.TopTCPPorts(topPorts)
	// fmt.Printf("Num ports: %d\n", len(ports))
	for host := range hosts {
		// fmt.Printf("[+] Scanning host %s\n", host)
		result := ScanResult{
			Host: host,
		}

		portChan := make(chan int)
		portResults := make(chan portStatus)

		ctx, cancel := context.WithCancel(context.Background())

		// for _, port := range ports {
		// 	status := checkPort(host, timeoutTCPMillis, port.Port)
		// 	if status.state == stateTimeout {
		// 		continue
		// 	}

		// 	if status.isHostDown() {
		// 		result.Error = fmt.Errorf("host is down: %v", status.err)
		// 		break
		// 	}

		// 	// If the state is unknown, just append the error until this is more fleshed out
		// 	if status.state == stateUnknown {
		// 		err := status.err
		// 		if result.Error != nil {
		// 			err = errors.Join(result.Error, err)
		// 		}

		// 		result.Error = err
		// 		continue
		// 	}

		// 	if status.isOpen() {
		// 		result.Ports = append(result.Ports, port.Port)
		// 	}
		// }

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

					// fmt.Printf("[+] Trying port %d\n", port)

					wgPort.Add(1)
					go func() {
						defer wgPort.Done()

						select {
						case <-ctx.Done():
						case portResults <- checkPort(host, timeoutTCPMillis, port):
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
					// fmt.Println("Context is done")
					return
				case portChan <- port.Port:
				}
			}
		}()

		for status := range portResults {
			// fmt.Printf("Received status: %d\n", status.port)
			if status.state == stateTimeout {
				continue
			}

			if status.isHostDown() {
				result.Error = fmt.Errorf("host is down: %v", status.err)
				break
			}

			// If the state is unknown, just append the error until this is more fleshed out
			if status.state == stateUnknown {
				err := status.err
				if result.Error != nil {
					err = errors.Join(result.Error, err)
				}

				result.Error = err
				continue
			}

			if status.isOpen() {
				result.Ports = append(result.Ports, status.port)
			}
		}
		cancel()

		results <- result
	}
}

func ScanHosts(hosts []string, timeoutTCPMillis int, topPorts int, threads int, rate int) chan ScanResult {
	results := make(chan ScanResult)

	go func() {
		defer close(results)

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
