package lib

import (
	"context"
	"fmt"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/schollz/progressbar/v3"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"
)

func HostRespondsToICMP(host string, timeoutMillisICMP int, privilegedICMP bool) bool {
	pinger, err := probing.NewPinger(host)
	if err != nil {
		return false
	}
	pinger.Count = 1
	pinger.SetPrivileged(privilegedICMP)
	pinger.Timeout = time.Duration(timeoutMillisICMP) * time.Millisecond
	err = pinger.Run()
	if err != nil {
		if !strings.Contains(err.Error(), "sendto") {
			log.Println("error running ping", host, err)
		}
		return false
	}
	stats := pinger.Statistics()

	if stats.PacketsRecv > 0 {
		return true
	}
	return false
}

func HostHasOpenPort(host string, ports []int, timeoutTCPMillis int) bool {
	for _, port := range ports {
		err := makeTCPConnection(host, timeoutTCPMillis, port)

		if err != nil {
			if strings.HasSuffix(err.Error(), "connect: connection refused") {
				return true
			}

			if strings.HasSuffix(err.Error(), "connect: no route to host") {
				return false
			}

			if strings.HasSuffix(err.Error(), "no such host") {
				return false
			}

			if strings.HasSuffix(err.Error(), "network is unreachable") {
				return false
			}

			if strings.HasSuffix(err.Error(), "i/o timeout") {
				continue
			}

			if strings.HasSuffix(err.Error(), "operation was canceled") {
				continue
			}

			println(err.Error())
			continue
		}

		return true
	}
	return false
}

func GetOpenPortsOnHost(host string, ports []int, timeoutTCPMillis int) []int {
	portResults := map[int]bool{}

	for _, port := range ports {
		err := makeTCPConnection(host, timeoutTCPMillis, port)

		if err != nil {
			if strings.HasSuffix(err.Error(), "connect: connection refused") {
				portResults[port] = false
				continue
			}

			if strings.HasSuffix(err.Error(), "connect: no route to host") {
				portResults[port] = false
				continue
			}

			if strings.HasSuffix(err.Error(), "no such host") {
				portResults[port] = false
				continue
			}

			if strings.HasSuffix(err.Error(), "network is unreachable") {
				portResults[port] = false
				continue
			}

			if strings.HasSuffix(err.Error(), "i/o timeout") {
				portResults[port] = false
				continue
			}

			if strings.HasSuffix(err.Error(), "operation was canceled") {
				portResults[port] = false
				continue
			}

			continue
		}

		portResults[port] = true
	}

	openPorts := []int{}
	for port, open := range portResults {
		if open {
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}

func makeTCPConnection(host string, timeoutTCPMillis int, port int) error {
	d := net.Dialer{
		Timeout:  time.Duration(timeoutTCPMillis) * time.Millisecond,
		Deadline: time.Now().Add(time.Duration(timeoutTCPMillis) * time.Millisecond),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutTCPMillis)*time.Millisecond)
	//defer cancel()
	go func() {
		time.Sleep(time.Duration(timeoutTCPMillis) * time.Millisecond)
		cancel()
	}()
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err == nil {
		conn.Close()
	}
	return err
}

func checkHost(host string, c chan hostStatus, ports []int, timeoutMillisICMP, timeoutTCPMillis int, privilegedICMP bool) {
	if timeoutMillisICMP > 0 && HostRespondsToICMP(host, timeoutMillisICMP, privilegedICMP) {
		c <- hostStatus{host, "ICMP", true}
		return
	}

	if timeoutTCPMillis > 0 && HostHasOpenPort(host, ports, timeoutTCPMillis) {
		c <- hostStatus{host, "TCP Ports", true}
		return
	}

	c <- hostStatus{host, "", false}
}

func worker(hosts chan string, res chan hostStatus, ports []int, timeoutMillisICMP, timeoutTCPMillis int, privilegedICMP bool) {

	for host := range hosts {
		checkHost(host, res, ports, timeoutMillisICMP, timeoutTCPMillis, privilegedICMP)
	}
}

func DiscoverHosts(hosts []string, verboseMode bool, attempts, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, workerCount int, privilegedICMP bool) []string {
	bar := progressbar.Default(int64(len(hosts)))
	workers := make(chan string, workerCount)
	c := make(chan hostStatus)

	ports := GetTopPopularPorts("tcp", portCheckCount)

	for i := 0; i < cap(workers); i++ {
		go worker(workers, c, ports, timeoutMillisICMP, timeoutTCPMillis, privilegedICMP)
	}

	go func() {
		for _, host := range hosts {
			workers <- host
		}
	}()

	result := make([]hostStatus, len(hosts))
	activeHosts := []string{}
	inactiveHosts := []string{}

	for i, _ := range result {
		result[i] = <-c
		bar.Add(1)
		if result[i].active {
			activeHosts = append(activeHosts, result[i].host)

			if verboseMode {
				fmt.Printf("%s\t%s\n", result[i].host, result[i].method)
			}
			//fmt.Println(result[i].host, "is up.")
		} else {
			// pin in this, we need to talk about how to handle async shit as a library
			inactiveHosts = append(inactiveHosts, result[i].host)
		}
	}

	close(workers)
	close(c)

	attempts--
	if attempts > 0 && len(inactiveHosts) > 0 {
		if verboseMode {
			fmt.Printf("Performing additional attempt on %d hosts.\n", len(inactiveHosts))
		}
		reallyActive := DiscoverHosts(inactiveHosts, verboseMode, attempts, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, workerCount, privilegedICMP)
		activeHosts = append(activeHosts, reallyActive...)
	}

	return activeHosts
}

type hostStatus struct {
	host   string
	method string
	active bool
}

func ExpandCIDR(cidr string) []string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}

	var ips []string
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr.String())
	}

	if len(ips) < 2 {
		return ips
	}

	return ips[1 : len(ips)-1]
}
