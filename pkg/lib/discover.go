package lib

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/analog-substance/nmapservices"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/schollz/progressbar/v3"
)

type portState int

const (
	stateClosed portState = iota
	stateOpen
	stateHostUnreachable
	stateTimeout
	stateUnknown
)

type portStatus struct {
	port  int
	state portState
	err   error
}

func (p portStatus) isOpen() bool {
	return p.state == stateOpen
}

func (p portStatus) isOpenOrClosed() bool {
	return p.isOpen() || p.state == stateClosed
}

func (p portStatus) isHostDown() bool {
	return p.state == stateHostUnreachable
}

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

func HostHasOpenPort(host string, timeoutTCPMillis, portCheckCount int) bool {
	for _, port := range nmapservices.TopTCPPorts(portCheckCount) {
		status := checkPort(host, timeoutTCPMillis, port.Port)
		if status.isOpenOrClosed() {
			return true
		}

		if status.isHostDown() {
			return false
		}

		if status.state == stateUnknown {
			fmt.Println(status.err) // Kept this in here but should move this to the cobra commands
		}
	}

	return false
}

func checkPort(host string, timeoutTCPMillis int, port int) portStatus {
	status := portStatus{
		port:  port,
		state: stateOpen,
	}

	err := makeTCPConnection(host, timeoutTCPMillis, port)
	if err != nil {
		status.err = err

		if strings.HasSuffix(err.Error(), "connect: connection refused") {
			status.state = stateClosed
			return status
		}

		if strings.HasSuffix(err.Error(), "connect: no route to host") {
			status.state = stateHostUnreachable
			return status
		}

		if strings.HasSuffix(err.Error(), "no such host") {
			status.state = stateHostUnreachable
			return status
		}

		if strings.HasSuffix(err.Error(), "network is unreachable") {
			status.state = stateHostUnreachable
			return status
		}

		if strings.HasSuffix(err.Error(), "i/o timeout") {
			status.state = stateTimeout
			return status
		}

		if strings.HasSuffix(err.Error(), "operation was canceled") {
			status.state = stateTimeout
			return status
		}

		status.state = stateUnknown
		return status
	}

	return status
}

func makeTCPConnection(host string, timeoutTCPMillis int, port int) error {
	d := net.Dialer{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutTCPMillis)*time.Millisecond)
	//defer cancel()
	go func() {
		time.Sleep(time.Duration(timeoutTCPMillis) * time.Millisecond)
		cancel()
	}()
	_, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))

	//_, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	return err
}

func checkHost(host string, c chan hostStatus, timeoutMillisICMP, timeoutTCPMillis, portCheckCount int, privilegedICMP bool) {
	if timeoutMillisICMP > 0 && HostRespondsToICMP(host, timeoutMillisICMP, privilegedICMP) {
		c <- hostStatus{host, "ICMP", true}
		return
	}

	if timeoutTCPMillis > 0 && HostHasOpenPort(host, timeoutTCPMillis, portCheckCount) {
		c <- hostStatus{host, "TCP Ports", true}
		return
	}

	c <- hostStatus{host, "", false}
}

func worker(hosts chan string, res chan hostStatus, timeoutMillisICMP, timeoutTCPMillis, portCheckCount int, privilegedICMP bool) {
	for host := range hosts {
		checkHost(host, res, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, privilegedICMP)
	}
}

func DiscoverHosts(hosts []string, verboseMode bool, attempts, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, workerCount int, privilegedICMP bool) []string {
	bar := progressbar.Default(int64(len(hosts)))
	workers := make(chan string, workerCount)
	c := make(chan hostStatus)
	for i := 0; i < cap(workers); i++ {
		go worker(workers, c, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, privilegedICMP)
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

type portInfo struct {
	Service  string
	Protocol string
	Port     int
	Weight   float64
}

func ExpandCIDR(cidr string) []string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}

	var ips []string
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr.String())
	}

	if len(ips) < 2 {
		return ips
	}

	return ips[1 : len(ips)-1]
}
