package lib

import (
	"bufio"
	"fmt"
	"github.com/go-ping/ping"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func HostRespondsToICMP(host string, timeoutMillisICMP int) bool {
	pinger, err := ping.NewPinger(host)
	if err != nil {
		return false
	}
	pinger.Count = 1
	pinger.Timeout = time.Duration(timeoutMillisICMP) * time.Millisecond
	pinger.Run()
	stats := pinger.Statistics()

	if stats.PacketLoss == 100 {
		return false
	}
	return true
}

func HostHasOpenPort(host string, timeoutTCPMillis, portCheckCount int) bool {
	for i, port := range ports {
		if i == portCheckCount {
			return false
		}
		d := net.Dialer{Timeout: time.Duration(timeoutTCPMillis) * time.Millisecond}
		_, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))

		if err != nil {
			if strings.HasSuffix(err.Error(), "connect: connection refused") {
				return true
			}

			if strings.HasSuffix(err.Error(), "connect: no route to host") {
				return false
			}

			if strings.HasSuffix(err.Error(), "i/o timeout") {
				continue
			}

			println(err.Error())
			continue
		}

		return true
	}
	return false
}

func checkHost(host string, c chan hostStatus, timeoutMillisICMP, timeoutTCPMillis, portCheckCount int) {
	if HostRespondsToICMP(host, timeoutMillisICMP) {
		c <- hostStatus{host, "ICMP", true}
		return
	}

	if HostHasOpenPort(host, timeoutTCPMillis, portCheckCount) {
		c <- hostStatus{host, "TCP Ports", true}
		return
	}

	c <- hostStatus{host, "", false}
}

func worker(hosts chan string, res chan hostStatus, timeoutMillisICMP, timeoutTCPMillis, portCheckCount int) {
	for host := range hosts {
		checkHost(host, res, timeoutMillisICMP, timeoutTCPMillis, portCheckCount)
	}
}

func DiscoverHosts(hosts []string, verboseMode bool, attempts, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, workerCount int) []string {
	workers := make(chan string, workerCount)
	c := make(chan hostStatus)
	for i := 0; i < cap(workers); i++ {
		go worker(workers, c, timeoutMillisICMP, timeoutTCPMillis, portCheckCount)
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
		if result[i].active {
			activeHosts = append(activeHosts, result[i].host)
			if verboseMode {
				fmt.Printf("%s\t%s\n", result[i].host, result[i].method)
			}
			//fmt.Println(result[i].host, "is up.")
		} else {
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
		reallyActive := DiscoverHosts(inactiveHosts, verboseMode, attempts, timeoutMillisICMP, timeoutTCPMillis, portCheckCount, workerCount)
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

func getNmapPortData(protocol string) []int {

	csvFile, err := os.Open("/usr/share/nmap/nmap-services")

	if err != nil {
		fmt.Println(err)
	}

	defer csvFile.Close()

	var allRecords []portInfo

	scanner := bufio.NewScanner(csvFile)

	re := regexp.MustCompile(`^([^\t]+)\t([0-9]+)/(tcp|udp)\t([0-9\.]+)`)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		each := re.FindStringSubmatch(scanner.Text())

		if len(each) > 0 {
			portNumber, _ := strconv.Atoi(each[2])
			weight, _ := strconv.ParseFloat(each[4], 6)
			allRecords = append(allRecords, portInfo{
				each[1],
				each[3],
				portNumber,
				weight,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	sort.Slice(allRecords, func(i, j int) bool {
		return allRecords[i].Weight > allRecords[j].Weight
	})

	portsByWeight := []int{}
	for _, port := range allRecords {
		if port.Protocol == protocol {
			portsByWeight = append(portsByWeight, port.Port)
		}
	}

	return portsByWeight
}

var ports []int

func init() {
	ports = getNmapPortData("tcp")
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
