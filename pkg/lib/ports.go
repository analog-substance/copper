package lib

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strconv"
)

type portInfo struct {
	Service  string
	Protocol string
	Port     int
	Weight   float64
}

var popularPorts = map[string][]int{}

func GetPopularPorts(protocol string) []int {
	if _, ok := popularPorts[protocol]; !ok {
		p, err := getNmapPortData(protocol)
		if err != nil {
			if protocol == "udp" {
				p = PopularUDPPorts
			} else {
				p = PopularTCPPorts
			}
		}
		popularPorts[protocol] = p
	}

	return popularPorts[protocol]
}

func GetTopPopularPorts(protocol string, count int) []int {
	return GetPopularPorts(protocol)[:count]
}

func getNmapPortData(protocol string) ([]int, error) {

	csvFile, err := os.Open("/usr/share/nmap/nmap-services")

	if err != nil {
		return nil, err
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
		return nil, err
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

	return portsByWeight, nil
}
