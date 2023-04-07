package cmd

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/analog-substance/copper/pkg/lib"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for open TCP ports",
	Run: func(cmd *cobra.Command, args []string) {
		timeoutTCP, _ := cmd.Flags().GetInt("tcp-timeout")
		tcpPortCount, _ := cmd.Flags().GetInt("top")
		scopeFile, _ := cmd.Flags().GetString("file")
		workers, _ := cmd.Flags().GetInt("workers")
		rate, _ := cmd.Flags().GetInt("rate")

		hosts := []string{}
		var scopeReader io.Reader
		var err error
		if scopeFile == "-" {
			scopeReader = os.Stdin
		} else {
			if _, err = os.Stat(scopeFile); err == nil {
				scopeReader, err = os.Open(scopeFile)
				if err != nil {
					fmt.Println(err)
				}
			} else {
				fmt.Printf("unable to open scope file: %s\n", scopeFile)
				return
			}
		}

		scanner := bufio.NewScanner(scopeReader)
		for scanner.Scan() {
			input := scanner.Text()
			if strings.Contains(input, "*") {
				continue
			}

			if strings.Contains(input, "/") {
				hosts = append(hosts, lib.ExpandCIDR(input)...)
			} else {
				hosts = append(hosts, input)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Println(err)
		}

		//if scopeFile != "-" {
		//	scopeReader.Close()
		//}

		if workers == 0 {
			workers = len(hosts)
		}

		results := lib.ScanHosts(hosts, timeoutTCP, tcpPortCount, workers, rate)
		for result := range results {
			fmt.Printf("[+] %s - Ports: %v\n", result.Host, result.Ports)
			if result.Error != nil {
				fmt.Printf("[!] Warning: %v\n", result.Error)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().IntP("tcp-timeout", "T", 500, "TCP timeout in milliseconds")
	scanCmd.Flags().IntP("top", "t", 1000, "Number of TCP ports to check")
	scanCmd.Flags().IntP("workers", "w", 0, "Worker count. Defaults to the number of hosts")
	scanCmd.Flags().IntP("rate", "r", 100, "Ports to check per second")
	scanCmd.Flags().StringP("file", "f", "scope.txt", "File with scope to check")
}
