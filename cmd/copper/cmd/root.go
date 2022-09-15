package cmd

import (
	"bufio"
	"fmt"
	"github.com/analog-substance/copper/pkg/lib"
	"github.com/spf13/cobra"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "copper",
	Short: "A fast host discovery tool",
	Long: `This tool will attempt to discover active hosts using the following:
	- ICMP Ping.
	- Checking TCP ports until it finds an open one.

If a method succeeds, the host is marked as active and not touched again. 
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		timeoutICMP, _ := cmd.Flags().GetInt("icmp-timeout")
		timeoutTCP, _ := cmd.Flags().GetInt("tcp-timeout")
		tcpPortCount, _ := cmd.Flags().GetInt("tcp-ports")
		attempts, _ := cmd.Flags().GetInt("attempts")
		scopeFile, _ := cmd.Flags().GetString("file")
		verboseMode, _ := cmd.Flags().GetBool("verbose")
		workerCount, _ := cmd.Flags().GetInt("workers")

		start := time.Now()

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

		if workerCount == 0 {
			workerCount = len(hosts)
		}

		activeHosts := lib.DiscoverHosts(hosts, verboseMode, attempts, timeoutICMP, timeoutTCP, tcpPortCount, workerCount)

		if !verboseMode {
			for _, host := range activeHosts {
				fmt.Println(host)
			}
		}

		duration := time.Since(start)
		fmt.Printf("Checked %d hosts, %d are active. Took %s\n", len(hosts), len(activeHosts), duration)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("verbose", "v", false, "Print active hosts as they are found")
	rootCmd.Flags().IntP("icmp-timeout", "i", 500, "ICMP timeout in milliseconds")
	rootCmd.Flags().IntP("tcp-timeout", "t", 500, "TCP timeout in milliseconds")
	rootCmd.Flags().IntP("tcp-ports", "T", 100, "Number of TCP ports to check")
	rootCmd.Flags().IntP("workers", "w", 0, "Worker count. defaults to the number of hosts")
	rootCmd.Flags().IntP("attempts", "a", 1, "Number of attempts per host")
	rootCmd.Flags().StringP("file", "f", "scope.txt", "File with scope to check")
}
