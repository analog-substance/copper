package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/analog-substance/copper/pkg/lib"
	"github.com/analog-substance/fileutil"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for open TCP ports",
	Run: func(cmd *cobra.Command, args []string) {
		timeoutTCP, _ := cmd.Flags().GetInt("tcp-timeout")
		tcpPortCount, _ := cmd.Flags().GetInt("top")
		targetFile, _ := cmd.Flags().GetString("file")
		workers, _ := cmd.Flags().GetInt("workers")
		rate, _ := cmd.Flags().GetInt("rate")
		openOnly, _ := cmd.Flags().GetBool("open")
		allTargets, _ := cmd.Flags().GetStringSlice("targets")

		if fileutil.HasStdin() {
			allTargets = append(allTargets, fileutil.ReadFileLines(os.Stdin)...)
		}

		if targetFile != "" {
			lines, err := fileutil.ReadLines(targetFile)
			if err != nil {
				fmt.Printf("[!] Unable to open target file: %s\n", targetFile)
				return
			}

			allTargets = append(allTargets, lines...)
		}

		var targets []string
		for _, target := range allTargets {
			if strings.Contains(target, "*") || target == "" {
				continue
			}

			if strings.Contains(target, "/") {
				targets = append(targets, lib.ExpandCIDR(target)...)
			} else {
				targets = append(targets, target)
			}
		}

		if workers == 0 {
			workers = len(targets)
		}

		results := lib.ScanHosts(targets, timeoutTCP, tcpPortCount, workers, rate)
		for result := range results {
			fmt.Printf("Host: %s\n\n", result.Host)

			lines := []string{"PORT\tSTATE\tSERVICE"}
			for _, p := range result.Ports {
				state := "open"
				if p.IsClosed() {
					if openOnly {
						continue
					}

					state = "closed"
				}

				lines = append(lines, fmt.Sprintf("%d\t%s\t%s", p.Port, state, p.Service))
			}

			fmt.Println(columnize.SimpleFormat(lines))

			if result.Error != nil {
				fmt.Printf("\n[!] Warning: %v\n", result.Error)
			}
			fmt.Println()
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().IntP("tcp-timeout", "T", 500, "TCP timeout in milliseconds")
	scanCmd.Flags().Int("top", 1000, "Top number ports to check")
	scanCmd.Flags().IntP("workers", "w", 0, "Worker count. Defaults to the number of hosts")
	scanCmd.Flags().IntP("rate", "r", 1000, "Ports to check per second")
	scanCmd.Flags().StringP("file", "f", "", "File containing targets")
	scanCmd.Flags().StringSliceP("targets", "t", []string{}, "Targets to scan")
	scanCmd.Flags().Bool("open", false, "Show only open ports")
}
