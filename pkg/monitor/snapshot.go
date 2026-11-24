package monitor

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

const snapshotTimeLayout = "2006-01-02_15-04-05.000000"

var listProcesses = process.ProcessesWithContext

type processUsage struct {
	pid        int32
	user       string
	cpuPercent float64
	memPercent float32
	memoryMBs  float64
	command    string
}

func (mh *monitorHub) saveSnapshot(dir string) error {
	usages, err := mh.collectProcessUsages()
	if err != nil {
		return fmt.Errorf("monitor.saveSnapshot(dir: %s) -> %w", dir, err)
	}

	sort.Slice(usages, func(i, j int) bool {
		return usages[i].cpuPercent > usages[j].cpuPercent
	})

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("monitor.saveSnapshot(dir: %s) -> %w: %v", dir, ErrCantCreateSnapshotDir, err)
	}

	path := filepath.Join(dir, time.Now().Format(snapshotTimeLayout)+".sp")

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("monitor.saveSnapshot(dir: %s) -> %w: %v", dir, ErrCantWriteSnapshot, err)
	}
	defer file.Close()

	if err := writeSnapshot(file, usages); err != nil {
		return fmt.Errorf("monitor.saveSnapshot(dir: %s) -> %w: %v", dir, ErrCantWriteSnapshot, err)
	}

	return nil
}

func (mh *monitorHub) collectProcessUsages() ([]processUsage, error) {
	processes, err := listProcesses(mh.ctx)
	if err != nil {
		return nil, fmt.Errorf("monitor.collectProcessUsages() -> %w: %v", ErrCantGetProcesses, err)
	}

	usages := make([]processUsage, 0, len(processes))
	if len(processes) == 0 {
		return usages, nil
	}

	var totalMemory uint64
	if memory, err := mem.VirtualMemoryWithContext(mh.ctx); err == nil && memory != nil {
		totalMemory = memory.Total
	}
	usernames := make(map[int32]string)

	for _, proc := range processes {
		usage := processUsage{pid: proc.Pid}
		if uids, err := proc.UidsWithContext(mh.ctx); err == nil && len(uids) > 0 {
			uid := uids[0]
			username, cached := usernames[uid]
			if !cached {
				if account, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
					username = account.Username
				}
				usernames[uid] = username
			}
			usage.user = username
		}

		if cpuPercent, err := proc.CPUPercentWithContext(mh.ctx); err == nil {
			usage.cpuPercent = cpuPercent
		}

		if memoryInfo, err := proc.MemoryInfoWithContext(mh.ctx); err == nil && memoryInfo != nil {
			usage.memoryMBs = float64(memoryInfo.RSS) / 1024 / 1024
			if totalMemory > 0 {
				usage.memPercent = 100 * float32(memoryInfo.RSS) / float32(totalMemory)
			}
		}

		usage.command = mh.processCommand(proc)
		if usage.command == "" {
			continue
		}

		usages = append(usages, usage)
	}

	return usages, nil
}

func (mh *monitorHub) processCommand(proc *process.Process) string {
	if cmdline, err := proc.CmdlineWithContext(mh.ctx); err == nil && cmdline != "" {
		return cmdline
	}

	if name, err := proc.NameWithContext(mh.ctx); err == nil && name != "" {
		return name
	}

	return ""
}

func writeSnapshot(file *os.File, usages []processUsage) error {
	writer := tabwriter.NewWriter(file, 0, 0, 2, ' ', 0)

	if _, err := fmt.Fprintf(writer, "snapshot taken at %s\n\n", time.Now().Format(time.RFC3339)); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(writer, "PID\tUSER\tCPU%\tMEM%\tRSS(MB)\tCOMMAND"); err != nil {
		return err
	}

	for _, usage := range usages {
		_, err := fmt.Fprintf(
			writer, "%d\t%s\t%.1f\t%.1f\t%.1f\t%s\n",
			usage.pid, usage.user, usage.cpuPercent, usage.memPercent, usage.memoryMBs, usage.command,
		)
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}
