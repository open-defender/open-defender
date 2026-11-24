package monitor

//go:generate mockgen -source=monitor.go -destination=mocks/monitor_mock.go -package=mocks

import (
	"context"
	"fmt"
	"log"
	"open-defender/pkg/banpool"
	"open-defender/pkg/config"
	"open-defender/pkg/connector"
	"open-defender/pkg/ebpfmonitors"
	"open-defender/pkg/protocol"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	netIOCounters  = net.IOCountersWithContext
	diskIOCounters = disk.IOCountersWithContext
	cpuPercent     = cpu.PercentWithContext
	memVirtual     = mem.VirtualMemoryWithContext
)

var ipPattern = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)

type MonitorHub interface {
	RunMonitoring()
	RunBaseMonitor(name string, bm *config.BaseFields) error
	RunResourceMonitor(rm *config.ResourceMonitorConfig) error
	RunNetworkMonitor(nc *config.EbpfNetworkAntireconConfig) error
}

type monitorHub struct {
	cfg        *config.Config
	configPath string
	ctx        context.Context
	cancel     context.CancelFunc
	wg         *sync.WaitGroup
	bp         banpool.BanPool
	exportChan chan protocol.Envelope
	restart    chan struct{}
}

func New(cfg *config.Config, bp banpool.BanPool, configPath string) MonitorHub {
	ctx, cancel := context.WithCancel(context.Background())
	return &monitorHub{
		ctx:        ctx,
		cancel:     cancel,
		cfg:        cfg,
		configPath: configPath,
		wg:         new(sync.WaitGroup),
		bp:         bp,
		exportChan: make(chan protocol.Envelope, exportQueueSize),
		restart:    make(chan struct{}, 1),
	}
}

func (mh *monitorHub) RunMonitoring() {
	for {
		mh.runCycle()

		select {
		case <-mh.restart:
			log.Println("configuration changed, restarting monitors")
			if err := mh.cfg.LoadConfigReadOnly(mh.configPath); err != nil {
				log.Println(err.Error())
				return
			}
			mh.ctx, mh.cancel = context.WithCancel(context.Background())
			mh.wg = new(sync.WaitGroup)
		default:
			return
		}
	}
}

func (mh *monitorHub) runCycle() {
	defer mh.cancel()

	if err := mh.bp.RestoreBans(mh.ctx); err != nil {
		log.Println(err.Error())
	}

	baseMonitors := []struct {
		name string
		bm   *config.BaseFields
	}{
		{protocol.SourceSSHMonitor, &mh.cfg.SSHMonitor.BaseFields},
		{protocol.SourceWebBruteMonitor, &mh.cfg.WebBruteMonitor.BaseFields},
		{protocol.SourceWebReconMonitor, &mh.cfg.WebReconMonitor.BaseFields},
		{protocol.SourceDatabaseMonitor, &mh.cfg.DatabaseMonitor.BaseFields},
	}

	for _, mon := range baseMonitors {
		mh.wg.Go(func() {
			if err := mh.RunBaseMonitor(mon.name, mon.bm); err != nil {
				log.Println(err.Error())
			}
		})
	}
	mh.wg.Go(func() {
		if err := mh.RunResourceMonitor(&mh.cfg.ResourceMonitor); err != nil {
			log.Println(err.Error())
		}
	})
	mh.wg.Go(func() {
		if err := mh.RunNetworkMonitor(&mh.cfg.EbpfMonitors.NetworkAntirecon); err != nil {
			log.Println(err.Error())
		}
	})
	mh.wg.Go(func() {
		controller := ebpfmonitors.NewUserCommandControllerMonitor(mh.ctx, mh.cfg.EbpfMonitors.UserCommandController, func(event protocol.AlertEvent) {
			mh.alert(journalInfo, event, func() {})
		})
		if err := controller.Run(); err != nil {
			log.Printf("user_command_controller: %v", err)
		}
	})
	if mh.cfg.Exporter.Enabled && mh.exportChan != nil {
		exporter := connector.New(mh.cfg, mh.configPath, mh.ctx, mh.cancel, mh.exportChan, mh.restart)
		mh.wg.Go(exporter.Run)
	}
	mh.wg.Wait()
}

func (mh *monitorHub) export(event protocol.AlertEvent) {
	if mh.exportChan == nil || !mh.cfg.Exporter.Enabled {
		return
	}
	if event.HappenedAt.IsZero() {
		event.HappenedAt = time.Now().UTC()
	}
	envelope, err := protocol.NewEnvelope(
		protocol.ServiceAlert,
		protocol.OpRaised,
		mh.cfg.Exporter.ConfigID,
		mh.cfg.Exporter.UserID,
		0,
		protocol.AlertPayload{Events: []protocol.AlertEvent{event}},
	)
	if err != nil {
		log.Println(err.Error())
		return
	}
	select {
	case mh.exportChan <- *envelope:
	default:
		log.Println("export queue is full, dropping event")
	}
}

func (mh *monitorHub) getIp(re *regexp.Regexp, message string) (string, bool) {
	matches := re.FindStringSubmatch(message)
	if len(matches) == 0 {
		return "", false
	}
	for i, name := range re.SubexpNames() {
		if name == "ip" {
			return matches[i], true
		}
	}
	return "", false

}

var goRun = func(f func()) { go f() }

func (mh *monitorHub) alert(critLevel int, event protocol.AlertEvent, afterAction func()) {
	log.Printf("<%d>%s\n", critLevel, event.Message)
	mh.export(event)
	goRun(afterAction)
}

func (mh *monitorHub) alertSync(critLevel int, event protocol.AlertEvent, afterAction func()) {
	log.Printf("<%d>%s\n", critLevel, event.Message)
	mh.export(event)
	afterAction()
}

func (mh *monitorHub) RunNetworkMonitor(nc *config.EbpfNetworkAntireconConfig) error {
	nm := ebpfmonitors.NewNetworkMonitor(mh.ctx, mh.cancel, *nc, mh.bp, func(message string, isNewBan bool) {
		ip := ipPattern.FindString(message)
		event := protocol.AlertEvent{
			Source:  protocol.SourceNetworkAntirecon,
			IP:      ip,
			Message: message,
		}
		mh.alert(journalInfo, event, func() {})
		if isNewBan {
			mh.export(protocol.AlertEvent{
				Source:  protocol.SourceIPBan,
				IP:      ip,
				Message: fmt.Sprintf("ip_ban -> %s is banned", ip),
			})
		}
	})
	return nm.Run()
}

func (mh *monitorHub) RunBaseMonitor(name string, bm *config.BaseFields) error {
	if bm.Mode == modeDisabled {
		return nil
	}
	outputChan := make(chan string, 1000)
	re, err := regexp.Compile(bm.Pattern)
	if err != nil {
		mh.cancel()
		return fmt.Errorf("monitor.RunBaseMonitor() -> %w: %v", ErrCompileRegexp, err)
	}
	if err := startSource(mh.ctx, bm, outputChan); err != nil {
		return err
	}
	ipAttempts := make(map[string]uint64)
	window := max(time.Second, time.Duration(bm.WindowSeconds)*time.Second)
	windowEnd := time.Now().Add(window)
	timer := time.NewTimer(time.Until(windowEnd))
	defer timer.Stop()
	for {
		var message string
		var received bool
		select {
		case <-timer.C:
		case message, received = <-outputChan:
			if !received {
				return nil
			}
		}
		if now := time.Now(); !now.Before(windowEnd) {
			ipAttempts = make(map[string]uint64)
			windowEnd = now.Add(window - now.Sub(windowEnd)%window)
			timer.Reset(time.Until(windowEnd))
		}
		if !received {
			continue
		}
		ip, found := mh.getIp(re, message)
		if !found || slices.Contains(mh.cfg.IPWhiteList, ip) {
			continue
		}
		counter := ipAttempts[ip] + 1
		if counter >= bm.Tries {
			isNewBan := false
			if bm.Mode == modeBlocker {
				alreadyBanned, err := mh.bp.BanIP(mh.ctx, ip, bm.BanSeconds)
				if err != nil {
					log.Println(err.Error())
				} else if !alreadyBanned {
					isNewBan = true
				}
			}

			if bm.Mode != modeBlocker || isNewBan {
				event := protocol.AlertEvent{
					Source:  name,
					IP:      ip,
					Message: fmt.Sprintf("%s -> found offenders ip %s while scanning %s: %s-%s", name, ip, bm.Engine, bm.LogPath, bm.UnitName),
					Details: map[string]any{"engine": bm.Engine, "source": bm.Source()},
				}
				mh.alert(journalInfo, event, func() {})
				if isNewBan {
					mh.export(protocol.AlertEvent{
						Source:  protocol.SourceIPBan,
						IP:      ip,
						Message: fmt.Sprintf("ip_ban -> %s is banned", ip),
					})
				}
			}

			counter = 0
		}
		ipAttempts[ip] = counter
	}
}

func (mh *monitorHub) checkResourceMetrics(rm *config.ResourceMonitorConfig) error {
	active := func(limits config.ResourceFields) bool {
		return limits.Warning != 0 || limits.Alert != 0
	}
	checkCPU := active(rm.CpuUsagePersentage)
	checkTraffic := active(rm.TrafficUsageMBs)
	checkDisk := active(rm.DiskUsageIOps)

	var netBefore []net.IOCountersStat
	var diskBefore map[string]disk.IOCountersStat
	var err error
	if checkTraffic {
		netBefore, err = netIOCounters(mh.ctx, false)
		if err != nil {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetTrafficUsage, err)
		}
	}
	if checkDisk {
		diskBefore, err = diskIOCounters(mh.ctx)
		if err != nil {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetDiskUsage, err)
		}
	}

	var cpuUsage float64
	if checkCPU {
		samples, err := cpuPercent(mh.ctx, windowPollInterval, false)
		if err != nil {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetCPUUsage, err)
		}
		if len(samples) == 0 {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: no measurements", ErrCantGetCPUUsage)
		}
		cpuUsage = samples[0]
	} else if checkTraffic || checkDisk {
		timer := time.NewTimer(windowPollInterval)
		defer timer.Stop()
		select {
		case <-mh.ctx.Done():
			return nil
		case <-timer.C:
		}
	}

	seconds := windowPollInterval.Seconds()
	var trafficMBs float64
	if checkTraffic {
		netAfter, err := netIOCounters(mh.ctx, false)
		if err != nil {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetTrafficUsage, err)
		}
		if len(netBefore) > 0 && len(netAfter) > 0 {
			rxBytes := netAfter[0].BytesRecv - netBefore[0].BytesRecv
			txBytes := netAfter[0].BytesSent - netBefore[0].BytesSent
			trafficMBs = float64(rxBytes+txBytes) / seconds / 1024 / 1024
		}
	}

	var diskIOps float64
	if checkDisk {
		diskAfter, err := diskIOCounters(mh.ctx)
		if err != nil {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetDiskUsage, err)
		}
		var totalIOps uint64
		for name, after := range diskAfter {
			before, ok := diskBefore[name]
			if ok {
				totalIOps += (after.ReadCount - before.ReadCount) + (after.WriteCount - before.WriteCount)
			}
		}
		diskIOps = float64(totalIOps) / seconds
	}

	var ramPercent float64
	if active(rm.RamUsagePersentage) {
		v, err := memVirtual(mh.ctx)
		if err != nil {
			return fmt.Errorf("monitor.checkResourceMetrics() -> %w: %v", ErrCantGetRAMUsage, err)
		}
		ramPercent = v.UsedPercent
	}

	alerted := mh.checkLimits("cpu usage", cpuUsage, "%", rm.CpuUsagePersentage, rm.OutputTopSnapshotDir)
	alerted = mh.checkLimits("ram usage", ramPercent, "%", rm.RamUsagePersentage, rm.OutputTopSnapshotDir) || alerted
	alerted = mh.checkLimits("traffic usage", trafficMBs, "mb/s", rm.TrafficUsageMBs, rm.OutputTopSnapshotDir) || alerted
	alerted = mh.checkLimits("disk usage", diskIOps, "iops", rm.DiskUsageIOps, rm.OutputTopSnapshotDir) || alerted

	if alerted {
		timer := time.NewTimer(resourceAlertCooldown)
		defer timer.Stop()
		select {
		case <-mh.ctx.Done():
		case <-timer.C:
		}
	}

	return nil
}

func (mh *monitorHub) checkLimits(name string, value float64, unit string, limits config.ResourceFields, snapshotDir string) bool {
	if limits.Alert != 0 && value >= float64(limits.Alert) {
		message := fmt.Sprintf("resource_monitor -> %s is %.2f%s, alert limit is %d%s", name, value, unit, limits.Alert, unit)
		event := protocol.AlertEvent{
			Source:   protocol.SourceResourceMonitor,
			Severity: protocol.SeverityAlert,
			Message:  message,
			Details:  map[string]any{"metric": name, "value": value, "unit": unit, "limit": limits.Alert},
		}

		mh.alertSync(journalAlert, event, func() {
			if err := mh.saveSnapshot(snapshotDir); err != nil {
				log.Println(err.Error())
			}
		})

		return true
	}

	if limits.Warning != 0 && value >= float64(limits.Warning) {
		message := fmt.Sprintf("resource_monitor -> %s is %.2f%s, warning limit is %d%s", name, value, unit, limits.Warning, unit)
		event := protocol.AlertEvent{
			Source:   protocol.SourceResourceMonitor,
			Severity: protocol.SeverityWarning,
			Message:  message,
			Details:  map[string]any{"metric": name, "value": value, "unit": unit, "limit": limits.Warning},
		}

		mh.alert(journalWarning, event, func() {})
	}

	return false
}

func (mh *monitorHub) RunResourceMonitor(rm *config.ResourceMonitorConfig) error {
	if !rm.Enabled {
		return nil
	}

	ticker := time.NewTicker(resourcePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-mh.ctx.Done():
			return nil

		case <-ticker.C:
			if err := mh.checkResourceMetrics(rm); err != nil {
				log.Println("RunResourceMonitor() -> ", err)
			}
		}
	}
}
