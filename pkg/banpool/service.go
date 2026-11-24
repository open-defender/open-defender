package banpool

//go:generate mockgen -source=service.go -destination=mocks/service_mock.go -package=mocks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"open-defender/pkg/config"
	"sync"
	"time"
)

type BanPool interface {
	BanIP(ctx context.Context, ip string, banSeconds uint64) (bool, error)
	UnbanIP(ip string) error
	RestoreBans(ctx context.Context) error
}

type banPool struct {
	repository  Repository
	firewall    Firewall
	mutex       sync.Mutex
	expirations *unbanScheduler
}

const maxUnbanRetries = 5

var unbanRetryInterval = time.Minute

func New(cfg *config.Config) (BanPool, error) {
	repository, err := NewRepository(cfg.BlockedIPsDatabase)
	if err != nil {
		return nil, fmt.Errorf("banpool.New() -> %w", err)
	}
	filterDockerChainsWithoutDockerEngine(cfg)
	fw, err := NewFirewall(cfg.FirewallEngine, cfg.FirewallChains)
	if err != nil {
		return nil, err
	}
	return &banPool{
		repository: repository,
		firewall:   fw,
	}, nil
}

func filterDockerChainsWithoutDockerEngine(cfg *config.Config) {
	hasDockerEngine := false
	for _, monitor := range cfg.Monitors() {
		if monitor.Fields.Engine == "docker" {
			hasDockerEngine = true
			break
		}
	}
	if hasDockerEngine {
		return
	}

	dockerChain := "DOCKER-USER"
	if cfg.FirewallEngine == "nftables" {
		dockerChain = nftablesForwardBanChain
	}
	foundDockerChain := false
	for _, chain := range cfg.FirewallChains {
		if chain == dockerChain {
			foundDockerChain = true
			break
		}
	}
	if !foundDockerChain {
		return
	}

	chains := make([]string, 0, len(cfg.FirewallChains)-1)
	for _, chain := range cfg.FirewallChains {
		if chain != dockerChain {
			chains = append(chains, chain)
		}
	}
	cfg.FirewallChains = chains
	log.Printf("No monitor uses engine docker; ignoring firewall chain %q for this run", dockerChain)
}

func (bp *banPool) RestoreBans(ctx context.Context) error {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()

	expired, err := bp.repository.GetExpired()
	if err != nil {
		return fmt.Errorf("banpool.RestoreBans() -> %w", err)
	}

	for _, ban := range expired {
		if err := bp.unban(ban.IP); err != nil {
			log.Println(err.Error())
		} else {
			bp.unscheduleUnban(ban.IP)
		}
	}

	bans, err := bp.repository.GetBanned()
	if err != nil {
		return fmt.Errorf("banpool.RestoreBans() -> %w", err)
	}

	for _, ban := range bans {
		if err := bp.firewall.Ban(ban.IP); err != nil {
			log.Println(err.Error())

			if deleteErr := bp.repository.Delete(ban.ID); deleteErr != nil {
				log.Println(deleteErr.Error())
			}

			continue
		}

		bp.scheduleUnban(ctx, ban)
	}

	return nil
}

func (bp *banPool) BanIP(ctx context.Context, ip string, banSeconds uint64) (bool, error) {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()

	now := time.Now()

	ban := &Ban{
		IP:          ip,
		BannedAt:    now,
		BannedUntil: now.Add(time.Duration(banSeconds) * time.Second),
	}

	current, err := bp.repository.Get(ip)
	if err != nil && !errors.Is(err, ErrBanNotFound) {
		return false, fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
	}

	if current != nil {
		if err := bp.firewall.Ban(ip); err != nil {
			return true, fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
		}

		if err := bp.extendBan(current, ban.BannedUntil); err != nil {
			return true, err
		}
		bp.scheduleUnban(ctx, current)
		return true, nil
	}

	id, err := bp.repository.Add(ban)
	if err != nil {
		return false, fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
	}

	ban.ID = id

	if err := bp.firewall.Ban(ip); err != nil {
		if deleteErr := bp.repository.Delete(ban.ID); deleteErr != nil {
			log.Println(deleteErr)
		}

		return false, fmt.Errorf("banpool.BanIP(ip: %s) -> %w", ip, err)
	}

	bp.scheduleUnban(ctx, ban)

	return false, nil
}

func (bp *banPool) UnbanIP(ip string) error {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()

	if err := bp.unban(ip); err != nil {
		return err
	}
	bp.unscheduleUnban(ip)
	return nil
}

func (bp *banPool) extendBan(ban *Ban, bannedUntil time.Time) error {
	if !bannedUntil.After(ban.BannedUntil) {
		return nil
	}

	updated := *ban
	updated.BannedUntil = bannedUntil
	if err := bp.repository.Update(&updated); err != nil {
		return fmt.Errorf("banpool.extendBan(ip: %s) -> %w", ban.IP, err)
	}
	ban.BannedUntil = bannedUntil

	return nil
}

func (bp *banPool) unban(ip string) error {
	ban, err := bp.repository.Get(ip)
	if err != nil {
		if errors.Is(err, ErrBanNotFound) {
			return nil
		}

		return fmt.Errorf("banpool.unban(ip: %s) -> %w", ip, err)
	}

	return bp.removeBan(ban)
}

func (bp *banPool) removeBan(ban *Ban) error {
	if err := bp.firewall.Unban(ban.IP); err != nil {
		return fmt.Errorf("banpool.unban(ip: %s) -> %w", ban.IP, err)
	}

	if err := bp.repository.Delete(ban.ID); err != nil {
		return fmt.Errorf("banpool.unban(ip: %s) -> %w", ban.IP, err)
	}
	log.Println("Successfully unbanned ip: ", ban.IP)
	return nil
}
