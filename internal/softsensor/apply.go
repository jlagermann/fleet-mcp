package softsensor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jlagermann/fleet-mcp/internal/host"
)

// Results of an upgrade run, from its last stage.
const (
	ResultRunning        = "running"
	ResultDone           = "done"
	ResultFailed         = "failed"
	ResultRebootRequired = "reboot-required"
)

// deployExit explains corelightctl sensor deploy's exit codes (from its
// --help).
var deployExit = map[string]string{
	"1": "general error",
	"2": "system reboot required before deployment",
	"3": "bootstrap process failed; there is no rollback (on slow storage usually a timeout: see the guide's retry rule)",
	"4": "preflight check failures",
	"5": "failed during the pre-deployment snapshot",
	"6": "deployment failed; the rollback completed, so the sensor runs the previous deployment",
	"7": "deployment failed with rollback disabled",
	"8": "deployment failed and the rollback also failed",
	"9": "deployment successful but post-deployment cleanup failed",
}

// runScript is the upgrade itself. It runs as a transient systemd unit and
// writes one line per stage to the state file.
const runScript = `#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
state=` + stateFile + `
log=` + logFile + `
stage() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >>"$state"; }
: >"$state"
stage start {{TARGET}}
if [ {{DEPLOYONLY}} = no ]; then
  stage install
  if ! apt-get install -y -q {{ALLOW}}-o Dpkg::Options::=--force-confold corelightctl={{TARGET}} corelight-sensor={{TARGET}} >>"$log" 2>&1; then
    stage failed install; exit 1
  fi
  apt-get clean
fi
stage prepare
corelightctl --no-color sensor prepare >>"$log" 2>&1; rc=$?
if [ $rc -eq 2 ]; then stage reboot-required prepare; exit 2; fi
if [ $rc -ne 0 ]; then stage failed prepare $rc; exit $rc; fi
stage deploy
corelightctl --no-color sensor deploy -v >>"$log" 2>&1; rc=$?
if [ $rc -eq 0 ] || [ $rc -eq 9 ]; then stage done $rc; exit 0; fi
if [ $rc -eq 2 ]; then stage reboot-required deploy; exit 2; fi
stage failed deploy $rc
exit $rc
`

// Status is the state of the latest upgrade run on a host.
type Status struct {
	Result    string   `json:"result"`
	Stages    []string `json:"stages,omitempty"`
	Installed string   `json:"installed,omitempty"`
	Error     string   `json:"error,omitempty"`
	LogTail   []string `json:"log_tail,omitempty"`
}

// startScript writes the run script and starts it as a systemd unit. The
// state file gets a "queued" stage first, so a run that dies before its
// first stage reads as failed, not as "never ran".
func startScript(p *Plan) string {
	deployOnly, allow := "no", ""
	if p.DeployOnly {
		deployOnly = "yes"
	}
	if p.Downgrade {
		allow = "--allow-downgrades "
	}
	run := strings.NewReplacer("{{TARGET}}", host.Quote(p.Target), "{{DEPLOYONLY}}", deployOnly, "{{ALLOW}}", allow).Replace(runScript)
	// The redirect must not follow the heredoc's end marker on a line of
	// its own: bash would then truncate the file after cat printed it.
	return fmt.Sprintf(`set -e
mkdir -p /var/lib/fleet-mcp
chmod 700 /var/lib/fleet-mcp
{
%s} >%s
chmod 700 %s
grep -q 'sensor deploy' %s
echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) queued" >%s
echo "=== $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) fleet-mcp Software Sensor upgrade to %s" >>%s
systemctl reset-failed %s 2>/dev/null || true
systemd-run --unit=%s --collect --quiet --property=TimeoutStartSec=infinity /bin/bash %s
`, host.Heredoc(run), scriptFile, scriptFile, scriptFile, stateFile, p.Target, logFile, unit, unit, scriptFile)
}

// Start begins the upgrade the plan describes and returns at once.
func (s *Planner) Start(ctx context.Context, p *Plan) error {
	if !p.Ready() {
		return fmt.Errorf("nothing to do, or blocked: %s", strings.Join(p.Blockers, "; "))
	}
	res, err := s.R.Run(ctx, startScript(p))
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("starting the upgrade failed: %s", strings.TrimSpace(res.Stderr))
	}
	return nil
}

const statusScript = `echo "unit=$(systemctl is-active ` + unit + ` 2>/dev/null)"
sed 's/^/stage=/' ` + stateFile + ` 2>/dev/null
echo "installed=$(dpkg-query -W -f='${Version}' corelight-sensor 2>/dev/null)"
tail -n 400 ` + logFile + ` 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -a -iE 'error|fatal|failed|E: ' | tail -n 8 | sed 's/^/err=/'
tail -n 5 ` + logFile + ` 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^/log=/'
`

// Status reads the latest upgrade run.
func (s *Planner) Status(ctx context.Context) (*Status, error) {
	res, err := s.R.Run(ctx, statusScript)
	if err != nil {
		return nil, err
	}
	st := &Status{}
	active := false
	var errs []string
	for _, l := range strings.Split(res.Stdout, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "unit":
			active = v == "active" || v == "activating"
		case "stage":
			st.Stages = append(st.Stages, v)
		case "installed":
			st.Installed = v
		case "err":
			errs = append(errs, clip(v, 300))
		case "log":
			st.LogTail = append(st.LogTail, clip(v, 300))
		}
	}
	st.Result = result(st.Stages, active)
	if st.Result == ResultFailed {
		st.Error = failure(st.Stages)
		st.LogTail = append(errs, st.LogTail...)
	}
	return st, nil
}

// Wait polls Status until the run ends or limit passes.
func (s *Planner) Wait(ctx context.Context, limit time.Duration) (*Status, error) {
	poll := s.Poll
	if poll == 0 {
		poll = 30 * time.Second
	}
	deadline := time.Now().Add(limit)
	for {
		st, err := s.Status(ctx)
		if err == nil && st.Result != ResultRunning {
			return st, nil
		}
		if err == nil && s.OnPoll != nil {
			s.OnPoll(st)
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, err
			}
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// result reads the outcome from the stages; a run whose unit is gone
// without a final stage was interrupted (e.g. by a reboot).
func result(stages []string, active bool) string {
	if active {
		return ResultRunning
	}
	if len(stages) == 0 {
		return ""
	}
	last := strings.Fields(stages[len(stages)-1])
	if len(last) < 2 {
		return ResultFailed
	}
	switch last[1] {
	case ResultDone:
		return ResultDone
	case ResultRebootRequired:
		return ResultRebootRequired
	}
	return ResultFailed
}

func failure(stages []string) string {
	if len(stages) == 0 {
		return ""
	}
	last := strings.Fields(stages[len(stages)-1])
	if len(last) < 2 {
		return "unknown"
	}
	if last[1] != ResultFailed {
		return "the run stopped during " + last[1] + " without finishing (interrupted, e.g. by a reboot or a killed unit)"
	}
	msg := "failed during " + strings.Join(last[2:3], "")
	if len(last) > 3 {
		code := last[3]
		msg += " (exit " + code + ")"
		if len(last) > 2 && last[2] == "deploy" {
			if why, ok := deployExit[code]; ok {
				msg += ": " + why
			}
		}
	}
	return msg
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
