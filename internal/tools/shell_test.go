package tools

import (
	"strings"
	"testing"
)

func TestShellCommand(t *testing.T) {
	ok := map[string]shellArgs{
		"status":        {Check: "status"},
		"upgrade":       {Check: "upgrade", Pattern: "zeek-bundle"},
		"upgrade-old":   {Check: "upgrade", File: "corelightctl.log-20261011"},
		"service_logs":  {Check: "service_logs", Service: "sensor-operator", Container: "manager", Lines: 5000},
		"exporter_logs": {Check: "exporter_logs", Exporter: "exporter-635n2t7kxj"},
		"pod_logs":      {Check: "pod_logs", Pod: "sensor-core-5cddd55b4f-abcde"},
		"system_log":    {Check: "system_log", File: "k3s.log", Pattern: "it's \"quoted\"; $(reboot)"},
		"datastore":     {Check: "datastore"},
	}
	for name, a := range ok {
		cmd, err := shellCommand(a)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(cmd, " stop") || strings.Contains(cmd, "purge") || strings.Contains(cmd, "deploy ") {
			t.Errorf("%s: a changing command: %s", name, cmd)
		}
	}
	cmd, _ := shellCommand(ok["service_logs"])
	if !strings.Contains(cmd, "-l 2000") || !strings.Contains(cmd, "-s 'sensor-operator' -c 'manager'") {
		t.Errorf("service_logs: %s", cmd)
	}
	cmd, _ = shellCommand(ok["system_log"])
	if !strings.Contains(cmd, `grep -i -F -e 'it'"'"'s "quoted"; $(reboot)'`) {
		t.Errorf("pattern not quoted: %s", cmd)
	}
	cmd, _ = shellCommand(ok["upgrade"])
	if !strings.Contains(cmd, "'/system-logs/corelightctl.log'") || !strings.Contains(cmd, "-e 'failed to get k8s node'") {
		t.Errorf("upgrade: %s", cmd)
	}

	for name, a := range map[string]shellArgs{
		"unknown":        {Check: "stop"},
		"no service":     {Check: "service_logs"},
		"service inject": {Check: "service_logs", Service: "x; reboot"},
		"traversal":      {Check: "system_log", File: "../etc/shadow"},
		"abs":            {Check: "system_log", File: "/etc/shadow"},
		"dotdot":         {Check: "system_log", File: "a..b"},
		"pattern nl":     {Check: "system_log", File: "k3s.log", Pattern: "a\nb"},
		"container":      {Check: "pod_logs", Pod: "p", Container: "-it"},
	} {
		if _, err := shellCommand(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
