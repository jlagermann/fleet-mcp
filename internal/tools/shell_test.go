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
		"pod_logs_kube": {Check: "pod_logs", Pod: "rke2-canal-7brk5", Container: "calico-node", Namespace: "kube-system", Pattern: "ready", Lines: 3},
		"system_log":    {Check: "system_log", File: "k3s.log", Pattern: "it's \"quoted\"; $(reboot)"},
		"datastore":     {Check: "datastore"},
		"deploy":        {Check: "deploy"},
		"node":          {Check: "node", Pattern: "Oct 12 14:5"},
	}
	for name, a := range ok {
		cmd, err := shellCommand(a)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(cmd, " stop") || strings.Contains(cmd, "purge") || strings.Contains(cmd, "corelightctl sensor deploy") {
			t.Errorf("%s: a changing command: %s", name, cmd)
		}
	}
	// sudoers allows "corelightctl sensor status" only without arguments.
	cmd, _ := shellCommand(ok["status"])
	if !strings.HasSuffix(cmd, "/usr/bin/corelightctl sensor status 2>&1") {
		t.Errorf("status: %s", cmd)
	}
	cmd, _ = shellCommand(ok["deploy"])
	if !strings.Contains(cmd, `running command \"sensor deploy\"`) || !strings.Contains(cmd, "tail -n 60") || !strings.Contains(cmd, "sensor deploy success") {
		t.Errorf("deploy: %s", cmd)
	}
	cmd, _ = shellCommand(ok["node"])
	if !strings.Contains(cmd, "grep -i -F -e 'Oct 12 14:5' /system-logs/kubelet.log") || !strings.Contains(cmd, "podStartSLOduration") {
		t.Errorf("node: %s", cmd)
	}
	cmd, _ = shellCommand(ok["pod_logs_kube"])
	if !strings.Contains(cmd, "logs -n kube-system 'rke2-canal-7brk5' -c 'calico-node' --tail 2000 | grep -i -F -e 'ready' | tail -n 3") {
		t.Errorf("pod_logs kube-system: %s", cmd)
	}
	cmd, _ = shellCommand(ok["pod_logs"])
	if !strings.Contains(cmd, "logs -n corelight-sensor 'sensor-core-") {
		t.Errorf("pod_logs default namespace: %s", cmd)
	}
	cmd, _ = shellCommand(ok["service_logs"])
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
		"namespace":      {Check: "pod_logs", Pod: "p", Namespace: "default"},
	} {
		if _, err := shellCommand(a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
