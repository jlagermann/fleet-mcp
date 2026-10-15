package tools

import (
	"context"
	"errors"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/hostdiag"
)

func registerHostDiag(s *mcp.Server, d *Deps) {
	f := false
	type diagArgs struct {
		Host    string `json:"host,omitempty" jsonschema:"host name or IP address of the Fleet Manager host (default: the host in the Fleet Manager's URL, from fleet)"`
		Fleet   string `json:"fleet,omitempty" jsonschema:"name of the Fleet Manager (see fm_fleets) whose host to check, when host is not given"`
		SSHUser string `json:"ssh_user,omitempty" jsonschema:"SSH user with passwordless sudo (default: FLEET_MCP_SSH_USER or your ssh config)"`
		SSHPort int    `json:"ssh_port,omitempty" jsonschema:"SSH port (default 22)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_host_diagnose",
		Description: "Read-only health check of a running Fleet Manager host over SSH: the corelight-fleetd service (state, restarts), installed and available version, CPU load, memory, disk space and the data path's largest parts, " +
			"corelight-fleetd errors and warnings in the journal over the last 24 hours, TLS and product identity certificate expiry, ports 443 and 1443, NTP sync, files holding secrets that every local user can read, and the newest backup. " +
			"Returns findings, errors first. For a host that has no Fleet Manager yet, use fm_host_check.",
		Annotations: &mcp.ToolAnnotations{Title: "Diagnose Fleet Manager host", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a diagArgs) (*mcp.CallToolResult, any, error) {
		h := a.Host
		if h == "" {
			if a.Fleet == "" {
				return nil, nil, errors.New("give host, or fleet to use the host of that Fleet Manager")
			}
			c, err := d.conn(a.Fleet)
			if err != nil {
				return nil, nil, err
			}
			u, err := url.Parse(c.URL)
			if err != nil || u.Hostname() == "" {
				return nil, nil, errors.New("cannot take a host from the Fleet Manager's URL; give host")
			}
			h = u.Hostname()
		}
		r, err := d.runner(hostArgs{Host: h, SSHUser: a.SSHUser, SSHPort: a.SSHPort})
		if err != nil {
			return nil, nil, err
		}
		rep, err := hostdiag.Run(ctx, r)
		if err != nil {
			return nil, nil, err
		}
		res, err := jsonResult(rep)
		return res, nil, err
	})
}
