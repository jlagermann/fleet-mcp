package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/guides"
	"github.com/jlagermann/fleet-mcp/internal/secrets"
)

// guideText returns a guide with every fleet-mcp command given by the
// binary's full path, since fleet-mcp is often not on the user's PATH.
func guideText(name string) (guides.Guide, string, bool) {
	g, text, ok := guides.Get(name)
	if !ok {
		return g, "", false
	}
	return g, strings.ReplaceAll(text, "`fleet-mcp ", "`"+secrets.Command()+" "), true
}

// registerGuides adds fm_guide and one MCP prompt per guide. They need no
// Fleet Manager or secret store.
func registerGuides(s *mcp.Server) {
	type guideArgs struct {
		Topic string `json:"topic,omitempty" jsonschema:"guide name; omit to list the guides"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "fm_guide",
		Description: "Step-by-step guide for a multi-step fleet-mcp task. Load the matching guide before you start the task and follow it. Guides: " +
			strings.Join(guides.Names(), ", ") + ". Without topic, lists the guides and when each applies.",
		Annotations: readOnly("Workflow guide"),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a guideArgs) (*mcp.CallToolResult, any, error) {
		if a.Topic == "" {
			r, err := jsonResult(guides.All())
			return r, nil, err
		}
		_, text, ok := guideText(a.Topic)
		if !ok {
			return nil, nil, fmt.Errorf("no guide %q; guides: %s", a.Topic, strings.Join(guides.Names(), ", "))
		}
		return textResult(text), nil, nil
	})

	for _, g := range guides.All() {
		name := g.Name
		s.AddPrompt(&mcp.Prompt{
			Name: name, Title: g.Title, Description: g.Description,
			Arguments: []*mcp.PromptArgument{{
				Name: "request", Title: "Request",
				Description: "what you want done, in your own words (Fleet Manager, sensor, host, policy...); optional",
			}},
		}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			g, text, _ := guideText(name)
			msg := "Follow this fleet-mcp guide.\n\n" + text
			if r := strings.TrimSpace(req.Params.Arguments["request"]); r != "" {
				msg += "\nMy request: " + r + "\n"
			} else {
				msg += "\nAsk me what I want done, then start.\n"
			}
			return &mcp.GetPromptResult{
				Description: g.Description,
				Messages:    []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: msg}}},
			}, nil
		})
	}
}

// guideFirst starts the description of a tool that a guide covers.
func guideFirst(topic string) string {
	return "Follow fm_guide topic " + topic + " for this task. "
}
