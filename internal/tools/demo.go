package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jlagermann/fleet-mcp/internal/metrics"
)

// DemoMetrics is server middleware that appends a timing footer to every
// tool result (FLEET_MCP_DEMO_METRICS=true): total time, the result's size
// in AI-context tokens, Fleet Manager API time and the tool's timeline.
// The model's own token usage is only known to the client; see
// "fleet-mcp report" for that.
func DemoMetrics() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			call, ok := req.(*mcp.CallToolRequest)
			if method != "tools/call" || !ok {
				return next(ctx, method, req)
			}
			ctx, rec := metrics.With(ctx)
			res, err := next(ctx, method, req)
			if r, ok := res.(*mcp.CallToolResult); ok && r != nil {
				size := 0
				for _, c := range r.Content {
					if t, ok := c.(*mcp.TextContent); ok {
						size += len(t.Text)
					}
				}
				r.Content = append(r.Content, &mcp.TextContent{Text: rec.Footer(call.Params.Name, size)})
			}
			return res, err
		}
	}
}
