package content

import "time"

func init() { rulesetSettle = 10 * time.Millisecond }

// LintModifier exposes lintModifier to tests.
var LintModifier = lintModifier
