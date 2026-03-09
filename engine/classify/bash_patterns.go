package classify

import "strings"

// isPipeToShell checks for dangerous pipe-to-shell patterns.
func isPipeToShell(cmd string) bool {
	lower := strings.ToLower(cmd)
	dangerousPatterns := []string{
		"| bash", "| sh", "| zsh",
		"|bash", "|sh", "|zsh",
		"eval $(",
		"eval `",
	}
	for _, p := range dangerousPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isHighRiskExecutionChain(cmd string) bool {
	lower := strings.ToLower(cmd)
	patterns := []string{
		"| python", "| python3", "| node", "| perl", "| ruby", "| php",
		"|python", "|python3", "|node", "|perl", "|ruby", "|php",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// matchPattern does simple glob matching where * matches any substring.
func matchPattern(pattern, text string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == text
	}

	remaining := text
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}
	return true
}
