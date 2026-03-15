// Package classify implements bash command classification for LOA.
// This is a UX optimization, not a security boundary.
// The real enforcement is at the Envoy sidecar (network) and scoped credentials (service).
package classify

import "strings"

// Result is the classification of a single command segment.
type Result struct {
	Executable string
	Action     string
	Resource   string
	Matched    bool // true if a tool mapping matched
}

// Classification is the result of classifying a full (possibly compound) command.
type Classification struct {
	Command  string
	Segments []Result
	Decision string // "permit_candidate", "observe_unmapped", "observe_flagged"
	Reason   string
}

// Classifier classifies bash commands against tool mappings.
type Classifier struct {
	mappings        []Mapping
	defaultUnmapped string // currently informational: "permit" or "deny"
	strict          bool
}

// ClassifierOptions configures optional classifier behavior.
type ClassifierOptions struct {
	Strict bool
}

// Mapping is a tool mapping entry from protector.yml.
type Mapping struct {
	Executable        string
	Pattern           string
	SubcommandPattern string
	Action            string
	ResourceExtractor string
}

// NewClassifier creates a classifier from tool mappings.
func NewClassifier(mappings []Mapping, defaultUnmapped string) *Classifier {
	return NewClassifierWithOptions(mappings, defaultUnmapped, ClassifierOptions{})
}

// NewClassifierWithOptions creates a classifier with optional strict-mode behavior.
func NewClassifierWithOptions(mappings []Mapping, defaultUnmapped string, opts ClassifierOptions) *Classifier {
	return &Classifier{
		mappings:        mappings,
		defaultUnmapped: defaultUnmapped,
		strict:          opts.Strict,
	}
}

// Classify classifies a bash command string. For compound commands, ALL
// segments must be classifiable for the command to be a permit candidate.
func (c *Classifier) Classify(command string) Classification {
	cl := Classification{Command: command}

	if isPipeToShell(command) {
		cl.Decision = "observe_flagged"
		cl.Reason = "pipe-to-shell pattern observed"
		return cl
	}
	if c.strict && isHighRiskExecutionChain(command) {
		cl.Decision = "observe_flagged"
		cl.Reason = "high-risk command chain observed (strict mode)"
		return cl
	}

	segments := SplitCommand(command)
	allMatched := true

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if isAssignmentOnlySegment(seg) {
			continue
		}
		result := c.classifySegment(seg)
		cl.Segments = append(cl.Segments, result)

		if result.Action == "__observe_always" {
			cl.Decision = "observe_flagged"
			cl.Reason = "flagged shell pattern observed: " + seg
			return cl
		}
		if !result.Matched {
			allMatched = false
		}
	}

	if !allMatched {
		cl.Decision = "observe_unmapped"
		cl.Reason = "unmapped command"
		return cl
	}

	if len(cl.Segments) == 0 {
		cl.Decision = "permit_candidate"
		return cl
	}

	cl.Decision = "permit_candidate"
	return cl
}

func (c *Classifier) classifySegment(segment string) Result {
	normalized := unwrapSegmentForMapping(segment)
	if normalized == "" {
		return Result{}
	}
	executableRaw := ExtractExecutable(normalized)
	executable := NormalizeExecutableName(executableRaw)
	result := Result{Executable: executable}

	for _, m := range c.mappings {
		if m.Pattern != "" {
			if matchPattern(m.Pattern, normalized) {
				result.Action = m.Action
				result.Matched = true
				result.Resource = extractResource(m.ResourceExtractor, normalized)
				return result
			}
			continue
		}

		if m.Executable != "" && executableMatches(m.Executable, executableRaw, executable) {
			if m.SubcommandPattern != "" {
				rest := strings.TrimSpace(strings.TrimPrefix(normalized, executable))
				if !matchPattern(m.SubcommandPattern, rest) {
					continue
				}
			}
			result.Action = m.Action
			result.Matched = true
			result.Resource = extractResource(m.ResourceExtractor, normalized)
			return result
		}
	}

	return result
}

// NormalizeExecutableName strips directory paths from an executable name.
func NormalizeExecutableName(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return token
	}
	if idx := strings.LastIndex(token, "/"); idx >= 0 && idx+1 < len(token) {
		return token[idx+1:]
	}
	return token
}

func executableMatches(mappingExecutable, rawExecutable, normalizedExecutable string) bool {
	if mappingExecutable == rawExecutable {
		return true
	}
	return mappingExecutable == normalizedExecutable
}
