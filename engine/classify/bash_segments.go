package classify

import "strings"

// unwrapSegmentForMapping removes common command wrappers used by shells/CLIs
// so mappings apply to the underlying executable instead of the wrapper.
func unwrapSegmentForMapping(segment string) string {
	fields := strings.Fields(segment)
	if len(fields) == 0 {
		return ""
	}
	i := 0
	for i < len(fields) && isAssignmentToken(fields[i]) {
		i++
	}
	if i >= len(fields) {
		return ""
	}

	for {
		handled := true
		switch fields[i] {
		case "env":
			i++
			for i < len(fields) {
				token := fields[i]
				if isAssignmentToken(token) {
					i++
					continue
				}
				if strings.HasPrefix(token, "-") {
					i++
					if (token == "-u" || token == "--unset" || token == "--chdir") && i < len(fields) {
						i++
					}
					continue
				}
				break
			}
		case "timeout":
			i++
			for i < len(fields) {
				token := fields[i]
				if strings.HasPrefix(token, "-") {
					i++
					if token == "-k" && i < len(fields) {
						i++
					}
					continue
				}
				i++
				break
			}
		case "command":
			i++
			for i < len(fields) && strings.HasPrefix(fields[i], "-") {
				i++
			}
		case "stdbuf":
			i++
			for i < len(fields) && strings.HasPrefix(fields[i], "-") {
				i++
			}
		case "nohup":
			i++
		default:
			handled = false
		}

		for i < len(fields) && isAssignmentToken(fields[i]) {
			i++
		}
		if i >= len(fields) {
			return ""
		}
		if !handled {
			break
		}
	}

	if i >= len(fields) {
		return ""
	}
	return strings.Join(fields[i:], " ")
}

// SplitCommand splits a bash command on compound operators.
// Splits on: |, &&, ||, ;, &
func SplitCommand(cmd string) []string {
	var segments []string
	var current strings.Builder
	runes := []rune(cmd)
	i := 0

	for i < len(runes) {
		ch := runes[i]

		if ch == '\'' || ch == '"' {
			quote := ch
			current.WriteRune(ch)
			i++
			for i < len(runes) && runes[i] != quote {
				if runes[i] == '\\' && quote == '"' {
					current.WriteRune(runes[i])
					i++
					if i < len(runes) {
						current.WriteRune(runes[i])
						i++
					}
					continue
				}
				current.WriteRune(runes[i])
				i++
			}
			if i < len(runes) {
				current.WriteRune(runes[i])
				i++
			}
			continue
		}

		switch {
		case ch == '|' && i+1 < len(runes) && runes[i+1] == '|':
			segments = append(segments, current.String())
			current.Reset()
			i += 2
		case ch == '|':
			segments = append(segments, current.String())
			current.Reset()
			i++
		case ch == '&' && i+1 < len(runes) && runes[i+1] == '&':
			segments = append(segments, current.String())
			current.Reset()
			i += 2
		case ch == ';':
			segments = append(segments, current.String())
			current.Reset()
			i++
		case ch == '&':
			segments = append(segments, current.String())
			current.Reset()
			i++
		default:
			current.WriteRune(ch)
			i++
		}
	}

	if s := current.String(); strings.TrimSpace(s) != "" {
		segments = append(segments, s)
	}
	return segments
}

// ExtractExecutable returns the first token of a command segment,
// skipping env var assignments (FOO=bar cmd ...).
func ExtractExecutable(segment string) string {
	fields := strings.Fields(segment)
	for _, f := range fields {
		if isAssignmentToken(f) {
			continue
		}
		return f
	}
	return ""
}

func isAssignmentOnlySegment(segment string) bool {
	fields := strings.Fields(segment)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !isAssignmentToken(f) {
			return false
		}
	}
	return true
}

func isAssignmentToken(token string) bool {
	if token == "" || strings.HasPrefix(token, "-") {
		return false
	}
	eq := strings.IndexByte(token, '=')
	if eq <= 0 {
		return false
	}
	return true
}
