package agent

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ExtractPaths returns all unique URL paths from a text blob whose host
// matches the supplied host. Lowercase, leading slash, deduped, sorted.
func ExtractPaths(text, host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	seen := make(map[string]struct{})
	var result []string

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as a full URL.
		u, err := url.Parse(line)
		if err != nil || u.Host == "" {
			// Might be a bare path — skip unless it starts with /.
			if strings.HasPrefix(line, "/") {
				p := normalizePath(line)
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					result = append(result, p)
				}
			}
			continue
		}

		if strings.ToLower(u.Host) != host {
			continue
		}

		p := normalizePath(u.Path)
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}

	sort.Strings(result)
	return result
}

// normalizePath lowercases and ensures a leading slash.
func normalizePath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Clean the path but keep trailing slash if present.
	cleaned := filepath.Clean(p)
	// filepath.Clean removes trailing slashes; re-add if the original had one
	// (except for root /).
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// WriteWordlist writes one path per line to a temp file and returns its
// path. Caller is responsible for cleanup (defer os.Remove).
func WriteWordlist(paths []string) (string, error) {
	f, err := os.CreateTemp("", "bb-wordlist-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, p := range paths {
		if _, err := f.WriteString(p + "\n"); err != nil {
			os.Remove(f.Name())
			return "", err
		}
	}
	return f.Name(), nil
}

// buildWordlistTool is the tool handler for "build_wordlist".
// Args format: <output_path>\n<path1>\n<path2>...
func (te *ToolExecutor) buildWordlistTool(args string) string {
	lines := strings.Split(args, "\n")
	if len(lines) < 2 {
		return "ERROR: usage: build_wordlist <output_path>\\n<path1>\\n<path2>..."
	}

	outPath := strings.TrimSpace(lines[0])
	if outPath == "" {
		return "ERROR: output_path is required"
	}

	var paths []string
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line != "" {
			paths = append(paths, line)
		}
	}

	if len(paths) == 0 {
		return "ERROR: at least one path entry is required"
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "ERROR: cannot create file: " + err.Error()
	}
	defer f.Close()

	for _, p := range paths {
		if _, err := f.WriteString(p + "\n"); err != nil {
			return "ERROR: write failed: " + err.Error()
		}
	}

	return fmt.Sprintf("OK: wrote %d entries to %s", len(paths), outPath)
}

