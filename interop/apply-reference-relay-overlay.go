package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type hunk struct{ old, new []string }
type filePatch struct {
	path  string
	hunks []hunk
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func flush(patch *filePatch, current *hunk) {
	if patch != nil && current != nil && (len(current.old) != 0 || len(current.new) != 0) {
		patch.hunks = append(patch.hunks, *current)
	}
}

func parse(contents string) ([]filePatch, error) {
	var patches []filePatch
	var patch *filePatch
	var current *hunk
	for _, line := range strings.Split(strings.TrimSuffix(contents, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "--- a/"):
			flush(patch, current)
			current = nil
			patches = append(patches, filePatch{})
			patch = &patches[len(patches)-1]
		case strings.HasPrefix(line, "+++ b/"):
			if patch == nil {
				return nil, fmt.Errorf("patch has a destination without a source")
			}
			patch.path = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "@@ "):
			if patch == nil || patch.path == "" {
				return nil, fmt.Errorf("patch hunk has no destination")
			}
			flush(patch, current)
			current = &hunk{}
		case current != nil && strings.HasPrefix(line, "-"):
			current.old = append(current.old, strings.TrimPrefix(line, "-"))
		case current != nil && strings.HasPrefix(line, "+"):
			current.new = append(current.new, strings.TrimPrefix(line, "+"))
		case current != nil && strings.HasPrefix(line, " "):
			value := strings.TrimPrefix(line, " ")
			current.old = append(current.old, value)
			current.new = append(current.new, value)
		default:
			return nil, fmt.Errorf("patch has an unsupported line %q", line)
		}
	}
	flush(patch, current)
	if len(patches) == 0 {
		return nil, fmt.Errorf("patch contains no files")
	}
	for _, patch := range patches {
		if patch.path == "" || len(patch.hunks) == 0 {
			return nil, fmt.Errorf("patch has an incomplete file entry")
		}
	}
	return patches, nil
}

func find(lines, needle []string, start int) int {
	for index := start; index+len(needle) <= len(lines); index++ {
		matches := true
		for offset := range needle {
			if lines[index+offset] != needle[offset] {
				matches = false
				break
			}
		}
		if matches {
			return index
		}
	}
	return -1
}

func apply(root string, patch filePatch) error {
	path := filepath.Join(root, filepath.FromSlash(patch.path))
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	cursor := 0
	for _, hunk := range patch.hunks {
		index := find(lines, hunk.old, cursor)
		if index < 0 {
			return fmt.Errorf("patch hunk does not match %s", patch.path)
		}
		updated := make([]string, 0, len(lines)-len(hunk.old)+len(hunk.new))
		updated = append(updated, lines[:index]...)
		updated = append(updated, hunk.new...)
		updated = append(updated, lines[index+len(hunk.old):]...)
		lines = updated
		cursor = index + len(hunk.new)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: %s SOURCE_ROOT PATCH", os.Args[0])
	}
	contents, err := os.ReadFile(os.Args[2])
	if err != nil {
		fail("read patch: %v", err)
	}
	patches, err := parse(string(contents))
	if err != nil {
		fail("parse patch: %v", err)
	}
	for _, patch := range patches {
		if err := apply(os.Args[1], patch); err != nil {
			fail("apply patch: %v", err)
		}
	}
}
