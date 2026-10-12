// Package discovery finds the files in a project that the checks look at.
package discovery

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Kind classifies a discovered file.
type Kind string

const (
	KindDockerfile Kind = "dockerfile"
	KindCompose    Kind = "compose"
	KindEnv        Kind = "env"
)

// File is a file relevant to the scan. Path is relative to the scanned root, with forward slashes.
type File struct {
	Path string `json:"path"`
	Kind Kind   `json:"kind"`
}

// skipDirs are directories that never contain project configuration worth scanning.
var skipDirs = map[string]bool{
	".git":         true,
	".hg":          true,
	".svn":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"__pycache__":  true,
}

// Classify returns the kind of a file based on its name, or false if it is not relevant.
func Classify(name string) (Kind, bool) {
	lower := strings.ToLower(name)
	switch {
	case lower == "dockerfile", lower == "containerfile",
		strings.HasSuffix(lower, ".dockerfile"), strings.HasSuffix(lower, ".containerfile"),
		isDockerfileVariant(lower):
		return KindDockerfile, true
	case isCompose(lower):
		return KindCompose, true
	case lower == ".env", strings.HasPrefix(lower, ".env."), strings.HasSuffix(lower, ".env"):
		return KindEnv, true
	}
	return "", false
}

// nonDockerExts are extensions that mark a "Dockerfile.<x>" name as something
// other than a Dockerfile variant (e.g. dockerfile.go, a source file).
var nonDockerExts = map[string]bool{
	".go": true, ".md": true, ".txt": true, ".rst": true, ".json": true,
	".yml": true, ".yaml": true, ".toml": true, ".ini": true, ".cfg": true,
	".sh": true, ".py": true, ".js": true, ".ts": true, ".rb": true,
	".lock": true, ".sum": true, ".mod": true, ".bak": true, ".orig": true,
	".swp": true, ".tmpl": true, ".html": true, ".xml": true,
}

// isDockerfileVariant reports whether a "dockerfile.<suffix>" or
// "containerfile.<suffix>" name is a Dockerfile variant (e.g. Dockerfile.prod)
// rather than a source file that merely starts with the word (e.g. dockerfile.go).
func isDockerfileVariant(lower string) bool {
	if !strings.HasPrefix(lower, "dockerfile.") && !strings.HasPrefix(lower, "containerfile.") {
		return false
	}
	return !nonDockerExts[filepath.Ext(lower)]
}

func isCompose(lower string) bool {
	ext := filepath.Ext(lower)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	base := strings.TrimSuffix(lower, ext)
	for _, prefix := range []string{"docker-compose", "compose"} {
		if base == prefix || strings.HasPrefix(base, prefix+".") || strings.HasPrefix(base, prefix+"-") {
			return true
		}
	}
	return false
}

// Walk returns all relevant files below root, sorted by path.
func Walk(root string) ([]File, error) {
	var files []File
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		kind, ok := Classify(d.Name())
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, File{Path: filepath.ToSlash(rel), Kind: kind})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}
