// Package compose parses Docker Compose files into a model with line numbers.
//
// It uses yaml.v3 directly rather than compose-go so that it can still inspect
// files that are invalid or incomplete, which is exactly where security issues
// often hide. Override merging and variable interpolation are a planned upgrade.
package compose

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is a parsed Compose file.
type File struct {
	Path     string
	Services []Service
}

// Service is one service entry with helpers to read its keys with line numbers.
type Service struct {
	Name string
	Line int        // line of the service name
	node *yaml.Node // the service's mapping node
}

// ParseFile reads and parses a Compose file from disk.
func ParseFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f := &File{Path: path}
	if len(root.Content) == 0 {
		return f, nil
	}
	doc := root.Content[0]
	servicesNode := mapValue(doc, "services")
	if servicesNode == nil || servicesNode.Kind != yaml.MappingNode {
		return f, nil
	}
	for i := 0; i+1 < len(servicesNode.Content); i += 2 {
		nameNode := servicesNode.Content[i]
		svcNode := servicesNode.Content[i+1]
		f.Services = append(f.Services, Service{
			Name: nameNode.Value,
			Line: nameNode.Line,
			node: svcNode,
		})
	}
	return f, nil
}

// Scalar returns the string value of a scalar key on the service, with its line.
func (s Service) Scalar(key string) (value string, line int, ok bool) {
	n := mapValue(s.node, key)
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", 0, false
	}
	return n.Value, n.Line, true
}

// Bool reports a boolean key's value. ok is false if the key is absent.
func (s Service) Bool(key string) (value bool, line int, ok bool) {
	v, line, ok := s.Scalar(key)
	if !ok {
		return false, 0, false
	}
	return strings.EqualFold(v, "true"), line, true
}

// Seq returns the scalar items of a sequence key, with the line of the key.
func (s Service) Seq(key string) (items []string, line int, ok bool) {
	n := mapValue(s.node, key)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil, 0, false
	}
	for _, c := range n.Content {
		if c.Kind == yaml.ScalarNode {
			items = append(items, c.Value)
		}
	}
	return items, n.Line, true
}

// Has reports whether the service defines the given key.
func (s Service) Has(key string) bool {
	return mapValue(s.node, key) != nil
}

// LineOf returns the line of a key on the service, or the service line if absent.
func (s Service) LineOf(key string) int {
	for i := 0; i+1 < len(s.node.Content); i += 2 {
		if s.node.Content[i].Value == key {
			return s.node.Content[i].Line
		}
	}
	return s.Line
}

// EnvPairs returns environment variables as name/value pairs. It handles both
// the list form ("- KEY=val") and the map form ("KEY: val"). value is empty and
// hasValue false when only a name is given (value comes from the host).
type EnvPair struct {
	Name     string
	Value    string
	HasValue bool
	Line     int
}

// Env returns the service's environment variables.
func (s Service) Env() []EnvPair {
	n := mapValue(s.node, "environment")
	if n == nil {
		return nil
	}
	var out []EnvPair
	switch n.Kind {
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				continue
			}
			name, val, has := strings.Cut(c.Value, "=")
			out = append(out, EnvPair{Name: name, Value: val, HasValue: has, Line: c.Line})
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			out = append(out, EnvPair{Name: k.Value, Value: v.Value, HasValue: v.Value != "", Line: k.Line})
		}
	}
	return out
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
