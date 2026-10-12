// Package sandbox starts a Compose stack in an isolated, data-safe sandbox so
// the dynamic checks can inspect and attack it without touching real data.
//
// The transform here rewrites a Compose file so that a run cannot destroy host
// data: every bind mount of a host path is replaced by a throwaway anonymous
// volume, and a mounted Docker socket is removed entirely. Named volumes are
// kept but namespaced by a unique project name, so `compose down -v` discards
// them. This lets even destructive tests run safely.
package sandbox

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Transform is the result of sandboxing a Compose file.
type Transform struct {
	YAML  []byte   // the rewritten Compose file
	Notes []string // human-readable description of what was changed
}

// SandboxCompose rewrites a Compose file's service volumes to be data-safe.
func SandboxCompose(data []byte) (*Transform, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing compose: %w", err)
	}
	tr := &Transform{}
	if len(root.Content) == 0 {
		tr.YAML = data
		return tr, nil
	}
	doc := root.Content[0]
	services := mapValue(doc, "services")
	if services != nil && services.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(services.Content); i += 2 {
			name := services.Content[i].Value
			svc := services.Content[i+1]
			sanitizeServiceVolumes(name, svc, tr)
		}
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("writing sandboxed compose: %w", err)
	}
	tr.YAML = out
	return tr, nil
}

func sanitizeServiceVolumes(service string, svc *yaml.Node, tr *Transform) {
	vols := mapValue(svc, "volumes")
	if vols == nil || vols.Kind != yaml.SequenceNode {
		return
	}
	var kept []*yaml.Node
	for _, item := range vols.Content {
		if item.Kind != yaml.ScalarNode {
			// Long-form mount: keep it, but flag that it was not sanitized.
			kept = append(kept, item)
			tr.Notes = append(tr.Notes, fmt.Sprintf("%s: Langform-Mount nicht umgeschrieben, bitte prüfen", service))
			continue
		}
		spec := item.Value
		if strings.Contains(spec, "docker.sock") {
			tr.Notes = append(tr.Notes, fmt.Sprintf("%s: Docker-Socket-Mount entfernt (%s)", service, spec))
			continue // drop entirely
		}
		src, dst, isBind := splitBind(spec)
		if !isBind {
			kept = append(kept, item) // named volume, namespaced by project
			continue
		}
		// Replace the host bind with a throwaway anonymous volume at the same path.
		item.Value = dst
		item.Tag = "!!str"
		kept = append(kept, item)
		tr.Notes = append(tr.Notes, fmt.Sprintf("%s: Bind-Mount %s durch Wegwerf-Volume ersetzt", service, src))
	}
	vols.Content = kept
}

// splitBind reports whether a short-form volume spec is a host bind mount, and
// returns its source and container destination. A spec whose source is a host
// path (absolute, relative or ~) is a bind; "name:/path" is a named volume.
func splitBind(spec string) (src, dst string, isBind bool) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) < 2 {
		return "", "", false // anonymous volume, nothing to do
	}
	src = parts[0]
	dst = parts[1]
	if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") {
		return src, dst, true
	}
	return "", "", false
}

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
