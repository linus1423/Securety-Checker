package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		kind Kind
		ok   bool
	}{
		{"Dockerfile", KindDockerfile, true},
		{"dockerfile", KindDockerfile, true},
		{"Dockerfile.prod", KindDockerfile, true},
		{"Dockerfile.alpine", KindDockerfile, true},
		{"dockerfile.go", "", false},
		{"Dockerfile.md", "", false},
		{"api.dockerfile", KindDockerfile, true},
		{"Containerfile", KindDockerfile, true},
		{"docker-compose.yml", KindCompose, true},
		{"docker-compose.override.yaml", KindCompose, true},
		{"docker-compose-dev.yml", KindCompose, true},
		{"compose.yaml", KindCompose, true},
		{"compose.prod.yml", KindCompose, true},
		{".env", KindEnv, true},
		{".env.local", KindEnv, true},
		{"prod.env", KindEnv, true},
		{"composer.json", "", false},
		{"compose.json", "", false},
		{"values.yaml", "", false},
		{"README.md", "", false},
	}
	for _, c := range cases {
		kind, ok := Classify(c.name)
		if kind != c.kind || ok != c.ok {
			t.Errorf("Classify(%q) = %q, %v; want %q, %v", c.name, kind, ok, c.kind, c.ok)
		}
	}
}

func TestWalk(t *testing.T) {
	files, err := Walk("testdata/project")
	if err != nil {
		t.Fatal(err)
	}
	want := []File{
		{".env", KindEnv},
		{"Dockerfile", KindDockerfile},
		{"api/Dockerfile.prod", KindDockerfile},
		{"deploy/compose.override.yaml", KindCompose},
		{"deploy/prod.env", KindEnv},
		{"docker-compose.yml", KindCompose},
	}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("Walk() = %v\nwant %v", files, want)
	}
}

func TestWalkSkipsVCSDirs(t *testing.T) {
	// A .git directory cannot be committed as a fixture, so build it here.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".git/Dockerfile", "Dockerfile"} {
		if err := os.WriteFile(filepath.Join(root, p), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []File{{"Dockerfile", KindDockerfile}}; !reflect.DeepEqual(files, want) {
		t.Errorf("Walk() = %v, want %v", files, want)
	}
}
