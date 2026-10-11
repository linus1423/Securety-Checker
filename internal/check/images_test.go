package check

import (
	"reflect"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/discovery"
)

func TestReferencedImages(t *testing.T) {
	files, err := discovery.Walk("testdata/bad")
	if err != nil {
		t.Fatal(err)
	}
	got := ReferencedImages("testdata/bad", files)
	want := []string{"nginx:latest", "ubuntu:latest"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReferencedImages = %v, want %v", got, want)
	}
}

func TestReferencedImagesSkipsPlaceholders(t *testing.T) {
	files, err := discovery.Walk("testdata/good")
	if err != nil {
		t.Fatal(err)
	}
	got := ReferencedImages("testdata/good", files)
	// scratch and stage refs are excluded; alpine digest and the compose image remain.
	want := []string{
		"alpine:3.20@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"myorg/api:1.2.3",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReferencedImages = %v, want %v", got, want)
	}
}
