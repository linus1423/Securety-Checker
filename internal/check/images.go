package check

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/compose"
	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/dockerfile"
)

// ReferencedImages returns the distinct, concrete container images referenced by
// the project's Compose files and Dockerfile FROM lines. Stage aliases, scratch
// and build-arg placeholders are skipped, since they cannot be pulled and scanned.
func ReferencedImages(root string, files []discovery.File) []string {
	set := map[string]bool{}
	for _, f := range files {
		abs := filepath.Join(root, filepath.FromSlash(f.Path))
		switch f.Kind {
		case discovery.KindCompose:
			cf, err := compose.ParseFile(abs)
			if err != nil {
				continue
			}
			for _, s := range cf.Services {
				if img, _, ok := s.Scalar("image"); ok {
					addImage(set, img)
				}
			}
		case discovery.KindDockerfile:
			df, err := dockerfile.ParseFile(abs)
			if err != nil {
				continue
			}
			names := df.StageNames()
			for _, st := range df.Stages {
				if st.From == "" || isStageRef(st.From, names) {
					continue
				}
				addImage(set, st.From)
			}
		}
	}
	out := make([]string, 0, len(set))
	for img := range set {
		out = append(out, img)
	}
	sort.Strings(out)
	return out
}

func addImage(set map[string]bool, img string) {
	img = strings.TrimSpace(img)
	if img == "" || img == "scratch" || strings.HasPrefix(img, "$") || strings.Contains(img, "${") {
		return
	}
	set[img] = true
}
