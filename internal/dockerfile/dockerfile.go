// Package dockerfile parses Dockerfiles into a small model with line numbers.
package dockerfile

import (
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Instruction is a single Dockerfile instruction such as FROM or RUN.
type Instruction struct {
	Cmd      string   // upper-case command, e.g. "FROM", "RUN"
	Args     []string // arguments in order, e.g. ["alpine:latest", "AS", "build"]
	Flags    []string // flags such as "--chown=root"
	Original string   // the original source line(s)
	Line     int      // 1-based start line
}

// Stage is one build stage (everything from a FROM until the next FROM).
type Stage struct {
	Name  string // the "AS <name>" alias, empty if none
	From  string // the base image reference
	Index int    // 0-based stage position
	Instr []Instruction
}

// Dockerfile is a parsed Dockerfile.
type Dockerfile struct {
	Path   string
	Stages []Stage
}

// Instructions returns every instruction across all stages.
func (d *Dockerfile) Instructions() []Instruction {
	var out []Instruction
	for _, s := range d.Stages {
		out = append(out, s.Instr...)
	}
	return out
}

// FinalStage returns the last stage, which produces the shipped image.
func (d *Dockerfile) FinalStage() *Stage {
	if len(d.Stages) == 0 {
		return nil
	}
	return &d.Stages[len(d.Stages)-1]
}

// ParseFile reads and parses a Dockerfile from disk.
func ParseFile(path string) (*Dockerfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res, err := parser.Parse(f)
	if err != nil {
		return nil, err
	}

	df := &Dockerfile{Path: path}
	stageAliases := map[string]bool{}
	var cur *Stage
	for _, node := range res.AST.Children {
		cmd := strings.ToUpper(node.Value)
		instr := Instruction{
			Cmd:      cmd,
			Args:     argsOf(node),
			Flags:    append([]string(nil), node.Flags...),
			Original: node.Original,
			Line:     node.StartLine,
		}
		if cmd == "FROM" {
			df.Stages = append(df.Stages, Stage{Index: len(df.Stages)})
			cur = &df.Stages[len(df.Stages)-1]
			cur.From = firstArg(instr.Args)
			cur.Name, _ = stageAlias(instr.Args)
			if cur.Name != "" {
				stageAliases[strings.ToLower(cur.Name)] = true
			}
		}
		if cur == nil {
			// Instructions before any FROM (e.g. a top-level ARG). Keep them in a
			// synthetic stage so nothing is dropped.
			df.Stages = append(df.Stages, Stage{Index: 0})
			cur = &df.Stages[len(df.Stages)-1]
		}
		cur.Instr = append(cur.Instr, instr)
	}
	return df, nil
}

// StageNames returns the set of stage aliases, lower-cased.
func (d *Dockerfile) StageNames() map[string]bool {
	names := map[string]bool{}
	for _, s := range d.Stages {
		if s.Name != "" {
			names[strings.ToLower(s.Name)] = true
		}
	}
	return names
}

func argsOf(node *parser.Node) []string {
	var args []string
	for n := node.Next; n != nil; n = n.Next {
		args = append(args, n.Value)
	}
	return args
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// stageAlias returns the "AS <name>" alias from a FROM instruction's args.
func stageAlias(args []string) (string, bool) {
	for i := 0; i+1 < len(args); i++ {
		if strings.EqualFold(args[i], "AS") {
			return args[i+1], true
		}
	}
	return "", false
}
