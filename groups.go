package netacl

import (
	"fmt"
	"slices"
	"strings"
)

type groupSet struct {
	flat map[string]*spec
}

func validateGroupName(name string) error {
	if name == "" {
		return fmt.Errorf("empty group name")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("invalid group name %q: use letters, digits, '_', '-' and '.'", name)
		}
	}
	return nil
}

func resolveGroups(defs map[string]Selector) (*groupSet, error) {
	type parsed struct {
		sp   *spec
		refs []string
	}
	parsedDefs := make(map[string]parsed, len(defs))
	// Sorted, so the reported error is the same on every run.
	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := validateGroupName(name); err != nil {
			return nil, err
		}
		sel := defs[name]
		if sel.isEmpty() {
			return nil, fmt.Errorf("group %q: no members", name)
		}
		sp, refs, err := parseSpec(sel)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", name, err)
		}
		parsedDefs[name] = parsed{sp: sp, refs: refs}
	}

	gs := &groupSet{flat: make(map[string]*spec, len(defs))}
	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]int, len(defs))
	var path []string

	var visit func(name string) error
	visit = func(name string) error {
		switch state[name] {
		case done:
			return nil
		case visiting:
			start := slices.Index(path, name)
			cycle := append(slices.Clone(path[start:]), name)
			return fmt.Errorf("group cycle: %s", strings.Join(cycle, " -> "))
		}
		state[name] = visiting
		path = append(path, name)
		p := parsedDefs[name]
		flat := new(spec)
		flat.merge(p.sp)
		for _, ref := range p.refs {
			if _, ok := parsedDefs[ref]; !ok {
				return fmt.Errorf("group %q: unknown group @%s", name, ref)
			}
			if err := visit(ref); err != nil {
				return err
			}
			flat.merge(gs.flat[ref])
		}
		path = path[:len(path)-1]
		state[name] = done
		gs.flat[name] = flat
		return nil
	}
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return gs, nil
}

func (gs *groupSet) lookup(name string) (*spec, error) {
	if gs != nil {
		if sp, ok := gs.flat[name]; ok {
			return sp, nil
		}
	}
	return nil, fmt.Errorf("unknown group @%s (groups are defined in the global netacl options block)", name)
}
