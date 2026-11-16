package middleware

import (
	"fmt"
	"strings"
)

// ProfileResolver expands named middleware profiles into concrete slices of MiddlewareItem.
type ProfileResolver struct {
	profiles map[string][]MiddlewareItem
}

// NewProfileResolver creates a ProfileResolver with cycle detection.
func NewProfileResolver(profiles map[string][]MiddlewareItem) (*ProfileResolver, error) {
	if profiles == nil {
		profiles = make(map[string][]MiddlewareItem)
	}

	pr := &ProfileResolver{
		profiles: profiles,
	}

	// Validate profiles for cycles or missing definitions
	for name := range profiles {
		visited := make(map[string]bool)
		if err := pr.validateCycles(name, visited); err != nil {
			return nil, err
		}
	}

	return pr, nil
}

func (pr *ProfileResolver) validateCycles(name string, visited map[string]bool) error {
	if visited[name] {
		return fmt.Errorf("circular reference detected in middleware profile %q", name)
	}
	visited[name] = true

	items, exists := pr.profiles[name]
	if !exists {
		return fmt.Errorf("unknown middleware profile %q", name)
	}

	for _, item := range items {
		// If an item name matches another profile, check for cycle
		if _, isSubProfile := pr.profiles[item.Name]; isSubProfile {
			subVisited := make(map[string]bool)
			for k, v := range visited {
				subVisited[k] = v
			}
			if err := pr.validateCycles(item.Name, subVisited); err != nil {
				return err
			}
		}
	}

	return nil
}

// Resolve expands a list of profile names into a flattened, ordered list of MiddlewareItems.
func (pr *ProfileResolver) Resolve(profileNames []string) ([]MiddlewareItem, error) {
	var result []MiddlewareItem
	for _, name := range profileNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		items, exists := pr.profiles[name]
		if !exists {
			return nil, fmt.Errorf("unknown middleware profile %q", name)
		}
		for _, item := range items {
			// If item refers to another profile, expand recursively
			if _, isSub := pr.profiles[item.Name]; isSub {
				subItems, err := pr.Resolve([]string{item.Name})
				if err != nil {
					return nil, err
				}
				result = append(result, subItems...)
			} else {
				result = append(result, item)
			}
		}
	}
	return result, nil
}
