package shell

import "strings"

// Flags holds parsed command-line options.
//
// Short flags may be grouped (-la), long flags may use --name=value, and
// "--" ends option parsing. Everything else is positional.
type Flags struct {
	set  map[string]bool   // boolean flags, short ("l") and long ("all")
	vals map[string]string // flags that took a value
	Args []string          // positional arguments
}

// ParseFlags parses args. valued lists the flags (short letters or long
// names) that take a value, as in -n 5, -n5, --lines 5 or --lines=5.
func ParseFlags(args []string, valued ...string) Flags {
	f := Flags{set: map[string]bool{}, vals: map[string]string{}}
	takes := map[string]bool{}
	for _, v := range valued {
		takes[v] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			f.Args = append(f.Args, args[i+1:]...)
			return f
		case strings.HasPrefix(a, "--") && len(a) > 2:
			name, val, hasVal := strings.Cut(a[2:], "=")
			if takes[name] {
				if !hasVal && i+1 < len(args) {
					i++
					val = args[i]
				}
				f.vals[name] = val
			} else {
				f.set[name] = true
				if hasVal {
					f.vals[name] = val
				}
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				name := string(a[j])
				if takes[name] {
					val := a[j+1:]
					if val == "" && i+1 < len(args) {
						i++
						val = args[i]
					}
					f.vals[name] = val
					break
				}
				f.set[name] = true
			}
		default:
			f.Args = append(f.Args, a)
		}
	}
	return f
}

// Has reports whether any of the named flags was given.
func (f Flags) Has(names ...string) bool {
	for _, n := range names {
		if f.set[n] {
			return true
		}
	}
	return false
}

// Value returns the value of the first named flag that was given.
func (f Flags) Value(names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := f.vals[n]; ok {
			return v, true
		}
	}
	return "", false
}
