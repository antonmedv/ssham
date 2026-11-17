package shell

import (
	"strconv"
	"strings"
)

// arith evaluates a $(( )) expression with C precedence: parentheses,
// unary - + !, * / %, + -, comparisons, == !=, && and ||. Names are shell
// variables. Errors (bad syntax, division by zero) evaluate to 0.
func arith(expr string, lookup func(string) string) int64 {
	p := &arithParser{toks: arithTokens(expr), lookup: lookup}
	v := p.binary(0)
	if p.err || p.pos != len(p.toks) {
		return 0
	}
	return v
}

// Binary operators by precedence, lowest first.
var arithLevels = [][]string{
	{"||"}, {"&&"}, {"==", "!="}, {"<", "<=", ">", ">="}, {"+", "-"}, {"*", "/", "%"},
}

type arithParser struct {
	toks   []string
	pos    int
	lookup func(string) string
	err    bool
}

func (p *arithParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *arithParser) binary(level int) int64 {
	if level == len(arithLevels) {
		return p.unary()
	}
	left := p.binary(level + 1)
	for {
		op := p.peek()
		found := false
		for _, o := range arithLevels[level] {
			found = found || op == o
		}
		if !found {
			return left
		}
		p.pos++
		right := p.binary(level + 1)
		left = p.apply(op, left, right)
	}
}

func (p *arithParser) apply(op string, a, b int64) int64 {
	bool2int := func(v bool) int64 {
		if v {
			return 1
		}
		return 0
	}
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/", "%":
		if b == 0 {
			p.err = true
			return 0
		}
		if op == "/" {
			return a / b
		}
		return a % b
	case "<":
		return bool2int(a < b)
	case "<=":
		return bool2int(a <= b)
	case ">":
		return bool2int(a > b)
	case ">=":
		return bool2int(a >= b)
	case "==":
		return bool2int(a == b)
	case "!=":
		return bool2int(a != b)
	case "&&":
		return bool2int(a != 0 && b != 0)
	case "||":
		return bool2int(a != 0 || b != 0)
	}
	return 0
}

func (p *arithParser) unary() int64 {
	switch tok := p.peek(); tok {
	case "-", "+", "!":
		p.pos++
		v := p.unary()
		switch tok {
		case "-":
			return -v
		case "!":
			if v == 0 {
				return 1
			}
			return 0
		}
		return v
	case "(":
		p.pos++
		v := p.binary(0)
		if p.peek() != ")" {
			p.err = true
		}
		p.pos++
		return v
	case "":
		p.err = true
		return 0
	default:
		p.pos++
		if v, err := strconv.ParseInt(tok, 0, 64); err == nil {
			return v
		}
		if isName(tok) {
			v, _ := strconv.ParseInt(strings.TrimSpace(p.lookup(tok)), 0, 64)
			return v
		}
		p.err = true
		return 0
	}
}

func arithTokens(s string) []string {
	var toks []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case isWordByte(c):
			j := i
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		case i+1 < len(s) && strings.Contains("&& || == != <= >=", s[i:i+2]):
			toks = append(toks, s[i:i+2])
			i += 2
		default:
			toks = append(toks, string(c))
			i++
		}
	}
	return toks
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
