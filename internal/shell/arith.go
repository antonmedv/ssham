package shell

import (
	"errors"
	"strconv"
	"strings"
)

var (
	errArithSyntax = errors.New("arithmetic syntax error")
	errDivideZero  = errors.New("divide by zero")
)

// arith evaluates a $(( )) expression the way ash's math does: C operators
// and precedence, including assignment (= += <<= ...), ++ and --, ?: and
// **. Names are shell variables; set stores assignments. The errors are
// ash's.
func arith(expr string, lookup func(string) string, set func(name, val string)) (int64, error) {
	p := &arithParser{toks: arithTokens(expr), lookup: lookup, set: set}
	if len(p.toks) == 0 {
		return 0, nil // $(( )) is 0
	}
	v := p.expr(0)
	switch {
	case p.err != nil:
		return 0, p.err
	case p.pos != len(p.toks):
		return 0, errArithSyntax
	}
	return v.n, nil
}

// Binary operators and their precedence; higher binds tighter.
var arithPrec = map[string]int{
	"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
	"==": 6, "!=": 6, "<": 7, "<=": 7, ">": 7, ">=": 7,
	"<<": 8, ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, "**": 11,
}

var arithAssign = map[string]bool{
	"=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true,
	"<<=": true, ">>=": true, "&=": true, "^=": true, "|=": true,
}

type arithParser struct {
	toks   []string
	pos    int
	lookup func(string) string
	set    func(name, val string)
	err    error
	skip   int // > 0 while evaluating a branch that is not taken
}

// value is a result, and the variable it came from, for assignments.
type value struct {
	n    int64
	name string
}

func (p *arithParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *arithParser) fail(err error) value {
	if p.err == nil {
		p.err = err
	}
	return value{}
}

func (p *arithParser) store(name string, n int64) {
	if p.skip == 0 && p.set != nil {
		p.set(name, strconv.FormatInt(n, 10))
	}
}

// expr parses a full expression: assignment and ?: bind loosest.
func (p *arithParser) expr(minPrec int) value {
	left := p.unary()
	for p.err == nil {
		op := p.peek()
		switch {
		case arithAssign[op] && minPrec == 0:
			if left.name == "" {
				return p.fail(errArithSyntax)
			}
			p.pos++
			right := p.expr(0)
			n := right.n
			if op != "=" {
				n = p.apply(strings.TrimSuffix(op, "="), left.n, right.n)
			}
			p.store(left.name, n)
			return value{n: n}
		case op == "?" && minPrec == 0:
			p.pos++
			cond := left.n != 0
			if !cond {
				p.skip++
			}
			a := p.expr(0)
			if !cond {
				p.skip--
			}
			if p.peek() != ":" {
				return p.fail(errArithSyntax)
			}
			p.pos++
			if cond {
				p.skip++
			}
			b := p.expr(0)
			if cond {
				p.skip--
				return value{n: a.n}
			}
			return value{n: b.n}
		}
		prec, ok := arithPrec[op]
		if !ok || prec <= minPrec-1 || prec < minPrec {
			return left
		}
		p.pos++
		next := prec + 1
		if op == "**" {
			next = prec // right associative
		}
		// && and || do not evaluate the right side when they need not.
		short := (op == "&&" && left.n == 0) || (op == "||" && left.n != 0)
		if short {
			p.skip++
		}
		right := p.expr(next)
		if short {
			p.skip--
		}
		left = value{n: p.apply(op, left.n, right.n)}
	}
	return left
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
			if p.skip == 0 {
				p.fail(errDivideZero)
			}
			return 0
		}
		if op == "/" {
			return a / b
		}
		return a % b
	case "**":
		if b < 0 {
			if p.skip == 0 {
				p.fail(errors.New("exponent less than 0"))
			}
			return 0
		}
		r := int64(1)
		for ; b > 0; b-- {
			r *= a
		}
		return r
	case "<<":
		return a << (uint64(b) & 63)
	case ">>":
		return a >> (uint64(b) & 63)
	case "&":
		return a & b
	case "|":
		return a | b
	case "^":
		return a ^ b
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

func (p *arithParser) unary() value {
	switch tok := p.peek(); tok {
	case "-", "+", "!", "~":
		p.pos++
		v := p.unary()
		switch tok {
		case "-":
			return value{n: -v.n}
		case "!":
			if v.n == 0 {
				return value{n: 1}
			}
			return value{}
		case "~":
			return value{n: ^v.n}
		}
		return value{n: v.n}
	case "++", "--":
		p.pos++
		v := p.unary()
		if v.name == "" {
			return p.fail(errArithSyntax)
		}
		n := v.n + 1
		if tok == "--" {
			n = v.n - 1
		}
		p.store(v.name, n)
		return value{n: n}
	case "(":
		p.pos++
		v := p.expr(0)
		if p.peek() != ")" {
			return p.fail(errArithSyntax)
		}
		p.pos++
		return value{n: v.n}
	case "":
		return p.fail(errArithSyntax)
	}
	tok := p.peek()
	p.pos++
	if tok[0] >= '0' && tok[0] <= '9' {
		n, err := parseArithNumber(tok)
		if err != nil {
			return p.fail(errArithSyntax)
		}
		return value{n: n}
	}
	if !isName(tok) {
		return p.fail(errArithSyntax)
	}
	n, ok := p.varValue(tok, 0)
	if !ok {
		return p.fail(errArithSyntax)
	}
	// Postfix ++ and -- return the old value.
	if op := p.peek(); op == "++" || op == "--" {
		p.pos++
		d := int64(1)
		if op == "--" {
			d = -1
		}
		p.store(tok, n+d)
		return value{n: n}
	}
	return value{n: n, name: tok}
}

// varValue is the number in a variable. A value that is itself a name is
// looked up in turn, as ash does.
func (p *arithParser) varValue(name string, depth int) (int64, bool) {
	s := strings.TrimSpace(p.lookup(name))
	switch {
	case s == "":
		return 0, true
	case isName(s) && depth < 10:
		return p.varValue(s, depth+1)
	}
	n, err := parseArithNumber(s)
	return n, err == nil
}

// parseArithNumber reads 42, 0x2a, 052 (octal) and BASE#DIGITS.
func parseArithNumber(s string) (int64, error) {
	if b, digits, ok := strings.Cut(s, "#"); ok {
		base, err := strconv.Atoi(b)
		if err != nil || base < 2 || base > 64 {
			return 0, errArithSyntax
		}
		return strconv.ParseInt(digits, base, 64)
	}
	if strings.HasPrefix(s, "-") {
		n, err := parseArithNumber(s[1:])
		return -n, err
	}
	return strconv.ParseInt(s, 0, 64)
}

func arithTokens(s string) []string {
	ops := []string{
		"<<=", ">>=", "**", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "++", "--",
		"+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=",
	}
	var toks []string
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' {
			i++
			continue
		}
		if isWordByte(c) || c == '#' {
			j := i
			for j < len(s) && (isWordByte(s[j]) || s[j] == '#') {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
			continue
		}
		matched := false
		for _, op := range ops {
			if strings.HasPrefix(s[i:], op) {
				toks = append(toks, op)
				i += len(op)
				matched = true
				break
			}
		}
		if !matched {
			toks = append(toks, string(c))
			i++
		}
	}
	return toks
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
