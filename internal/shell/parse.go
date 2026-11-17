package shell

import (
	"fmt"
	"strings"
)

// The parser understands a practical subset of bash: lists joined by ; & &&
// and ||, pipelines, ( ) groups, redirections, and quoted words. Words are
// kept raw and expanded only when the command runs, so that variables set by
// earlier commands on the same line are visible to later ones.

type tokKind int

const (
	tWord tokKind = iota
	tPipe
	tAndIf
	tOrIf
	tSemi
	tAmp
	tRedir
	tLParen
	tRParen
)

type token struct {
	kind tokKind
	val  string // raw word, or redirection operator
	fd   int    // redirection source fd
}

type redir struct {
	fd     int
	op     string // ">", ">>", "<", ">&", "&>"
	target string // raw word
}

type command struct {
	assigns []string
	words   []string
	redirs  []redir
	group   *list
}

type pipeline struct {
	cmds []*command
}

type list struct {
	items []*pipeline
	ops   []string // ops[i] joins items[i] and items[i+1]; the last is the terminator
}

// SyntaxError is returned for input the parser cannot handle.
type SyntaxError struct{ Token string }

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("syntax error near unexpected token `%s'", e.Token)
}

func isMeta(c byte) bool {
	switch c {
	case ' ', '\t', '\n', ';', '&', '|', '<', '>', '(', ')':
		return true
	}
	return false
}

// lex splits src into tokens.
func lex(src string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '\n' || c == ';':
			toks = append(toks, token{kind: tSemi, val: string(c)})
			i++
		case c == '|':
			if strings.HasPrefix(src[i:], "||") {
				toks = append(toks, token{kind: tOrIf, val: "||"})
				i += 2
			} else {
				toks = append(toks, token{kind: tPipe, val: "|"})
				i++
			}
		case c == '&':
			switch {
			case strings.HasPrefix(src[i:], "&&"):
				toks = append(toks, token{kind: tAndIf, val: "&&"})
				i += 2
			case strings.HasPrefix(src[i:], "&>>"):
				toks = append(toks, token{kind: tRedir, val: "&>>", fd: 1})
				i += 3
			case strings.HasPrefix(src[i:], "&>"):
				toks = append(toks, token{kind: tRedir, val: "&>", fd: 1})
				i += 2
			default:
				toks = append(toks, token{kind: tAmp, val: "&"})
				i++
			}
		case c == '(':
			toks = append(toks, token{kind: tLParen, val: "("})
			i++
		case c == ')':
			toks = append(toks, token{kind: tRParen, val: ")"})
			i++
		case c == '<' || c == '>':
			op, n := lexRedirOp(src[i:])
			fd := 1
			if c == '<' {
				fd = 0
			}
			toks = append(toks, token{kind: tRedir, val: op, fd: fd})
			i += n
		default:
			// An fd number directly before a redirection, e.g. 2> or 2>&1.
			j := i
			for j < len(src) && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			if j > i && j-i <= 2 && j < len(src) && (src[j] == '>' || src[j] == '<') {
				fd := 0
				for _, d := range src[i:j] {
					fd = fd*10 + int(d-'0')
				}
				op, n := lexRedirOp(src[j:])
				toks = append(toks, token{kind: tRedir, val: op, fd: fd})
				i = j + n
				continue
			}
			w, n, err := lexWord(src[i:])
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{kind: tWord, val: w})
			i += n
		}
	}
	return toks, nil
}

func lexRedirOp(s string) (string, int) {
	for _, op := range []string{">>", ">&", ">|", "<<<", "<&", "<>", ">", "<"} {
		if strings.HasPrefix(s, op) {
			if op == ">|" {
				return ">", 2
			}
			return op, len(op)
		}
	}
	return s[:1], 1
}

// lexWord returns the raw word at the start of s and its length.
func lexWord(s string) (string, int, error) {
	i := 0
	for i < len(s) && !isMeta(s[i]) {
		n, err := skipQuoted(s[i:])
		if err != nil {
			return "", 0, err
		}
		i += n
	}
	return s[:i], i, nil
}

// skipQuoted returns the length of the quoted construct or single
// character at the start of s.
func skipQuoted(s string) (int, error) {
	switch s[0] {
	case '\\':
		if len(s) > 1 {
			return 2, nil
		}
		return 1, nil
	case '\'':
		end := strings.IndexByte(s[1:], '\'')
		if end < 0 {
			return 0, &SyntaxError{Token: "newline"}
		}
		return end + 2, nil
	case '"':
		i := 1
		for i < len(s) {
			switch s[i] {
			case '\\':
				i += 2
				continue
			case '"':
				return i + 1, nil
			case '$', '`':
				if s[i] == '$' && (i+1 >= len(s) || s[i+1] != '(') {
					i++
					continue
				}
				n, err := skipQuoted(s[i:])
				if err != nil {
					return 0, err
				}
				i += n
				continue
			}
			i++
		}
		return 0, &SyntaxError{Token: "newline"}
	case '`':
		i := 1
		for i < len(s) {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == '`' {
				return i + 1, nil
			}
			i++
		}
		return 0, &SyntaxError{Token: "newline"}
	case '$':
		if len(s) > 1 && s[1] == '(' {
			depth := 0
			i := 1
			for i < len(s) {
				switch s[i] {
				case '(':
					depth++
				case ')':
					depth--
					if depth == 0 {
						return i + 1, nil
					}
				case '\'', '"', '`', '\\':
					n, err := skipQuoted(s[i:])
					if err != nil {
						return 0, err
					}
					i += n
					continue
				}
				i++
			}
			return 0, &SyntaxError{Token: "newline"}
		}
		if len(s) > 1 && s[1] == '{' {
			end := strings.IndexByte(s, '}')
			if end < 0 {
				return 0, &SyntaxError{Token: "newline"}
			}
			return end + 1, nil
		}
	}
	return 1, nil
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

// parse turns src into a list. An empty or comment-only line yields an
// empty list.
func parse(src string) (*list, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	l, err := p.parseList(false)
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t != nil {
		return nil, &SyntaxError{Token: t.val}
	}
	return l, nil
}

func (p *parser) parseList(inGroup bool) (*list, error) {
	l := &list{}
	for {
		// Skip blank separators between commands.
		for t := p.peek(); t != nil && t.kind == tSemi && t.val == "\n"; t = p.peek() {
			p.pos++
		}
		t := p.peek()
		if t == nil || (inGroup && t.kind == tRParen) {
			break
		}
		pl, err := p.parsePipeline()
		if err != nil {
			return nil, err
		}
		l.items = append(l.items, pl)
		op := ";"
		if t := p.peek(); t != nil {
			switch t.kind {
			case tSemi, tAmp, tAndIf, tOrIf:
				op = t.val
				if op == "\n" {
					op = ";"
				}
				p.pos++
				if t.kind == tAndIf || t.kind == tOrIf {
					for n := p.peek(); n != nil && n.kind == tSemi && n.val == "\n"; n = p.peek() {
						p.pos++
					}
					if n := p.peek(); n == nil || n.kind == tRParen {
						return nil, &SyntaxError{Token: "newline"}
					}
				}
			case tRParen:
				if !inGroup {
					return nil, &SyntaxError{Token: ")"}
				}
			default:
				return nil, &SyntaxError{Token: t.val}
			}
		}
		l.ops = append(l.ops, op)
	}
	return l, nil
}

func (p *parser) parsePipeline() (*pipeline, error) {
	pl := &pipeline{}
	for {
		c, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		pl.cmds = append(pl.cmds, c)
		if t := p.peek(); t != nil && t.kind == tPipe {
			p.pos++
			for n := p.peek(); n != nil && n.kind == tSemi && n.val == "\n"; n = p.peek() {
				p.pos++
			}
			continue
		}
		return pl, nil
	}
}

func (p *parser) parseCommand() (*command, error) {
	c := &command{}
	t := p.peek()
	if t == nil {
		return nil, &SyntaxError{Token: "newline"}
	}
	if t.kind == tLParen {
		p.pos++
		g, err := p.parseList(true)
		if err != nil {
			return nil, err
		}
		if t := p.peek(); t == nil || t.kind != tRParen {
			return nil, &SyntaxError{Token: "newline"}
		}
		p.pos++
		if len(g.items) == 0 {
			return nil, &SyntaxError{Token: ")"}
		}
		c.group = g
	}
	for {
		t := p.peek()
		if t == nil {
			break
		}
		switch t.kind {
		case tWord:
			if c.group != nil {
				return nil, &SyntaxError{Token: t.val}
			}
			if len(c.words) == 0 && isAssignment(t.val) {
				c.assigns = append(c.assigns, t.val)
			} else {
				c.words = append(c.words, t.val)
			}
			p.pos++
			continue
		case tRedir:
			p.pos++
			r := redir{fd: t.fd, op: t.val}
			nt := p.peek()
			if nt == nil || nt.kind != tWord {
				tok := "newline"
				if nt != nil {
					tok = nt.val
				}
				return nil, &SyntaxError{Token: tok}
			}
			r.target = nt.val
			p.pos++
			c.redirs = append(c.redirs, r)
			continue
		case tLParen:
			return nil, &SyntaxError{Token: "("}
		}
		break
	}
	if c.group == nil && len(c.words) == 0 && len(c.assigns) == 0 && len(c.redirs) == 0 {
		t := p.peek()
		tok := "newline"
		if t != nil {
			tok = t.val
		}
		return nil, &SyntaxError{Token: tok}
	}
	return c, nil
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	return isName(w[:eq])
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
