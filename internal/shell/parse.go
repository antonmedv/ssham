package shell

import (
	"fmt"
	"strings"
)

// The parser understands BusyBox ash: lists joined by ; & && ||,
// pipelines, ( ) and { } groups, if, while, until, for, case, !,
// functions, redirections, here-documents and quoted words. Words are kept
// raw and expanded only when the command runs, so that variables set by
// earlier commands on the same line are visible to later ones.
//
// Arrays and process substitution are not in ash; they fail with the
// syntax errors ash gives for them.

type tokKind int

const (
	tWord tokKind = iota
	tPipe
	tAndIf
	tOrIf
	tSemi  // ; or newline
	tDSemi // ;;
	tAmp
	tRedir
	tLParen
	tRParen
)

type token struct {
	kind tokKind
	val  string // raw word, or redirection operator
	fd   int    // redirection source fd
	// For the delimiter word of a here-document: its body, and whether
	// the delimiter was quoted (then the body is not expanded).
	heredoc *heredoc
}

type heredoc struct {
	body   string
	quoted bool
}

type redir struct {
	fd     int
	op     string // ">", ">>", "<", ">&", "&>", "<<"
	target string // raw word
	doc    *heredoc
}

// command is a simple command (words), or one compound form.
type command struct {
	assigns []string
	words   []string
	redirs  []redir

	subshell *list // ( list )
	brace    *list // { list; }
	ifc      *ifClause
	loop     *loopClause
	forc     *forClause
	casec    *caseClause
	fn       *funcDef // name() { ... }: defines a function
}

type caseClause struct {
	word  string
	items []caseItem
}

type caseItem struct {
	patterns []string
	body     *list
}

type funcDef struct {
	name string
	body *command
}

type ifClause struct {
	conds, bodies []*list // if/elif conditions and their then-bodies
	elseBody      *list
}

type loopClause struct {
	until      bool
	cond, body *list
}

type forClause struct {
	name  string
	words []string
	in    bool // false: iterate over "$@"
	body  *list
}

type pipeline struct {
	negate bool // ! pipeline
	cmds   []*command
}

type list struct {
	items []*pipeline
	ops   []string // ops[i] joins items[i] and items[i+1]; the last is the terminator
}

// SyntaxError is returned for input the parser cannot handle. Its message
// matches BusyBox ash.
type SyntaxError struct {
	Token        string // the unexpected token; "" means end of input
	Expecting    string // what was expected, if known
	Unterminated bool   // an unterminated quote
}

// Incomplete reports whether more input could complete the command: an
// interactive shell then asks for it with $PS2.
func (e *SyntaxError) Incomplete() bool { return e.Token == "" || e.Unterminated }

func (e *SyntaxError) Error() string {
	switch {
	case e.Unterminated:
		return "syntax error: unterminated quoted string"
	case e.Token == "" && e.Expecting != "":
		return fmt.Sprintf("syntax error: unexpected end of file (expecting %q)", e.Expecting)
	case e.Token == "":
		return "syntax error: unexpected end of file"
	case e.Expecting != "":
		return fmt.Sprintf("syntax error: unexpected %q (expecting %q)", e.Token, e.Expecting)
	}
	return fmt.Sprintf("syntax error: unexpected %q", e.Token)
}

// reserved words are only special at the start of a command.
var reserved = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"while": true, "until": true, "for": true, "do": true, "done": true,
	"{": true, "}": true, "!": true, "case": true, "esac": true, "function": true,
}

func isMeta(c byte) bool {
	switch c {
	case ' ', '\t', '\n', ';', '&', '|', '<', '>', '(', ')':
		return true
	}
	return false
}

// lex splits src into tokens. Here-document bodies are read from the
// lines after the one with their << operator. If final is false, a
// missing here-document end is an incomplete-input error; otherwise the
// document ends with the input, as in ash.
func lex(src string, final bool) ([]token, error) {
	var toks []token
	var pending []int // tokens whose here-document body comes next
	readDocs := func(i int) (int, error) {
		for _, t := range pending {
			delim, quoted := heredocDelim(toks[t].val)
			strip := toks[t-1].val == "<<-"
			var body strings.Builder
			found := false
			for i < len(src) {
				end := strings.IndexByte(src[i:], '\n')
				line := src[i:]
				if end >= 0 {
					line = src[i : i+end]
					i += end + 1
				} else {
					i = len(src)
				}
				if strip {
					line = strings.TrimLeft(line, "\t")
				}
				if line == delim {
					found = true
					break
				}
				body.WriteString(line + "\n")
			}
			if !found && !final {
				return i, &SyntaxError{Expecting: delim}
			}
			toks[t].heredoc = &heredoc{body: body.String(), quoted: quoted}
		}
		pending = pending[:0]
		return i, nil
	}
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n' && len(pending) > 0:
			toks = append(toks, token{kind: tSemi, val: "\n"})
			var err error
			if i, err = readDocs(i + 1); err != nil {
				return nil, err
			}
			continue
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], ";;"):
			toks = append(toks, token{kind: tDSemi, val: ";;"})
			i += 2
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
			if k := len(toks); k > 1 && toks[k-2].kind == tRedir && strings.HasPrefix(toks[k-2].val, "<<") && toks[k-2].val != "<<<" {
				pending = append(pending, k-1)
			}
			i += n
		}
	}
	if len(pending) > 0 {
		if _, err := readDocs(len(src)); err != nil {
			return nil, err
		}
	}
	return toks, nil
}

// heredocDelim is the word that ends a here-document. Quoting any part of
// it turns off expansion in the body.
func heredocDelim(w string) (string, bool) {
	quoted := strings.ContainsAny(w, `'"\`)
	return strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(w), quoted
}

func lexRedirOp(s string) (string, int) {
	for _, op := range []string{">>", ">&", ">|", "<<<", "<<-", "<<", "<&", "<>", ">", "<"} {
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

var errUnterminated = &SyntaxError{Unterminated: true}

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
			return 0, errUnterminated
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
		return 0, errUnterminated
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
		return 0, errUnterminated
	case '$':
		if len(s) > 1 && s[1] == '\'' {
			for i := 2; i < len(s); i++ {
				switch s[i] {
				case '\\':
					i++
				case '\'':
					return i + 1, nil
				}
			}
			return 0, errUnterminated
		}
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
			return 0, &SyntaxError{Expecting: ")"}
		}
		if len(s) > 1 && s[1] == '{' {
			end := strings.IndexByte(s, '}')
			if end < 0 {
				return 0, &SyntaxError{Expecting: "}"}
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

// peekWord returns the next token's text if it is a word.
func (p *parser) peekWord() string {
	if t := p.peek(); t != nil && t.kind == tWord {
		return t.val
	}
	return ""
}

func (p *parser) skipNewlines() {
	for t := p.peek(); t != nil && t.kind == tSemi && t.val == "\n"; t = p.peek() {
		p.pos++
	}
}

// unexpected returns the syntax error for the next token.
func (p *parser) unexpected(expecting string) error {
	t := p.peek()
	if t == nil {
		return &SyntaxError{Expecting: expecting}
	}
	return &SyntaxError{Token: t.val, Expecting: expecting}
}

// expect consumes the reserved word w.
func (p *parser) expect(w string) error {
	p.skipNewlines()
	if p.peekWord() != w {
		return p.unexpected(w)
	}
	p.pos++
	return nil
}

// parse turns src into a list. An empty or comment-only line yields an
// empty list. src is all the input there is.
func parse(src string) (*list, error) { return parseInput(src, true) }

// parseInput parses src; with final false, a here-document without its end
// is incomplete input rather than ending at the end of src.
func parseInput(src string, final bool) (*list, error) {
	toks, err := lex(src, final)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	l, err := p.parseList()
	if err != nil {
		return nil, err
	}
	if p.peek() != nil {
		return nil, p.unexpected("")
	}
	return l, nil
}

// endsList reports whether the next token closes the enclosing construct.
func (p *parser) endsList() bool {
	t := p.peek()
	if t == nil || t.kind == tRParen || t.kind == tDSemi {
		return true
	}
	switch p.peekWord() {
	case "then", "elif", "else", "fi", "do", "done", "}", "esac":
		return true
	}
	return false
}

func (p *parser) parseList() (*list, error) {
	l := &list{}
	for {
		p.skipNewlines()
		if p.endsList() {
			return l, nil
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
					p.skipNewlines()
					if p.endsList() {
						return nil, p.unexpected("")
					}
				}
			case tRParen, tDSemi:
			case tWord:
				if !p.endsList() {
					return nil, p.unexpected("")
				}
			default:
				return nil, p.unexpected("")
			}
		}
		l.ops = append(l.ops, op)
	}
}

func (p *parser) parsePipeline() (*pipeline, error) {
	pl := &pipeline{}
	if p.peekWord() == "!" {
		pl.negate = true
		p.pos++
	}
	for {
		c, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		pl.cmds = append(pl.cmds, c)
		if t := p.peek(); t != nil && t.kind == tPipe {
			p.pos++
			p.skipNewlines()
			continue
		}
		return pl, nil
	}
}

func (p *parser) parseCommand() (*command, error) {
	t := p.peek()
	if t == nil {
		return nil, p.unexpected("")
	}
	c := &command{}
	var err error
	switch {
	case t.kind == tLParen:
		p.pos++
		if c.subshell, err = p.parseList(); err != nil {
			return nil, err
		}
		if t := p.peek(); t == nil || t.kind != tRParen {
			return nil, p.unexpected(")")
		}
		p.pos++
		if len(c.subshell.items) == 0 {
			return nil, &SyntaxError{Token: ")"}
		}
	case t.kind == tWord && reserved[t.val]:
		if err := p.parseCompound(c); err != nil {
			return nil, err
		}
		if c.fn != nil {
			return c, nil
		}
	case t.kind == tWord && p.isFuncDef():
		name := t.val
		p.pos += 3
		return p.parseFuncBody(c, name)
	}
	compound := c.subshell != nil || c.brace != nil || c.ifc != nil || c.loop != nil || c.forc != nil || c.casec != nil

	for t := p.peek(); t != nil; t = p.peek() {
		switch t.kind {
		case tWord:
			if compound {
				return nil, p.unexpected("")
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
			nt := p.peek()
			if nt == nil || nt.kind != tWord {
				return nil, p.unexpected("")
			}
			c.redirs = append(c.redirs, redir{fd: t.fd, op: t.val, target: nt.val, doc: nt.heredoc})
			p.pos++
			continue
		case tLParen:
			// a=(1 2): ash has no arrays.
			return nil, p.unexpected("")
		}
		break
	}
	if !compound && len(c.words) == 0 && len(c.assigns) == 0 && len(c.redirs) == 0 {
		return nil, p.unexpected("")
	}
	return c, nil
}

// parseCompound parses a construct that starts with a reserved word.
func (p *parser) parseCompound(c *command) error {
	word := p.peekWord()
	p.pos++
	var err error
	switch word {
	case "{":
		if c.brace, err = p.parseList(); err != nil {
			return err
		}
		if len(c.brace.items) == 0 {
			return p.unexpected("")
		}
		return p.expect("}")
	case "if":
		c.ifc = &ifClause{}
		for {
			cond, err := p.parseList()
			if err != nil {
				return err
			}
			if err := p.expect("then"); err != nil {
				return err
			}
			body, err := p.parseList()
			if err != nil {
				return err
			}
			c.ifc.conds = append(c.ifc.conds, cond)
			c.ifc.bodies = append(c.ifc.bodies, body)
			switch p.peekWord() {
			case "elif":
				p.pos++
				continue
			case "else":
				p.pos++
				if c.ifc.elseBody, err = p.parseList(); err != nil {
					return err
				}
			}
			return p.expect("fi")
		}
	case "while", "until":
		c.loop = &loopClause{until: word == "until"}
		if c.loop.cond, err = p.parseList(); err != nil {
			return err
		}
		if c.loop.body, err = p.parseDoGroup(); err != nil {
			return err
		}
		return nil
	case "for":
		name := p.peekWord()
		if !isName(name) {
			return p.unexpected("")
		}
		p.pos++
		c.forc = &forClause{name: name}
		p.skipNewlines()
		if p.peekWord() == "in" {
			p.pos++
			c.forc.in = true
			for t := p.peek(); t != nil && t.kind == tWord; t = p.peek() {
				c.forc.words = append(c.forc.words, t.val)
				p.pos++
			}
		}
		if t := p.peek(); t != nil && t.kind == tSemi {
			p.pos++
		}
		c.forc.body, err = p.parseDoGroup()
		return err
	case "case":
		return p.parseCase(c)
	case "function":
		// bash's function NAME [()] BODY, which ash accepts too.
		name := p.peekWord()
		if !isName(name) {
			return p.unexpected("")
		}
		p.pos++
		if t := p.peek(); t != nil && t.kind == tLParen {
			if n := p.peekAt(1); n == nil || n.kind != tRParen {
				return p.unexpected("")
			}
			p.pos += 2
		}
		_, err := p.parseFuncBody(c, name)
		return err
	}
	// then, fi, done, case, ... where a command should start.
	p.pos--
	return p.unexpected("")
}

func (p *parser) peekAt(n int) *token {
	if p.pos+n < len(p.toks) {
		return &p.toks[p.pos+n]
	}
	return nil
}

// isFuncDef reports whether the next tokens are NAME ( ).
func (p *parser) isFuncDef() bool {
	t, open, close := p.peek(), p.peekAt(1), p.peekAt(2)
	return t != nil && t.kind == tWord && isName(t.val) && !reserved[t.val] &&
		open != nil && open.kind == tLParen && close != nil && close.kind == tRParen
}

// parseFuncBody parses the compound command that is a function's body.
func (p *parser) parseFuncBody(c *command, name string) (*command, error) {
	p.skipNewlines()
	t := p.peek()
	if t == nil {
		return nil, p.unexpected("")
	}
	if t.kind != tLParen && !(t.kind == tWord && reserved[t.val] && t.val != "function") {
		return nil, p.unexpected("")
	}
	body, err := p.parseCommand()
	if err != nil {
		return nil, err
	}
	c.fn = &funcDef{name: name, body: body}
	return c, nil
}

// parseCase parses the rest of case WORD in PATTERN) LIST ;; ... esac.
func (p *parser) parseCase(c *command) error {
	word := p.peekWord()
	if word == "" {
		return p.unexpected("")
	}
	p.pos++
	if err := p.expect("in"); err != nil {
		return err
	}
	c.casec = &caseClause{word: word}
	for {
		p.skipNewlines()
		if p.peekWord() == "esac" {
			p.pos++
			return nil
		}
		if t := p.peek(); t != nil && t.kind == tLParen {
			p.pos++
		}
		var item caseItem
		for {
			w := p.peekWord()
			if w == "" {
				return p.unexpected("")
			}
			item.patterns = append(item.patterns, w)
			p.pos++
			t := p.peek()
			if t != nil && t.kind == tPipe {
				p.pos++
				continue
			}
			if t == nil || t.kind != tRParen {
				return p.unexpected(")")
			}
			p.pos++
			break
		}
		body, err := p.parseList()
		if err != nil {
			return err
		}
		item.body = body
		c.casec.items = append(c.casec.items, item)
		if t := p.peek(); t != nil && t.kind == tDSemi {
			p.pos++
			continue
		}
		p.skipNewlines()
		if p.peekWord() != "esac" {
			return p.unexpected("esac")
		}
	}
}

func (p *parser) parseDoGroup() (*list, error) {
	if err := p.expect("do"); err != nil {
		return nil, err
	}
	body, err := p.parseList()
	if err != nil {
		return nil, err
	}
	if len(body.items) == 0 {
		return nil, p.unexpected("")
	}
	return body, p.expect("done")
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
