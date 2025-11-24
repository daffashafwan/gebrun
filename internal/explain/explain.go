// package explain implements parsing Go code to extract a "story"
// upgraded version: goroutine (A - linear w/ tags) and worker-pool as goroutine (1)
//
// features:
// - parse files under root
// - detect: assign, binary expr, call expr, go stmt, defer stmt, send/recv (channels), func literals
// - treat go/worker submit as "goroutine start" and tag internal operations with GoroutineID
// - build graph nodes/edges with metadata
// - PrintStoryText outputs linear reading order but marks goroutine starts & defer & channel ops
package explain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// =====================
// Types
// =====================

// NodeType is textual type info
type NodeType string

const (
	NodeVar    NodeType = "var"
	NodeConst  NodeType = "const"
	NodeFunc   NodeType = "func"
	NodeLit    NodeType = "literal"
	NodeChan   NodeType = "chan"
	NodeOthers NodeType = "other"
)

// DataNode represents a variable/value/func in the story
type DataNode struct {
	ID        string   `json:"id"`         // unique id: name|pos or synthetic
	Name      string   `json:"name"`       // human name
	Type      NodeType `json:"type"`       // var, func, literal, ...
	OriginPos string   `json:"origin_pos"` // file:line:col
}

// DataEdge represents a transformation / flow from From -> To
type DataEdge struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Op          string `json:"op"`           // assign, +, concat, call, go_start, defer, chan_send, chan_recv
	Expr        string `json:"expr"`         // source code fragment
	Pos         string `json:"pos"`          // position of the operation
	GoroutineID string `json:"goroutine_id"` // "" for main / not in goroutine
	Info        string `json:"info"`         // human-friendly short info
}

// StoryGraph contains nodes + edges
type StoryGraph struct {
	Nodes map[string]DataNode `json:"nodes"`
	Edges []DataEdge          `json:"edges"`
}

// StoryResult is final output
type StoryResult struct {
	ScannedAt time.Time  `json:"scanned_at"`
	Root      string     `json:"root"`
	Graph     StoryGraph `json:"graph"`
	// linear events (preserve discovery order) used for PrintStoryText
	Events []DataEdge `json:"-"`
}

// ParseOptions for customizing behavior
type ParseOptions struct {
	// GoroutineModeA: if true, we use the "A" behavior (linear story with goroutine tagged)
	// other modes could be added later
	GoroutineModeA bool
	// WorkerPoolAsGoroutine: if true, treat worker pool submissions (ants, pool.Submit) same as goroutine
	WorkerPoolAsGoroutine bool
	// File exclusion patterns (suffix)
	FileExclusionSuffix []string
}

// =====================
// Utilities
// =====================

func readFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func isExcluded(path string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

func walkGoFiles(root string, excludeSuffix []string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// skip vendor and hidden dirs
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" && !isExcluded(path, excludeSuffix) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func safeSlice(src []byte, start, end token.Pos) string {
	s := int(start) - 1
	e := int(end) - 1
	if s < 0 {
		s = 0
	}
	if e > len(src) {
		e = len(src)
	}
	if s >= e {
		return ""
	}
	return string(src[s:e])
}

func exprToString(e ast.Expr) string {
	if e == nil {
		return ""
	}
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprToString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprToString(v.Fun) + "(...)"
	case *ast.StarExpr:
		return "*" + exprToString(v.X)
	case *ast.IndexExpr:
		return exprToString(v.X) + "[..]"
	case *ast.CompositeLit:
		return "struct{..}"
	case *ast.BasicLit:
		return v.Value
	case *ast.UnaryExpr:
		// e.g. <-ch or &x
		if v.Op.String() == "<-" {
			return "<-" + exprToString(v.X)
		}
		return v.Op.String() + exprToString(v.X)
	case *ast.BinaryExpr:
		return exprToString(v.X) + " " + v.Op.String() + " " + exprToString(v.Y)
	case *ast.ParenExpr:
		return "(" + exprToString(v.X) + ")"
	case *ast.FuncLit:
		return "func{...}"
	default:
		return fmt.Sprintf("%T", e)
	}
}

func nodePosString(fset *token.FileSet, n ast.Node) string {
	if n == nil {
		return ""
	}
	pos := fset.Position(n.Pos())
	return fmt.Sprintf("%s:%d:%d", pos.Filename, pos.Line, pos.Column)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func openBrowser(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}

// =====================
// Core parsing / graph builder
// =====================

type parserState struct {
	fset             *token.FileSet
	src              []byte
	graph            StoryGraph
	events           []DataEdge
	goroutineCounter int
	// stack of current goroutine context while walking nodes
	goroutineStack []string
	opts           ParseOptions
	// for concurrency safety in multi-file parse (not heavily needed but safe)
	mu sync.Mutex
}

func (s *parserState) pushGoroutine(tag string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.goroutineCounter++
	id := fmt.Sprintf("goroutine#%d", s.goroutineCounter)
	// label: tag@file:line if available
	if tag != "" {
		id = fmt.Sprintf("%s@%s", id, tag)
	}
	s.goroutineStack = append(s.goroutineStack, id)
	return id
}

func (s *parserState) popGoroutine() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.goroutineStack) == 0 {
		return
	}
	s.goroutineStack = s.goroutineStack[:len(s.goroutineStack)-1]
}

func (s *parserState) currentGoroutine() string {
	if len(s.goroutineStack) == 0 {
		return "" // main
	}
	return s.goroutineStack[len(s.goroutineStack)-1]
}

func newParserState(fset *token.FileSet, src []byte, opts ParseOptions) *parserState {
	return &parserState{
		fset:  fset,
		src:   src,
		graph: StoryGraph{Nodes: map[string]DataNode{}, Edges: []DataEdge{}},
		opts:  opts,
	}
}

func (s *parserState) addNode(name string, ntype NodeType, posInfo string) string {
	id := fmt.Sprintf("%s|%s", name, posInfo)
	// if node exists, keep existing ID; else create
	if _, ok := s.graph.Nodes[id]; !ok {
		s.graph.Nodes[id] = DataNode{ID: id, Name: name, Type: ntype, OriginPos: posInfo}
	}
	return id
}

func (s *parserState) addEdge(from, to, op, expr, pos, info string) {
	edge := DataEdge{
		From:        from,
		To:          to,
		Op:          op,
		Expr:        expr,
		Pos:         pos,
		GoroutineID: s.currentGoroutine(),
		Info:        info,
	}
	s.graph.Edges = append(s.graph.Edges, edge)
	s.events = append(s.events, edge)
}

// detect function-like worker pool call names commonly used (ants, pool.Submit, etc)
func isWorkerPoolCall(fun ast.Expr) bool {
	// simplistic: look for "ants.Submit", "pool.Submit", "workerPool.Submit"
	switch v := fun.(type) {
	case *ast.SelectorExpr:
		name := exprToString(v)
		if strings.Contains(name, "ants.") || strings.Contains(name, "pool.") || strings.Contains(name, "Worker") || strings.Contains(name, "worker") {
			if strings.HasSuffix(name, "Submit(...)") || strings.HasSuffix(name, "Submit") || strings.Contains(name, "Submit") {
				return true
			}
		}
	}
	return false
}

// main scanning recursive function
func (s *parserState) scanNodeRecursive(n ast.Node) {
	if n == nil {
		return
	}

	// handle specific nodes
	switch v := n.(type) {
	case *ast.AssignStmt:
		// assignment (a = b, a := b, multi-assign)
		for i, lhs := range v.Lhs {
			var rhs ast.Expr
			if i < len(v.Rhs) {
				rhs = v.Rhs[i]
			} else if len(v.Rhs) == 1 {
				// e.g., a, b = f()  (Rhs len==1 => same expr for multiple lhs)
				rhs = v.Rhs[0]
			} else {
				rhs = nil
			}
			lhsStr := exprToString(lhs)
			posL := nodePosString(s.fset, lhs)
			lid := s.addNode(lhsStr, NodeVar, posL)

			exprText := ""
			if rhs != nil {
				exprText = strings.TrimSpace(safeSlice(s.src, rhs.Pos(), rhs.End()))
			}
			// if rhs is binary expr, break into two edges
			switch r := rhs.(type) {
			case *ast.BinaryExpr:
				left := exprToString(r.X)
				right := exprToString(r.Y)
				pos := nodePosString(s.fset, r)
				// nodes
				ln := s.addNode(left, NodeVar, nodePosString(s.fset, r.X))
				rn := s.addNode(right, NodeVar, nodePosString(s.fset, r.Y))
				// edges left -> lhs and right -> lhs with op r.Op
				s.addEdge(ln, lid, r.Op.String(), exprText, pos, fmt.Sprintf("binary %s", r.Op.String()))
				s.addEdge(rn, lid, r.Op.String(), exprText, pos, fmt.Sprintf("binary %s", r.Op.String()))
			default:
				// general case: single rhs -> lhs
				if rhs != nil {
					rname := exprToString(rhs)
					rpos := nodePosString(s.fset, rhs)
					rid := s.addNode(rname, classifyExprType(rhs), rpos)
					pos := nodePosString(s.fset, v)
					op := v.Tok.String() // = or :=
					s.addEdge(rid, lid, "assign_"+op, exprText, pos, "assign")
				}
			}
		}
	case *ast.DeferStmt:
		// mark defer call; call expr inside
		pos := nodePosString(s.fset, v)
		call := v.Call
		callee := exprToString(call.Fun)
		cid := s.addNode(callee, NodeFunc, nodePosString(s.fset, call.Fun))
		s.addEdge("", cid, "defer", strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "defer call")

		// scan args inside defer
		for _, arg := range call.Args {
			aid := s.addNode(exprToString(arg), classifyExprType(arg), nodePosString(s.fset, arg))
			s.addEdge(aid, cid, "call_arg", exprToString(arg), pos, "defer arg")
		}
	case *ast.GoStmt:
		// goroutine start: can be CallExpr or FuncLit
		pos := nodePosString(s.fset, v)
		switch g := v.Call.Fun.(type) {
		case *ast.CallExpr:
			// go someFunc(args...) OR go func(){ ... }()
			// decide if callee is a function literal or normal function
			if flit, ok := g.Fun.(*ast.FuncLit); ok {
				tag := nodePosString(s.fset, flit)
				gid := s.pushGoroutine(tag)
				// record "goroutine start" edge from current ctx (empty from) to gid as special node
				gNodeId := s.addNode(gid, NodeOthers, tag)
				s.addEdge("", gNodeId, "go_start", "go func literal", pos, "goroutine start (func lit)")
				// scan body inside goroutine with goroutine context
				// push done above; we scan flit.Body then pop
				s.scanNodeRecursive(flit.Body)
				s.popGoroutine()
			} else {
				// normal call expression: go someFunc(x)
				callee := exprToString(g.Fun)
				tag := nodePosString(s.fset, g)
				gid := s.pushGoroutine(fmt.Sprintf("%s@%s", callee, tag))
				gNodeId := s.addNode(gid, NodeOthers, tag)
				s.addEdge("", gNodeId, "go_start", fmt.Sprintf("go %s", callee), pos, "goroutine start (call)")
				// add edges from args -> callee node inside goroutine
				calleeNodeId := s.addNode(callee+"()", NodeFunc, nodePosString(s.fset, g.Fun))
				for _, arg := range g.Args {
					aid := s.addNode(exprToString(arg), classifyExprType(arg), nodePosString(s.fset, arg))
					s.addEdge(aid, calleeNodeId, "call_arg", strings.TrimSpace(safeSlice(s.src, arg.Pos(), arg.End())), pos, "goroutine arg")
				}
				// assume callee body scanned elsewhere (function decl) - keep linked by name
				s.popGoroutine()
			}
		case *ast.FuncLit:
			// go func() { ... }()
			fl := g
			tag := nodePosString(s.fset, fl)
			gid := s.pushGoroutine(tag)
			gNodeId := s.addNode(gid, NodeOthers, tag)
			s.addEdge("", gNodeId, "go_start", "go func literal", pos, "goroutine start (func lit)")
			s.scanNodeRecursive(fl.Body)
			s.popGoroutine()
		default:
			// unknown shape
		}
	case *ast.CallExpr:
		// function calls - including potential worker pool submits
		callee := exprToString(v.Fun)
		pos := nodePosString(s.fset, v)
		// detect worker-pool submissions by name heuristics
		if s.opts.WorkerPoolAsGoroutine && isWorkerPoolCall(v.Fun) {
			// find func literal in args
			for _, arg := range v.Args {
				if fl, ok := arg.(*ast.FuncLit); ok {
					// treat like goroutine start, but mark source as pool-submit
					tag := nodePosString(s.fset, fl)
					gid := s.pushGoroutine(fmt.Sprintf("pool@%s", tag))
					gNodeId := s.addNode(gid, NodeOthers, tag)
					s.addEdge("", gNodeId, "pool_submit", strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "worker pool submit")
					// scan function literal body
					s.scanNodeRecursive(fl.Body)
					s.popGoroutine()
				}
			}
		} else {
			// regular call: create callee node and link args -> callee
			cnodeId := s.addNode(callee+"()", NodeFunc, nodePosString(s.fset, v.Fun))
			for _, arg := range v.Args {
				aid := s.addNode(exprToString(arg), classifyExprType(arg), nodePosString(s.fset, arg))
				s.addEdge(aid, cnodeId, "call_arg", strings.TrimSpace(safeSlice(s.src, arg.Pos(), arg.End())), pos, "call arg")
			}
			// record call as event too (caller -> callee)
			s.addEdge("", cnodeId, "call", strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "call")
		}
	case *ast.SendStmt:
		// ch <- x  (channel send)
		pos := nodePosString(s.fset, v)
		chExpr := exprToString(v.Chan)
		valExpr := exprToString(v.Value)
		chNode := s.addNode(chExpr, NodeChan, nodePosString(s.fset, v.Chan))
		valNode := s.addNode(valExpr, classifyExprType(v.Value), nodePosString(s.fset, v.Value))
		s.addEdge(valNode, chNode, "chan_send", strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "channel send")
	case *ast.UnaryExpr:
		// recv: <-ch appears as UnaryExpr with Op = <- and X = ident
		if v.Op.String() == "<-" {
			pos := nodePosString(s.fset, v)
			chanExpr := exprToString(v.X)
			chanNode := s.addNode(chanExpr, NodeChan, nodePosString(s.fset, v.X))
			// create a synthetic "recv" node -> usually assigned elsewhere; but we record recv op
			recvID := fmt.Sprintf("recv@%s", pos)
			rnode := s.addNode(recvID, NodeOthers, pos)
			s.addEdge(chanNode, rnode, "chan_recv", strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "channel recv")
		}
	case *ast.FuncDecl:
		// scan inside function; set current goroutine main for top-level funcs (we don't push)
		// but if function has receiver, include receiver name in node to help disambiguation
		// also scan body normally
		s.scanNodeRecursive(v.Body)
	case *ast.RangeStmt:
		// range over channel or slice
		pos := nodePosString(s.fset, v)
		x := exprToString(v.X)
		xID := s.addNode(x, classifyExprType(v.X), nodePosString(s.fset, v.X))
		// iteration yields values - if Key/Value present, link
		if v.Value != nil {
			vname := exprToString(v.Value)
			vID := s.addNode(vname, NodeVar, nodePosString(s.fset, v.Value))
			s.addEdge(xID, vID, "range_iter", strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "range iteration")
		}
	case *ast.BinaryExpr:
		// e.g., a + b used inline (not necessarily assignment)
		left := exprToString(v.X)
		right := exprToString(v.Y)
		pos := nodePosString(s.fset, v)
		ln := s.addNode(left, classifyExprType(v.X), nodePosString(s.fset, v.X))
		rn := s.addNode(right, classifyExprType(v.Y), nodePosString(s.fset, v.Y))
		// get a synthetic result node name
		resID := fmt.Sprintf("tmp@%s", pos)
		rd := s.addNode(resID, NodeOthers, pos)
		s.addEdge(ln, rd, v.Op.String(), strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "binary expr")
		s.addEdge(rn, rd, v.Op.String(), strings.TrimSpace(safeSlice(s.src, v.Pos(), v.End())), pos, "binary expr")
	case *ast.BlockStmt:
		// scan children (default fallback happens later too)
	default:
		// other nodes ignored as top-level here
	}

	// recursively inspect children; use ast.Inspect to walk all child nodes
	ast.Inspect(n, func(child ast.Node) bool {
		// avoid re-processing the same node we already handled (some cases)
		if child == n {
			return true
		}
		s.scanNodeRecursive(child)
		return true
	})
}

func classifyExprType(e ast.Expr) NodeType {
	if e == nil {
		return NodeOthers
	}
	switch e.(type) {
	case *ast.Ident:
		return NodeVar
	case *ast.BasicLit:
		return NodeLit
	case *ast.CallExpr:
		return NodeFunc
	case *ast.SelectorExpr:
		return NodeVar
	case *ast.CompositeLit:
		return NodeVar
	default:
		return NodeOthers
	}
}

// ParseServiceWithOptions parses all go files under root with options
func ParseServiceWithOptions(root string, opts ParseOptions) (StoryResult, error) {
	files, err := walkGoFiles(root, opts.FileExclusionSuffix)
	if err != nil {
		return StoryResult{}, err
	}
	fset := token.NewFileSet()
	globalState := StoryGraph{Nodes: map[string]DataNode{}, Edges: []DataEdge{}}
	var globalEvents []DataEdge

	// we parse files sequentially but keep a consistent parserState across files
	state := newParserState(fset, nil, opts)

	for _, file := range files {
		src, err := readFile(file)
		if err != nil {
			// skip unreadable file but continue
			continue
		}
		state.src = src
		f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			// skip parse errors but continue
			continue
		}

		// walk top-level nodes
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				return true
			}
			// when encountering a function declaration, we scan inside.
			// keep main goroutine context (empty)
			if fn, ok := n.(*ast.FuncDecl); ok {
				// push nothing, just scan body (body may contain go statements which push goroutine)
				state.scanNodeRecursive(fn.Body)
				return false // we've scanned body; skip children because scanNodeRecursive will traverse
			}
			// top-level walking
			state.scanNodeRecursive(n)
			return true
		})
		// merge per-file state into global
		for k, v := range state.graph.Nodes {
			globalState.Nodes[k] = v
		}
		globalState.Edges = append(globalState.Edges, state.graph.Edges...)
		globalEvents = append(globalEvents, state.events...)
		// reset state.graph for next file, but keep goroutineCounter so numbering is global
		state.graph = StoryGraph{Nodes: map[string]DataNode{}, Edges: []DataEdge{}}
		state.events = []DataEdge{}
	}

	// merge nodes already done; edges appended
	// deduplicate edges? keep discovery order
	res := StoryResult{
		ScannedAt: time.Now().UTC(),
		Root:      root,
		Graph:     globalState,
		Events:    globalEvents,
	}
	return res, nil
}

// =====================
// Output / Story generation
// =====================

// PrintStoryText prints a linear story (mode A style). It prints events in discovery order,
// but annotate goroutine start and operations inside goroutine via GoroutineID tags.
func PrintStoryText(res StoryResult) {
	fmt.Printf("Story for service at: %s\n\n", res.Root)

	// If events empty, fallback to scanning graph edges in order
	events := res.Events
	if len(events) == 0 {
		events = res.Graph.Edges
	}

	// We'll print in order, but when we see a go_start or pool_submit edge we print a header
	// and then keep printing events; operations that have GoroutineID non-empty will be printed
	// with indentation.
	for _, e := range events {
		// pretty position
		pos := e.Pos
		expr := truncate(e.Expr, 80)
		gid := e.GoroutineID
		switch e.Op {
		case "go_start":
			// e.To is goroutine synthetic node id
			fmt.Printf("goroutine launched -> %s (%s)\n", e.To, pos)
		case "pool_submit":
			fmt.Printf("worker-pool submit -> %s (%s)\n", e.To, pos)
		case "defer":
			fmt.Printf("[defer] will execute -> %s (at: %s) | %s\n", e.To, pos, expr)
		case "chan_send":
			if gid != "" {
				fmt.Printf("  [%s] %s --[chan_send]--> %s | %s (%s)\n", gid, e.From, e.To, expr, pos)
			} else {
				fmt.Printf("%s --[chan_send]--> %s | %s (%s)\n", e.From, e.To, expr, pos)
			}
		case "chan_recv":
			if gid != "" {
				fmt.Printf("  [%s] %s --[chan_recv]--> %s | %s (%s)\n", gid, e.From, e.To, expr, pos)
			} else {
				fmt.Printf("%s --[chan_recv]--> %s | %s (%s)\n", e.From, e.To, expr, pos)
			}
		case "call":
			// call can be inside goroutine; show tag
			if gid != "" {
				fmt.Printf("  [%s] call -> %s | %s (%s)\n", gid, e.To, expr, pos)
			} else {
				fmt.Printf("call -> %s | %s (%s)\n", e.To, expr, pos)
			}
		case "call_arg":
			// argument flow
			if gid != "" {
				fmt.Printf("  [%s] %s -> %s (arg) | %s (%s)\n", gid, e.From, e.To, expr, pos)
			} else {
				fmt.Printf("%s -> %s (arg) | %s (%s)\n", e.From, e.To, expr, pos)
			}
		default:
			// default prints include assign, assign_:=, binary etc
			if gid != "" {
				fmt.Printf("  [%s] %s --[%s]--> %s | %s (%s)\n", gid, e.From, e.Op, e.To, expr, pos)
			} else {
				fmt.Printf("%s --[%s]--> %s | %s (%s)\n", e.From, e.Op, e.To, expr, pos)
			}
		}
	}
}

// PrintStoryJSON pretty encodes StoryResult
func PrintStoryJSON(res StoryResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

// PrintStoryPlantUML prints a PlantUML-ish representation: participants are nodes; arrows are edges.
// Note: not perfect PlantUML labels but enough to visualize flows.
func PrintStoryPlantUML(res StoryResult) {
	fmt.Println("@startuml")
	fmt.Println("title Service Story - Data Flow")
	// we will register participant names (limit length)
	seen := map[string]bool{}
	for _, n := range res.Graph.Nodes {
		name := sanitizePlantName(n.Name)
		if !seen[name] {
			fmt.Printf("participant \"%s\" as %s\n", n.Name, name)
			seen[name] = true
		}
	}
	// edges
	for _, e := range res.Graph.Edges {
		from := e.From
		to := e.To
		if from == "" {
			// use synthetic "START"
			fmt.Printf("note over %s : %s\n", sanitizePlantName(to), e.Op)
			continue
		}
		fmt.Printf("%s -> %s : %s\\n%s\n", sanitizePlantName(shortName(from)), sanitizePlantName(shortName(to)), e.Op, truncate(e.Expr, 50))
	}
	fmt.Println("@enduml")
}

func sanitizePlantName(s string) string {
	// make a simple safe name by removing special chars and truncating
	if s == "" {
		return "EMPTY"
	}
	out := s
	out = strings.ReplaceAll(out, " ", "_")
	out = strings.ReplaceAll(out, ".", "_")
	out = strings.ReplaceAll(out, "|", "_")
	out = strings.ReplaceAll(out, "/", "_")
	out = strings.ReplaceAll(out, ":", "_")
	out = strings.ReplaceAll(out, "@", "_")
	out = strings.ReplaceAll(out, "-", "_")
	return truncate(out, 40)
}

func shortName(id string) string {
	// id is name|pos — we want readable name
	parts := strings.Split(id, "|")
	if len(parts) > 0 {
		return parts[0]
	}
	return id
}

// PrintStoryHTML writes a simple HTML table and opens in browser
func PrintStoryHTML(res StoryResult, filename string) error {
	var sb strings.Builder
	sb.WriteString("<html><head><meta charset='utf-8'><title>Service Story</title></head><body>")
	sb.WriteString("<h2>Service Story</h2>")
	sb.WriteString("<table border='1' cellpadding='6' cellspacing='0'>")
	sb.WriteString("<tr><th>From</th><th>Op</th><th>To</th><th>Goroutine</th><th>Expr</th><th>Pos</th></tr>")
	for _, e := range res.Graph.Edges {
		sb.WriteString("<tr>")
		sb.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(shortName(e.From))))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(e.Op)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(shortName(e.To))))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(e.GoroutineID)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(truncate(e.Expr, 200))))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(e.Pos)))
		sb.WriteString("</tr>")
	}
	sb.WriteString("</table></body></html>")
	if err := ioutil.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
		return err
	}
	openBrowser(filename)
	return nil
}

func htmlEscape(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			buf.WriteString("&amp;")
		case '<':
			buf.WriteString("&lt;")
		case '>':
			buf.WriteString("&gt;")
		case '"':
			buf.WriteString("&quot;")
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// =====================
// Example helper function (not required but useful)
// =====================

// QuickParseAndPrint convenience wrapper
func QuickParseAndPrint(root string, fileExclusionSuffixes []string) (res StoryResult) {
	opts := ParseOptions{GoroutineModeA: true, WorkerPoolAsGoroutine: true, FileExclusionSuffix: fileExclusionSuffixes}
	res, err := ParseServiceWithOptions(root, opts)
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}
	return res
}

// =====================
// End of library
// =====================
