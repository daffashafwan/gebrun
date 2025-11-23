package analyzer

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Operation represents an arithmetic operation found inside a function
type Operation struct {
	Func    string `json:"func"`
	Pos     string `json:"pos"`
	Op      string `json:"op"`
	Expr    string `json:"expr"`
	Output  string 	`json:"output"`
	Input   []string `json:"input"`
}

// Call represents a call from one function to another
type Call struct {
	Caller string `json:"caller"`
	Callee string `json:"callee"`
	Pos    string `json:"pos"`
}

// Result is the aggregated scan output
type Result struct {
	ScannedAt  time.Time          `json:"scanned_at"`
	Root       string             `json:"root"`
	Operations []Operation        `json:"operations"`
	Calls      []Call             `json:"calls"`
	ByFunc     map[string]Summary `json:"by_func"`
}

// Summary contains operations + callees for a function
type Summary struct {
	Operations []Operation `json:"operations"`
	Callees    []string    `json:"callees"`
}

// Arithmetic token set (as strings used in AST.BinaryExpr.Op)
var arithmeticOps = map[string]bool{
	"+":  true,
	"-":  true,
	"*":  true,
	"/":  true,
	"%":  true,
	"<<": true,
	">>": true,
	"&":  true,
	"|":  true,
	"^":  true,
}

// Utility: read file bytes
func readFile(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// walkGoFiles collects .go files under root (skips vendor and test files by default)
func walkGoFiles(root string, fileExclusionSuffix []string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" && !isFileExcludedBySuffix(path, fileExclusionSuffix) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func isFileExcludedBySuffix(path string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// parseAndCollect scans files and returns operations and calls
func ParseAndCollect(root string, fileExclusionSuffix []string) (Result, error) {
	files, err := walkGoFiles(root, fileExclusionSuffix)
	if err != nil {
		return Result{}, err
	}
	fset := token.NewFileSet()
	// maps to accumulate
	ops := []Operation{}
	calls := []Call{}
	byFunc := map[string]Summary{}

	for _, file := range files {
		srcBytes, err := readFile(file)
		if err != nil {
			return Result{}, err
		}
		f, err := parser.ParseFile(fset, file, srcBytes, parser.ParseComments)
		if err != nil {
			return Result{}, err
		}

		ast.Inspect(f, func(n ast.Node) bool {
			// find function declarations
			if fn, ok := n.(*ast.FuncDecl); ok {
				fname := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					// method receiver -> include receiver type for disambiguation
					recvType := exprToString(fn.Recv.List[0].Type)
					fname = recvTypeClean(recvType) + "." + fname
				}
				// initialize
				if _, exists := byFunc[fname]; !exists {
					byFunc[fname] = Summary{}
				}
				// inspect function body for binary expressions and calls
				ast.Inspect(fn.Body, func(n2 ast.Node) bool {
					// arithmetic expressions
					if assign, ok := n2.(*ast.AssignStmt); ok {
						for i, rhs := range assign.Rhs {
							var op string
							var expr ast.Expr = rhs

							// handle assignment operators like +=, -=, etc
							// or normal binary expressions
							if assign.Tok != token.ASSIGN {
								op = assign.Tok.String() // "+=", "-=", "*=", "/=", etc
							} else if bin, ok := rhs.(*ast.BinaryExpr); ok {
								
								// normal binary expression
								// e.g., a = b + c
								op = bin.Op.String()
								expr = bin
							} else {
								continue
							}

							if arithmeticOps[strings.TrimRight(op, "=")] { // cek aritmatik
								pos := fset.Position(assign.Pos())
								output := exprToString(assign.Lhs[i])
								inputs := extractIdents(expr) // ambil semua identifier di kanan
								exprStr := strings.TrimSpace(safeSlice(srcBytes, expr.Pos(), expr.End()))
								if exprStr == "" {
									exprStr = nodeToString(expr)
								}

								opRec := Operation{
									Func:   fname,
									Pos:    pos.String(),
									Op:     op,
									Output: output,
									Input:  inputs,
									Expr:   exprStr,
								}
								ops = append(ops, opRec)
								s := byFunc[fname]
								s.Operations = append(s.Operations, opRec)
								byFunc[fname] = s
							}
						}
						return true
					}
				// function calls
				if call, ok := n2.(*ast.CallExpr); ok {
					// try to get callee as string
					callee := exprToString(call.Fun)
					pos := fset.Position(call.Pos())
					c := Call{Caller: fname, Callee: callee, Pos: pos.String()}
					calls = append(calls, c)
					// add callee to byFunc summary
					s := byFunc[fname]
					// avoid duplicates
					if !contains(s.Callees, callee) {
						s.Callees = append(s.Callees, callee)
					}
					byFunc[fname] = s
					return true
				}
				return true
				})
			}
			return true
		})
	}

	// sort operations by pos for deterministic output
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].Pos < ops[j].Pos })
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].Pos < calls[j].Pos })

	// normalize byFunc: sort callees and operations
	for k := range byFunc {
		s := byFunc[k]
		sort.SliceStable(s.Operations, func(i, j int) bool { return s.Operations[i].Pos < s.Operations[j].Pos })
		sort.Strings(s.Callees)
		byFunc[k] = s
	}

	res := Result{
		ScannedAt:  time.Now().UTC(),
		Root:       root,
		Operations: ops,
		Calls:      calls,
		ByFunc:     byFunc,
	}
	return res, nil
} 

// parseAndCollectGreedy is a more aggressive version that scans all nodes recursively
// dont try this at home
// do not ever use this in production
// or even in local development
// it will probably break your computer
// you have been warned
// use at your own risk
// seriously
// you have been warned
// this is just for fun
// dont sue me
// ok enough warnings
// enjoy :)
func ParseAndCollectGreedy(root string) (Result, error) {
	files, err := walkGoFiles(root, []string{})
	if err != nil {
		return Result{}, err
	}
	fset := token.NewFileSet()
	ops := []Operation{}
	calls := []Call{}
	byFunc := map[string]Summary{}

	for _, file := range files {
		srcBytes, err := readFile(file)
		if err != nil {
			return Result{}, err
		}
		f, err := parser.ParseFile(fset, file, srcBytes, parser.ParseComments)
		if err != nil {
			return Result{}, err
		}

		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				fname := fn.Name.Name
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					recvType := exprToString(fn.Recv.List[0].Type)
					fname = recvTypeClean(recvType) + "." + fname
				}
				if _, exists := byFunc[fname]; !exists {
					byFunc[fname] = Summary{}
				}

				scanNodeRecursive(fn.Body, fset, srcBytes, fname, &ops, &calls, byFunc)
			}
			return true
		})
	}

	// sort untuk deterministik
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].Pos < ops[j].Pos })
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].Pos < calls[j].Pos })
	for k := range byFunc {
		s := byFunc[k]
		sort.SliceStable(s.Operations, func(i, j int) bool { return s.Operations[i].Pos < s.Operations[j].Pos })
		sort.Strings(s.Callees)
		byFunc[k] = s
	}

	return Result{
		ScannedAt:  time.Now().UTC(),
		Root:       root,
		Operations: ops,
		Calls:      calls,
		ByFunc:     byFunc,
	}, nil
}

func scanNodeRecursive(n ast.Node, fset *token.FileSet, src []byte, fname string, ops *[]Operation, calls *[]Call, byFunc map[string]Summary) {
	if n == nil {
		return
	}

	switch v := n.(type) {
	case *ast.BinaryExpr:
		op := v.Op.String()
		if arithmeticOps[op] {
			pos := fset.Position(v.Pos())
			expr := exprToString(v)
			opRec := Operation{Func: fname, Pos: pos.String(), Op: op, Expr: expr}
			*ops = append(*ops, opRec)
			s := byFunc[fname]
			s.Operations = append(s.Operations, opRec)
			byFunc[fname] = s
		}
	case *ast.CallExpr:
		callee := exprToString(v.Fun)
		pos := fset.Position(v.Pos())
		c := Call{Caller: fname, Callee: callee, Pos: pos.String()}
		*calls = append(*calls, c)
		s := byFunc[fname]
		if !contains(s.Callees, callee) {
			s.Callees = append(s.Callees, callee)
		}
		byFunc[fname] = s
	}

	ast.Inspect(n, func(child ast.Node) bool {
		if child != n {
			scanNodeRecursive(child, fset, src, fname, ops, calls, byFunc)
		}
		return true
	})
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

// helper: convert ast.Expr to a readable string (best-effort)
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
		return "composite{..}"
	case *ast.BasicLit:
		return v.Value
	case *ast.UnaryExpr:
		return v.Op.String() + exprToString(v.X)
	case *ast.BinaryExpr:
		return exprToString(v.X) + " " + v.Op.String() + " " + exprToString(v.Y)
	default:
		return fmt.Sprintf("%T", e)
	}
}

func nodeToString(n ast.Node) string {
	if n == nil {
		return ""
	}
	// best-effort fallback using fmt
	return fmt.Sprintf("%T", n)
}

func recvTypeClean(s string) string {
	// a receiver type might be like (*MyType) or MyType. Keep simple
	s = strings.TrimPrefix(s, "*")
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Output: pretty table to stdout
func PrintTable(res Result) {
	fmt.Println("Arithmetic operations found:\n")
	fmt.Printf("%-40s | %-8s | %-15s | %-25s | %s\n", "Function", "Op", "Output", "Input(s)", "Expression (pos)")
	fmt.Println(strings.Repeat("-", 130))
	for _, o := range res.Operations {
		fmt.Printf("%-40s | %-8s | %-15s | %-25s | %s (%s)\n",
			o.Func, o.Op, o.Output, strings.Join(o.Input, ", "), truncateClean(o.Expr, 50), o.Pos)
	}

	fmt.Println("\nCall graph (caller -> callee):\n")
	fmt.Printf("%-40s -> %s\n", "Caller", "Callee")
	fmt.Println(strings.Repeat("-", 80))
	for _, c := range res.Calls {
		fmt.Printf("%-40s -> %s (%s)\n", c.Caller, c.Callee, c.Pos)
	}
}

func PrintTableChained(res Result) {
	fmt.Println("Arithmetic operations found (grouped by function):\n")

	for fname, f := range res.ByFunc {
		if len(f.Operations) == 0 {
			continue
		}
		fmt.Printf("Function: %s\n", fname)
		for _, o := range f.Operations {
			inputs := strings.Join(o.Input, ", ")
			if len(inputs) > 60 {
				inputs = inputs[:57] + "..."
			}

			expr := truncateClean(o.Expr, 50)

			fmt.Printf("  Op: %-3s | Output: %-20s | Inputs: %-60s | Expr: %s (%s)\n",
				o.Op, o.Output, inputs, expr, o.Pos)
		}
		fmt.Println()
	}

	fmt.Println("\nCall graph (caller -> callee):\n")
	for _, c := range res.Calls {
		fmt.Printf("  %s -> %s (%s)\n", c.Caller, c.Callee, c.Pos)
	}
}

func PrintTableHTMLGrouped(res Result, filename string) error {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
		<html lang="en">
		<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
		<title>Analysis Result</title>
		<style>
		.table-responsive { max-height: 400px; overflow-y: auto; margin-bottom: 20px; }
		.func-header { cursor: pointer; }
		</style>
		</head>
		<body class="p-3">
		<div class="container-fluid">
		<h2>Arithmetic Operations (Grouped by Function)</h2>
	`)

	for funcName, summary := range res.ByFunc {
		funcID := strings.ReplaceAll(funcName, ".", "_")
		sb.WriteString(fmt.Sprintf(`
			<div class="card mb-2">
			<div class="card-header func-header" data-bs-toggle="collapse" data-bs-target="#%s" aria-expanded="true" aria-controls="%s">
				%s
			</div>
			<div id="%s" class="collapse show">
				<div class="table-responsive">
				<table class="table table-striped table-bordered table-sm">
					<thead class="table-dark">
					<tr><th>Op</th><th>Output</th><th>Input(s)</th><th>Expression (pos)</th></tr>
					</thead>
					<tbody>
			`, funcID, funcID, funcName, funcID))

					for _, o := range summary.Operations {
						sb.WriteString(fmt.Sprintf(
							"<tr><td>%s</td><td>%s</td><td>%s</td><td>%s (%s)</td></tr>\n",
							o.Op, o.Output, strings.Join(o.Input, ", "), o.Expr, o.Pos))
					}

					sb.WriteString(`
					</tbody>
				</table>
				</div>
			</div>
			</div>
			`)
	}

	sb.WriteString("<h2>Call Graph (caller -> callee)</h2>\n")
	sb.WriteString(`<div class="table-responsive"><table class="table table-striped table-bordered table-sm"><thead class="table-dark"><tr><th>Caller</th><th>Callee</th><th>Position</th></tr></thead><tbody>`)
	for _, c := range res.Calls {
		sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", c.Caller, c.Callee, c.Pos))
	}
	sb.WriteString("</tbody></table></div>\n")

	sb.WriteString(`
		</div>
		<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
		</body>
		</html>
	`)

	err := os.WriteFile(filename, []byte(sb.String()), 0644)
	if err != nil {
		return err
	}

	openBrowser(filename)
	return nil
}

// openBrowser tries to open the file in default browser
func openBrowser(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", path)
	default: // linux
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}


func truncateClean(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// Output JSON
func PrintJSON(res Result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		log.Fatal(err)
	}
}

// Output PlantUML sequence diagram: actors are functions; when caller calls callee, show arrow; annotate functions with operations
func PrintPlantUML(res Result) {
	// header
	fmt.Println("@startuml")
	fmt.Println("title Arithmetic trace for: ", res.Root)
	// define participants for each function found
	funcs := map[string]bool{}
	for f := range res.ByFunc {
		funcs[f] = true
	}
	for _, c := range res.Calls {
		funcs[c.Caller] = true
		funcs[c.Callee] = true
	}
	// sanitize names for PlantUML (no dots as actor names) -> use alias mapping
	aliases := map[string]string{}
	i := 0
	keys := []string{}
	for k := range funcs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		i++
		alias := fmt.Sprintf("F%d", i)
		aliases[k] = alias
		// participant with label
		label := k
		fmt.Printf("participant %s as \"%s\"\n", alias, label)
	}

	// annotate each function with its operations as notes
	for _, f := range keys {
		opers := res.ByFunc[f].Operations
		if len(opers) == 0 {
			continue
		}
		fmt.Printf("note over %s\n", aliases[f])
		for _, o := range opers {
			line := fmt.Sprintf("%s %s = %s (%s) (%s)",
				o.Op,
				strings.Join(o.Input, ", "),
				o.Output,
				truncateClean(o.Expr, 60),
				o.Pos,
			)
			fmt.Println(line)
		}
		fmt.Println("end note")
	}

	// now calls
	for _, c := range res.Calls {
		ca := aliases[c.Caller]
		cb := aliases[c.Callee]
		if ca == "" || cb == "" {
			continue
		}
		fmt.Printf("%s -> %s: call (%s)\n", ca, cb, truncateClean(c.Pos, 30))
	}

	fmt.Println("@enduml")
}

func filterResult(res Result, funcFilter string, pkgFilter string) Result {
	// filter operations
	filteredOps := []Operation{}
	for _, o := range res.Operations {
		if funcFilter != "" && !strings.Contains(o.Func, funcFilter) {
			continue
		}
		if pkgFilter != "" && !strings.Contains(o.Pos, pkgFilter) {
			continue
		}
		filteredOps = append(filteredOps, o)
	}
	// filter calls
	filteredCalls := []Call{}
	for _, c := range res.Calls {
		if funcFilter != "" && !(strings.Contains(c.Caller, funcFilter) || strings.Contains(c.Callee, funcFilter)) {
			continue
		}
		if pkgFilter != "" && !strings.Contains(c.Pos, pkgFilter) {
			continue
		}
		filteredCalls = append(filteredCalls, c)
	}
	// rebuild ByFunc
	filteredByFunc := map[string]Summary{}
	for f, s := range res.ByFunc {
		if funcFilter != "" && !strings.Contains(f, funcFilter) {
			continue
		}
		filteredByFunc[f] = s
	}
	res.Operations = filteredOps
	res.Calls = filteredCalls
	res.ByFunc = filteredByFunc
	return res
}

func extractIdents(expr ast.Expr) []string {
	var idents []string

	var walk func(e ast.Expr)
	walk = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.Ident:
			idents = append(idents, v.Name)
		case *ast.SelectorExpr:
			base := exprToString(v.X)
			idents = append(idents, fmt.Sprintf("%s.%s", base, v.Sel.Name))
		case *ast.CallExpr:
			for _, arg := range v.Args {
				walk(arg)
			}
		case *ast.BinaryExpr:
			walk(v.X)
			walk(v.Y)
		case *ast.ParenExpr:
			walk(v.X)
		case *ast.UnaryExpr:
			walk(v.X)
		case *ast.IndexExpr:
			walk(v.X)
			walk(v.Index)
		// need to handle more expr types as needed
		}
	}

	walk(expr)
	return idents
}