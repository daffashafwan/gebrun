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
	"path/filepath"
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
func walkGoFiles(root string) ([]string, error) {
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
		if filepath.Ext(path) == ".go" && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// parseAndCollect scans files and returns operations and calls
func ParseAndCollect(root string) (Result, error) {
	files, err := walkGoFiles(root)
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
					if bin, ok := n2.(*ast.BinaryExpr); ok {
						op := bin.Op.String()
						if arithmeticOps[op] {
							pos := fset.Position(bin.Pos())
							expr := strings.TrimSpace(safeSlice(srcBytes, bin.Pos(), bin.End()))
						// Fall back to building expr string
						if expr == "" {
							expr = nodeToString(bin)
						}
						opRec := Operation{Func: fname, Pos: pos.String(), Op: op, Expr: expr}
						ops = append(ops, opRec)
						// add to byFunc
						s := byFunc[fname]
						s.Operations = append(s.Operations, opRec)
						byFunc[fname] = s
						return true
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
	fmt.Printf("%-40s | %-8s | %s\n", "Function", "Op", "Expression (pos)")
	fmt.Println(strings.Repeat("-", 110))
	for _, o := range res.Operations {
		fmt.Printf("%-40s | %-8s | %s (%s)\n", o.Func, o.Op, truncateClean(o.Expr, 60), o.Pos)
	}

	fmt.Println("\nCall graph (caller -> callee):\n")
	fmt.Printf("%-40s -> %s\n", "Caller", "Callee")
	fmt.Println(strings.Repeat("-", 80))
	for _, c := range res.Calls {
		fmt.Printf("%-40s -> %s (%s)\n", c.Caller, c.Callee, c.Pos)
	}
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
			line := fmt.Sprintf("%s %s (%s)", o.Op, truncateClean(o.Expr, 80), o.Pos)
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