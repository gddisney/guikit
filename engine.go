package guikit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"text/scanner"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/gorilla/websocket"
)

// ==========================================
// 1. Global Configurations & Virtual FS
// ==========================================

var AppFS fs.FS

var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

var (
	rxH3      = regexp.MustCompile(`(?m)^### (.*)$`)
	rxH2      = regexp.MustCompile(`(?m)^## (.*)$`)
	rxH1      = regexp.MustCompile(`(?m)^# (.*)$`)
	rxBold    = regexp.MustCompile(`\*\*(.*?)\*\*`)
	rxItalic  = regexp.MustCompile(`\*(.*?)\*`)
	rxMention = regexp.MustCompile(`@([a-zA-Z0-9_][a-zA-Z0-9_-]*)`)
	rxHashtag = regexp.MustCompile(`\B#([a-zA-Z0-9_]+)`)
)

type contextKey string
const nonceKey contextKey = "csp-nonce"

type SessionRecord struct {
	ID         uint64 `json:"id"`
	SessionKey string `json:"session_key"`
	Value      string `json:"value"`
}

// ==========================================
// 2. Types & Interfaces
// ==========================================

type ThreadSafeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *ThreadSafeConn) WriteJSON(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteJSON(v)
}

func (s *ThreadSafeConn) WriteMessage(messageType int, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(messageType, data)
}

func (s *ThreadSafeConn) Close() error {
	return s.conn.Close()
}

type Context struct {
	W        http.ResponseWriter
	R        *http.Request
	Data     map[string]interface{}
	CspNonce string
}

type LiveComponent interface {
	ID() string
	Render() string
}

type IncomingEvent struct {
	CompID string            `json:"id"`
	Event  string            `json:"event"`
	Data   map[string]string `json:"data"`
}

type OutgoingPatch struct {
	CompID string `json:"id"`
	HTML   string `json:"html"`
}

type GUIKit struct {
	DB  *ultimate_db.DB
	ORM *ultimate_db.ORM
	Mux *http.ServeMux

	globalData   map[string]interface{}
	globalDataMu sync.RWMutex

	components   map[string]LiveComponent
	componentsMu sync.RWMutex

	upgrader  websocket.Upgrader
	clients   map[*ThreadSafeConn]bool
	clientsMu sync.Mutex

	templateCache map[string]*template.Template
	cacheMu       sync.RWMutex
}

// ==========================================
// 3. Engine Initialization & Routing
// ==========================================

func New(db *ultimate_db.DB, orm *ultimate_db.ORM) (*GUIKit, error) {
	if db == nil || orm == nil {
		return nil, errors.New("cannot initialize GUIKit without active DB and ORM subsystems")
	}

	if AppFS == nil {
		AppFS = os.DirFS(".")
	}

	gk := &GUIKit{
		DB:            db,
		ORM:           orm,
		Mux:           http.NewServeMux(),
		globalData:    make(map[string]interface{}),
		components:    make(map[string]LiveComponent),
		clients:       make(map[*ThreadSafeConn]bool),
		templateCache: make(map[string]*template.Template),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}

	gk.Mux.HandleFunc("GET /ws", gk.HandleWebSocket)
	gk.Mux.HandleFunc("GET /guikit.js", gk.serveJS)

	return gk, nil
}

func (gk *GUIKit) SetGlobal(key string, value interface{}) {
	gk.globalDataMu.Lock()
	defer gk.globalDataMu.Unlock()
	gk.globalData[key] = value
}

func (gk *GUIKit) GetGlobal(key string) (interface{}, bool) {
	gk.globalDataMu.RLock()
	defer gk.globalDataMu.RUnlock()
	val, ok := gk.globalData[key]
	return val, ok
}

func (gk *GUIKit) GetGlobalMap() map[string]interface{} {
	gk.globalDataMu.RLock()
	defer gk.globalDataMu.RUnlock()
	snapshot := make(map[string]interface{}, len(gk.globalData))
	for k, v := range gk.globalData {
		snapshot[k] = v
	}
	return snapshot
}

func (gk *GUIKit) RegisterComponent(comp LiveComponent) {
	gk.componentsMu.Lock()
	defer gk.componentsMu.Unlock()
	gk.components[comp.ID()] = comp
}

func (gk *GUIKit) Get(pattern string, handler func(c *Context)) {
	gk.Mux.HandleFunc("GET "+pattern, gk.SecureHeaders(func(w http.ResponseWriter, r *http.Request) {
		handler(&Context{W: w, R: r, Data: make(map[string]interface{}), CspNonce: gk.GetNonce(r)})
	}))
}

func (gk *GUIKit) Post(pattern string, handler func(c *Context)) {
	gk.Mux.HandleFunc("POST "+pattern, gk.SecureHeaders(func(w http.ResponseWriter, r *http.Request) {
		handler(&Context{W: w, R: r, Data: make(map[string]interface{}), CspNonce: gk.GetNonce(r)})
	}))
}

func (gk *GUIKit) SecureHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := make([]byte, 16)
		if _, err := rand.Read(token); err != nil {
			http.Error(w, "Internal Security Failure", http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(token)
		
		r = r.WithContext(context.WithValue(r.Context(), nonceKey, nonce))

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		csp := fmt.Sprintf("default-src 'self'; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-%s'; img-src * data: blob:;", nonce)
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		next.ServeHTTP(w, r)
	}
}

func (gk *GUIKit) GetNonce(r *http.Request) string {
	if nonce, ok := r.Context().Value(nonceKey).(string); ok {
		return nonce
	}
	return ""
}

// ==========================================
// 4. Session Management Layer
// ==========================================

func (gk *GUIKit) SetSession(id uint64, key string, value string) error {
	rec := SessionRecord{
		ID:         id,
		SessionKey: key,
		Value:      value,
	}
	return gk.ORM.Insert(rec)
}

func (gk *GUIKit) GetSession(id uint64) string {
	var rec SessionRecord
	if err := gk.ORM.Find(id, &rec); err != nil {
		return ""
	}
	return rec.Value
}

// ==========================================
// 5. WebSocket Router
// ==========================================

func (gk *GUIKit) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	rawConn, err := gk.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket Upgrade Error:", err)
		return
	}

	conn := &ThreadSafeConn{conn: rawConn}

	gk.clientsMu.Lock()
	gk.clients[conn] = true
	gk.clientsMu.Unlock()

	done := make(chan struct{})

	defer func() {
		close(done)
		gk.clientsMu.Lock()
		delete(gk.clients, conn)
		gk.clientsMu.Unlock()
		_ = conn.Close()
	}()

	const pongWait = 60 * time.Second
	const pingPeriod = (pongWait * 9) / 10

	rawConn.SetReadLimit(512 * 1024)
	_ = rawConn.SetReadDeadline(time.Now().Add(pongWait))
	rawConn.SetPongHandler(func(string) error {
		_ = rawConn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	for {
		var msg IncomingEvent
		err := rawConn.ReadJSON(&msg)
		if err != nil {
			break
		}

		gk.componentsMu.RLock()
		comp, exists := gk.components[msg.CompID]
		gk.componentsMu.RUnlock()

		if !exists {
			continue
		}

		val := reflect.ValueOf(comp)
		method := val.MethodByName(msg.Event)
		
		if method.IsValid() && method.Kind() == reflect.Func {
			if method.Type().NumIn() == 1 && method.Type().In(0) == reflect.TypeOf(msg.Data) {
				method.Call([]reflect.Value{reflect.ValueOf(msg.Data)})
			} else if method.Type().NumIn() == 0 {
				method.Call(nil)
			} else {
				continue
			}

			rawGML := comp.Render()
			htmlOut := gk.compileGMLString(rawGML, gk.GetGlobalMap())

			patch := OutgoingPatch{
				CompID: msg.CompID,
				HTML:   htmlOut,
			}
			_ = conn.WriteJSON(patch)
		}
	}
}

func (gk *GUIKit) Broadcast(event string, payload interface{}) {
	message := map[string]interface{}{
		"event":   event,
		"payload": payload,
	}

	gk.clientsMu.Lock()
	var failedClients []*ThreadSafeConn

	for client := range gk.clients {
		if err := client.WriteJSON(message); err != nil {
			failedClients = append(failedClients, client)
		}
	}

	for _, client := range failedClients {
		_ = client.Close()
		delete(gk.clients, client)
	}
	gk.clientsMu.Unlock()
}

// ==========================================
// 6. Rendering, CLI & GML Engine
// ==========================================

func (gk *GUIKit) Render(c *Context, viewPath string) {
	if c.Data == nil {
		c.Data = make(map[string]interface{})
	}
	gk.cacheMu.RLock()
	tmpl, cached := gk.templateCache[viewPath]
	gk.cacheMu.RUnlock()

	if !cached {
		scriptInput, err := fs.ReadFile(AppFS, viewPath+".gml")
		if err != nil {
			http.Error(c.W, "View resource not located", http.StatusNotFound)
			return
		}

		parser := NewParser(string(scriptInput))
		nodes := parser.Parse()

		var rawHTML strings.Builder
		for _, node := range nodes {
			rawHTML.WriteString(node.Eval() + "\n")
		}

		funcMap := template.FuncMap{
			"safeSlice": func(s string, i, j int) string {
				rs := []rune(s)
				if i < 0 { i = 0 }
				if j > len(rs) { j = len(rs) }
				if i > j { return "" }
				return string(rs[i:j])
			},
			"initial": func(s string) string {
				rs := []rune(s)
				if len(rs) > 0 {
					return strings.ToUpper(string(rs[0]))
				}
				return "W"
			},
			"markdown": func(s string) template.HTML {
				return template.HTML(gk.formatMarkdown(s))
			},
		}

		var errTmpl error
		tmpl, errTmpl = template.New(viewPath).Funcs(funcMap).Parse(rawHTML.String())
		if errTmpl != nil {
			http.Error(c.W, "Template Compilation Failure", http.StatusInternalServerError)
			return
		}

		gk.cacheMu.Lock()
		gk.templateCache[viewPath] = tmpl
		gk.cacheMu.Unlock()
	}

	globalState := gk.GetGlobalMap()
	for k, v := range globalState {
		c.Data[k] = v
	}
	c.Data["CspNonce"] = c.CspNonce

	jsonData, err := fs.ReadFile(AppFS, viewPath+".json")
	if err == nil {
		_ = json.Unmarshal(jsonData, &c.Data)
	}

	var finalOutput bytes.Buffer
	if err := tmpl.Execute(&finalOutput, c.Data); err != nil {
		http.Error(c.W, "Template Execution Failure", http.StatusInternalServerError)
		return
	}

	c.W.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = c.W.Write(finalOutput.Bytes())
}

func (gk *GUIKit) compileGMLString(script string, data map[string]interface{}) string {
	if strings.TrimSpace(script) == "" {
		return ""
	}

	parser := NewParser(script)
	nodes := parser.Parse()

	var rawHTML strings.Builder
	for _, node := range nodes {
		rawHTML.WriteString(node.Eval() + "\n")
	}

	funcMap := template.FuncMap{
		"safeSlice": func(s string, i, j int) string {
			rs := []rune(s)
			if i < 0 { i = 0 }
			if j > len(rs) { j = len(rs) }
			if i > j { return "" }
			return string(rs[i:j])
		},
		"initial": func(s string) string {
			rs := []rune(s)
			if len(rs) > 0 { return strings.ToUpper(string(rs[0])) }
			return "W"
		},
		"markdown": func(s string) template.HTML {
			return template.HTML(gk.formatMarkdown(s))
		},
	}

	tmpl, err := template.New("live-runtime").Funcs(funcMap).Parse(rawHTML.String())
	if err != nil {
		return `<div style="color:red;">Parse Fault</div>`
	}

	var finalOutput bytes.Buffer
	if err := tmpl.Execute(&finalOutput, data); err != nil {
		return `<div style="color:red;">Execution Fault</div>`
	}

	return finalOutput.String()
}

func (gk *GUIKit) formatMarkdown(s string) string {
	content := html.EscapeString(s)
	content = rxH3.ReplaceAllString(content, "<h3>$1</h3>")
	content = rxH2.ReplaceAllString(content, "<h2>$1</h2>")
	content = rxH1.ReplaceAllString(content, "<h1>$1</h1>")
	content = rxBold.ReplaceAllString(content, "<strong>$1</strong>")
	content = rxItalic.ReplaceAllString(content, "<em>$1</em>")
	content = rxMention.ReplaceAllString(content, `<a href="/u/$1" style="color:rgb(29, 155, 240); text-decoration:none; font-weight:bold;">@$1</a>`)
	content = rxHashtag.ReplaceAllString(content, `<a href="/search?q=%23$1" style="color:rgb(29, 155, 240); text-decoration:none; font-weight:bold;">#$1</a>`)
	return strings.ReplaceAll(content, "\n\n", "<br><br>")
}

func (gk *GUIKit) Run() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "pack":
			target, out := ".", "app.gweb"
			if len(os.Args) >= 3 { target = os.Args[2] }
			if len(os.Args) >= 4 { out = os.Args[3] }
			_ = gk.packGWeb(target, out)
			return
		case "serve":
			port := "8080"
			if len(os.Args) >= 3 {
				if strings.HasSuffix(os.Args[2], ".gweb") {
					z, err := zip.OpenReader(os.Args[2])
					if err != nil { log.Fatal(err) }
					defer z.Close()
					AppFS = z
					if len(os.Args) >= 4 { port = os.Args[3] }
				} else {
					port = os.Args[2]
					AppFS = os.DirFS(".")
				}
			}
			gk.startServer(port)
			return
		}
	}
}

func (gk *GUIKit) startServer(port string) {
	if AppFS == nil {
		AppFS = os.DirFS(".")
	}
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      gk.Mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func (gk *GUIKit) packGWeb(targetDir, outPath string) error {
	outFile, err := os.Create(outPath)
	if err != nil { return err }
	defer outFile.Close()

	w := zip.NewWriter(outFile)
	defer w.Close()

	return filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() { return err }
		if strings.HasSuffix(path, ".db") || strings.HasSuffix(path, ".wal") || strings.HasSuffix(path, ".gweb") {
			return nil
		}
		relPath, err := filepath.Rel(targetDir, path)
		if err != nil { return err }
		f, err := w.Create(filepath.ToSlash(relPath))
		if err != nil { return err }
		content, err := os.ReadFile(path)
		if err != nil { return err }
		_, err = f.Write(content)
		return err
	})
}

// ==========================================
// 7. AST (Abstract Syntax Tree) Nodes
// ==========================================

type Node interface {
	Eval() string
}

type Element struct {
	Tag        string
	Attributes map[string]string
	Children   []Node
}

func (e Element) Eval() string {
	tag := strings.ToLower(e.Tag)

	if tag == "wrapper" {
		if len(e.Children) == 0 { return "" }
		layoutFile := filepath.ToSlash(filepath.Clean(e.Children[0].Eval()))
		if strings.HasPrefix(layoutFile, "../") || strings.Contains(layoutFile, "..") {
			return "" 
		}

		var content strings.Builder
		for _, child := range e.Children[1:] {
			content.WriteString(child.Eval())
		}

		layoutContent, err := fs.ReadFile(AppFS, layoutFile)
		if err != nil { return "" }

		parser := NewParser(string(layoutContent))
		var layoutHTML strings.Builder
		for _, n := range parser.Parse() {
			layoutHTML.WriteString(n.Eval())
		}
		return strings.Replace(layoutHTML.String(), "<slot />", content.String(), 1)
	}

	if tag == "slot" { return "<slot />" }

	if tag == "import" {
		if len(e.Children) == 0 { return "" }
		filename := filepath.ToSlash(filepath.Clean(e.Children[0].Eval()))
		if strings.HasPrefix(filename, "../") || strings.Contains(filename, "..") {
			return ""
		}

		content, err := fs.ReadFile(AppFS, filename)
		if err != nil { return "" }

		var builder strings.Builder
		for _, node := range NewParser(string(content)).Parse() {
			builder.WriteString(node.Eval())
		}
		return builder.String()
	}

	if tag == "rule" {
		if len(e.Children) == 0 { return "" }
		var css strings.Builder
		css.WriteString(fmt.Sprintf("%s {\n", e.Children[0].Eval()))
		for _, child := range e.Children[1:] {
			css.WriteString(fmt.Sprintf("\t%s;\n", child.Eval()))
		}
		css.WriteString("}\n")
		return css.String()
	}

	if tag == "markdown" {
		content := ""
		if len(e.Children) > 0 { content = e.Children[0].Eval() }

		if strings.HasPrefix(content, "{{") && strings.HasSuffix(content, "}}") {
			inner := strings.TrimSpace(content[2 : len(content)-2])
			return fmt.Sprintf("{{ markdown %s }}", inner)
		}

		content = html.EscapeString(content)
		content = rxH3.ReplaceAllString(content, "<h3>$1</h3>")
		content = rxH2.ReplaceAllString(content, "<h2>$1</h2>")
		content = rxH1.ReplaceAllString(content, "<h1>$1</h1>")
		content = rxBold.ReplaceAllString(content, "<strong>$1</strong>")
		content = rxItalic.ReplaceAllString(content, "<em>$1</em>")
		content = rxMention.ReplaceAllString(content, `<a href="/u/$1" style="color:rgb(29, 155, 240); text-decoration:none; font-weight:bold;">@$1</a>`)
		content = rxHashtag.ReplaceAllString(content, `<a href="/search?q=%23$1" style="color:rgb(29, 155, 240); text-decoration:none; font-weight:bold;">#$1</a>`)

		return strings.ReplaceAll(content, "\n\n", "<br><br>")
	}

	var builder strings.Builder
	builder.WriteString("<" + tag)
	for key, val := range e.Attributes {
		builder.WriteString(fmt.Sprintf(` %s="%s"`, key, strings.ReplaceAll(val, `"`, `&quot;`)))
	}

	if voidElements[tag] {
		builder.WriteString(" />")
		return builder.String()
	}

	builder.WriteString(">")
	if tag == "style" || tag == "script" { builder.WriteString("\n") }

	for _, child := range e.Children {
		if child != nil { builder.WriteString(child.Eval()) }
	}

	if tag == "style" || tag == "script" { builder.WriteString("\n") }
	builder.WriteString("</" + tag + ">")
	return builder.String()
}

type Text string

func (t Text) Eval() string { return string(t) }

// ==========================================
// 8. The Lexical Parser
// ==========================================

type Parser struct {
	s   scanner.Scanner
	tok rune
}

func NewParser(src string) *Parser {
	var s scanner.Scanner
	s.Init(strings.NewReader(src))
	s.Error = func(s *scanner.Scanner, msg string) {}
	s.IsIdentRune = func(ch rune, i int) bool {
		return ch == '_' || ch == '-' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
	}

	p := &Parser{s: s}
	p.next()
	return p
}

func (p *Parser) next() { p.tok = p.s.Scan() }

func (p *Parser) Parse() []Node {
	var nodes []Node
	for p.tok != scanner.EOF {
		if node := p.parseExpr(); node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '`' && s[len(s)-1] == '`')) {
		return s[1 : len(s)-1]
	}
	return s
}

func (p *Parser) parseExpr() Node {
	switch p.tok {
	case scanner.Ident:
		tag := p.s.TokenText()
		p.next()

		attrs := make(map[string]string)
		for p.tok == '.' || p.tok == '#' || p.tok == ':' {
			modifier := p.tok
			p.next()

			if modifier == '.' {
				className := stripQuotes(p.s.TokenText())
				p.next()
				attrs["class"] = strings.TrimSpace(attrs["class"] + " " + className)
			} else if modifier == '#' {
				attrs["id"] = stripQuotes(p.s.TokenText())
				p.next()
			} else if modifier == ':' {
				attrName := stripQuotes(p.s.TokenText())
				p.next()
				attrValue := "true"

				if p.tok == '.' {
					p.next()
					attrValue = stripQuotes(p.s.TokenText())
					p.next()
				}

				if attrName == "class" {
					attrs["class"] = strings.TrimSpace(attrs["class"] + " " + attrValue)
				} else {
					attrs[attrName] = attrValue
				}
			}
		}

		var children []Node
		if p.tok == '(' {
			p.next()
			for p.tok != ')' && p.tok != scanner.EOF {
				if arg := p.parseExpr(); arg != nil {
					children = append(children, arg)
				}
				if p.tok == ',' { p.next() }
			}
			if p.tok == ')' { p.next() }
		}
		return Element{Tag: tag, Attributes: attrs, Children: children}

	case scanner.String, scanner.RawString:
		val := stripQuotes(p.s.TokenText())
		p.next()
		return Text(val)

	default:
		p.next()
		return nil
	}
}

// ==========================================
// 9. Built-in Client Framework JS
// ==========================================

func (gk *GUIKit) serveJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte(guikitJS))
}

const guikitJS = `
class GUIKitClient {
    constructor() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(protocol + '//' + window.location.host + '/ws');
        this.initWebSocket();
        this.initEventListeners();
    }
    initWebSocket() {
        this.ws.onmessage = (event) => {
            const patch = JSON.parse(event.data);
            if (patch.id && patch.html) {
                const targetElement = document.getElementById(patch.id);
                if (targetElement) { targetElement.outerHTML = patch.html; }
            }
        };
        this.ws.onclose = () => { setTimeout(() => window.location.reload(), 2000); };
    }
    initEventListeners() {
        document.addEventListener('click', (e) => {
            const trigger = e.target.closest('[gk-click]');
            if (!trigger) return;
            e.preventDefault();
            const componentRoot = trigger.closest('[id]');
            if (!componentRoot) return;
            this.ws.send(JSON.stringify({
                id: componentRoot.id,
                event: trigger.getAttribute('gk-click'),
                data: {} 
            }));
        });
    }
}
document.addEventListener("DOMContentLoaded", () => { window.gk = new GUIKitClient(); });`
