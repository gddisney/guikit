package guikit

import (
"net/http"
"net/http/httptest"
"os"
"path/filepath"
"strings"
"testing"

"github.com/0TrustCloud/ultimate_db"
)

func setupMockDatabase(t *testing.T) (*ultimate_db.DB, *ultimate_db.ORM, func()) {
dbPath := "guikit_test.db"
walPath := "guikit_test.wal"

_ = os.Remove(dbPath)
_ = os.Remove(walPath)

device, err := ultimate_db.NewOSFileDevice(dbPath)
if err != nil {
t.Fatalf("Failed to initialize storage file descriptor: %v", err)
}

disk := ultimate_db.NewDiskManager(device)
evictor := ultimate_db.NewLRUEvictionPolicy()
metrics := ultimate_db.NewAtomicMetrics()
bp := ultimate_db.NewBufferPool(disk, 10, evictor, metrics)

wal, err := ultimate_db.NewBatchingWAL(walPath)
if err != nil {
t.Fatalf("Failed to instantiate WAL log system: %v", err)
}

db := ultimate_db.NewDB(bp, wal, metrics)
rootPage, err := bp.NewPage()
if err != nil {
t.Fatalf("Failed to format base page index allocations: %v", err)
}
bp.UnpinPage(rootPage.ID, true)

index := ultimate_db.NewMemIndex()
orm := ultimate_db.NewORM(db, index, nil, walPath)

cleanup := func() {
_ = db.Close()
_ = os.Remove(dbPath)
_ = os.Remove(walPath)
}

return db, orm, cleanup
}

func TestGUIKit_SecureHeadersMiddleware(t *testing.T) {
db, orm, cleanup := setupMockDatabase(t)
defer cleanup()

gk, err := New(db, orm)
if err != nil {
t.Fatalf("Failed to spin up GUIKit: %v", err)
}

gk.Get("/dashboard", func(c *Context) {
if c.CspNonce == "" {
t.Error("Security context error: Nonce trace vector missing on target HTTP handler context")
}
_, _ = c.W.Write([]byte("OK"))
})

req := httptest.NewRequest("GET", "/dashboard", nil)
rr := httptest.NewRecorder()

gk.Mux.ServeHTTP(rr, req)

if rr.Code != http.StatusOK {
t.Errorf("Unexpected status code returned: got %d, expected 200", rr.Code)
}

if rr.Header().Get("X-Frame-Options") != "DENY" {
t.Error("Missing X-Frame-Options clickjacking mitigation vector")
}
if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
t.Error("Missing content-type sniffing protection banner")
}

csp := rr.Header().Get("Content-Security-Policy")
if !strings.Contains(csp, "script-src 'self' 'nonce-") {
t.Errorf("Improper Content-Security-Policy format structured: %s", csp)
}
}

func TestGUIKit_SessionLayerORM(t *testing.T) {
db, orm, cleanup := setupMockDatabase(t)
defer cleanup()

gk, err := New(db, orm)
if err != nil {
t.Fatalf("Failed to spin up GUIKit: %v", err)
}

sessionID := uint64(888)
key := "auth_token_hash"
val := "9b7a4c11de36a281"

err = gk.SetSession(sessionID, key, val)
if err != nil {
t.Fatalf("Session persistence write failure through ORM: %v", err)
}

fetchedVal := gk.GetSession(sessionID)
if fetchedVal != val {
t.Errorf("Data lookup verification anomaly. Expected value '%s', retrieved '%s'", val, fetchedVal)
}
}

func TestGUIKit_GMLEngineCompilation(t *testing.T) {
db, orm, cleanup := setupMockDatabase(t)
defer cleanup()

gk, err := New(db, orm)
if err != nil {
t.Fatalf("Failed to spin up GUIKit: %v", err)
}

tmpViewsDir := t.TempDir()
viewSubDir := filepath.Join(tmpViewsDir, "views")
if err := os.Mkdir(viewSubDir, 0755); err != nil {
t.Fatalf("Failed to build view testing directory footprint: %v", err)
}

// Format exactly like your index.gml code layout patterns
gmlScript := `div.card#incident-frame:gk-click."TriggerAlert" (
span.title ("Active Threat Intel Profile"),
markdown ("### Critical Alert")
)`

filePath := filepath.Join(viewSubDir, "threat.gml")
if err := os.WriteFile(filePath, []byte(gmlScript), 0644); err != nil {
t.Fatalf("Failed to write mock view template to workspace layout file: %v", err)
}

AppFS = os.DirFS(tmpViewsDir)

req := httptest.NewRequest("GET", "/threat", nil)
rr := httptest.NewRecorder()
ctx := &Context{
W:    rr,
R:    req,
Data: make(map[string]interface{}),
}

gk.Render(ctx, "views/threat")

if rr.Code != http.StatusOK {
t.Fatalf("Render processing aborted with failure code: %d", rr.Code)
}

body := rr.Body.String()

// Semantic parsing validation checks rather than fragile positional strings
if !strings.Contains(body, `id="incident-frame"`) || !strings.Contains(body, `gk-click="TriggerAlert"`) || !strings.Contains(body, `class="card"`) {
t.Errorf("GML AST Engine generated unexpected tag wrapper elements: %s", body)
}

if !strings.Contains(body, `<h3>Critical Alert</h3>`) {
t.Errorf("Custom GML markdown processing failed to parse headers accurately: %s", body)
}
}
