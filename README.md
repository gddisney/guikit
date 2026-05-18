# GUIKit

A high-performance, full-stack Go web framework featuring reactive Live-Components, a custom GML markup engine, and an embedded database.

## Features

* **Reactive Live-Components:** Real-time DOM patching over thread-safe WebSockets, inspired by LiveView architectures.
* **GML Markup Engine:** A custom lexical parser and AST evaluator for a clean, component-driven template syntax.
* **Embedded Database:** Deep integration with `ultimate_db` for seamless persistence and session management without external dependencies.
* **Production-Grade Security:** Built-in Content Security Policy (CSP) noncing, path-traversal guards, and strict HTTP headers to prevent XSS and file-system exploits.
* **In-Memory Caching:** High-performance template caching to eliminate disk I/O on active routes.
* **Virtual File System:** Package your entire application (templates, assets, and database) into a single `.gweb` zip archive for trivial deployment.

## Installation

GUIKit requires Go 1.23+. Initialize your module and fetch GUIKit alongside its custom database dependency:

```bash
go mod init guikit
go get github.com/gddisney/ultimate_db]
go mod tidy

```

## Quick Start

### 1. Initialize the Engine (`main.go`)

```go
package main

import (
	"log"
	"guikit"
)

func main() {
	// Initialize the framework with DB and WAL file paths
	engine, err := guikit.New("app.db", "app.wal")
	if err != nil {
		log.Fatalf("Failed to initialize GUIKit: %v", err)
	}

	// Define a protected route
	engine.Get("/", func(c *guikit.Context) {
		c.Data["Title"] = "Welcome to GUIKit"
		engine.Render(c, "views/index")
	})

	// Run the CLI / Server
	engine.Run()
}

```

### 2. Create a View (`views/index.gml`)

```html
<wrapper "views/layout.gml">
	<h1 class="text-2xl font-bold">{{ .Title }}</h1>
	<p>This is a fast, secure, and reactive web interface running on GUIKit.</p>
</wrapper>

```

## CLI Usage

GUIKit includes a built-in command-line interface for packing and serving your application seamlessly.

### Serve Locally

Run your application in development mode on a specified port:

```bash
go run main.go serve 8080

```

### Pack for Production

Bundle your entire application into a `.gweb` virtual file system archive:

```bash
go run main.go pack . build/app.gweb

```

### Serve an Archive

Deploy by serving assets and routes directly out of a packed `.gweb` file:

```bash
go run main.go serve build/app.gweb 8080

```

## Security & Architecture

GUIKit is hardened out-of-the-box for production stability:

* **CSP Noncing:** Every request generates a unique cryptographic nonce applied to all inline scripts via internal middleware to mitigate XSS vulnerabilities.
* **Path Traversal Prevention:** The GML engine strictly sanitizes all `<wrapper>` and `<import>` paths to restrict directory traversal escapes.
* **Concurrent Write Safety:** WebSocket connections are entirely thread-safe to prevent memory corruption and race condition panics under high traffic.
* **Dead-Connection Sweeping:** Automatic heartbeats (ping/pong) and failed client pruning cleanly sweep resources behind load balancers.

```

```
