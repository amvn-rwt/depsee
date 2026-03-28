# depsee

`depsee` is a local-first SBOM explorer for CycloneDX files. It reads a software bill of materials, builds a dependency graph, enriches packages with NVD CVE data, and serves a small web UI for visualizing dependency risk.

The goal is simple: make SBOMs easier to understand than a flat list of packages or CVEs.

## Features

- Parse CycloneDX JSON SBOM files
- Build a directed dependency graph from `components` and `dependencies`
- Serve a local web UI and `/api/graph` JSON endpoint
- Enrich nodes with NVD CVEs using package URL to CPE matching
- Compute blast radius, dependent count, severity, and risk score
- Keep NVD requests rate-limited, retried, and cached in memory

## Status

`depsee` is an early-stage project. The core graph pipeline is working, and the web UI is served locally, but the project is still evolving.

## Installation

### Prerequisites

- Go `1.25+`

### Run from source

```bash
git clone https://github.com/amvn-rwt/depsee.git
cd depsee
go run ./cmd/depsee -file path/to/service.sbom.json
```

### Build a binary

```bash
go build -o depsee ./cmd/depsee
```

On Windows:

```bash
go build -o depsee.exe ./cmd/depsee
```

## Quick Start

### CLI mode

Print a basic adjacency list from an SBOM:

```bash
go run ./cmd/depsee -file path/to/service.sbom.json
```

### Web mode

Start the local server:

```bash
go run ./cmd/depsee -serve -file path/to/service.sbom.json
```

Then open:

- `http://127.0.0.1:8080/`
- `http://127.0.0.1:8080/api/graph`

### Skip NVD enrichment

If you want to work offline or avoid network calls:

```bash
go run ./cmd/depsee -serve -file path/to/service.sbom.json -skip-nvd
```

## Usage

```bash
depsee -file path/to/service.sbom.json
depsee -serve -file path/to/service.sbom.json
depsee -serve -addr :9090 -file path/to/service.sbom.json
depsee -serve -file path/to/service.sbom.json -skip-nvd
```

### Flags

- `-file` - path to a CycloneDX JSON SBOM file
- `-serve` - start the local HTTP server and web UI
- `-addr` - HTTP listen address for web mode
- `-skip-nvd` - disable NVD enrichment

## NVD API Key

`depsee` can query the NVD API without an API key, but rate limits are much lower. To improve throughput, set:

```bash
export NVD_API_KEY=your_key_here
```

On PowerShell:

```powershell
$env:NVD_API_KEY="your_key_here"
```

## API

### `GET /api/graph`

Returns graph data for the loaded SBOM:

```json
{
  "nodes": [
    {
      "id": "pkg:npm/express@4.18.0",
      "label": "express@4.18.0",
      "type": "library",
      "severity": "HIGH"
    }
  ],
  "links": [
    {
      "source": "pkg:npm/my-api@1.0.0",
      "target": "pkg:npm/express@4.18.0"
    }
  ]
}
```

## Project Layout

```text
depsee/
├── cmd/depsee/          # CLI entrypoint
├── internal/app/        # core application logic
└── internal/app/web/    # embedded static UI assets
```

## Development

Run all tests:

```bash
go test ./...
```

Run the web app locally:

```bash
go run ./cmd/depsee -serve -file path/to/service.sbom.json -skip-nvd
```

## Roadmap

- Better CycloneDX validation and empty-dependency handling
- Improved graph UI and node details
- More complete CVE enrichment and remediation guidance
- Risk ranking and "fix these first" workflow
- Additional export and integration options

## Contributing

Issues and pull requests are welcome. If you want to contribute, start by opening an issue or proposing an improvement.

## License

This project is licensed under the terms of the `LICENSE` file in this repository.
