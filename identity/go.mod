module github.com/horizoonn/relay/identity

go 1.27.0

require (
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.57.0
)

require (
	github.com/stretchr/testify v1.12.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/horizoonn/relay/platform => ../platform

replace github.com/horizoonn/relay/shared => ../shared
