module github.com/horizoonn/relay/identity

go 1.27.0

require (
	github.com/horizoonn/relay/platform v0.0.0
	github.com/redis/go-redis/v9 v9.21.0
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.57.0
	golang.org/x/time v0.16.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-redis/redis_rate/v10 v10.0.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/horizoonn/relay/platform => ../platform

replace github.com/horizoonn/relay/shared => ../shared
