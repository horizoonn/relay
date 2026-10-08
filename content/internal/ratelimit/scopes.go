package ratelimit

type Scope string

const (
	Capture Scope = "capture-user"
	Write   Scope = "write-user"
	Read    Scope = "read-user"
	Search  Scope = "search-user"
)
