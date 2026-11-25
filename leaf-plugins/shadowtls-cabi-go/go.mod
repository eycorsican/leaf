module leaf-plugins/shadowtls-cabi-go

go 1.26.0

require (
	github.com/metacubex/utls v1.8.7
	github.com/sagernet/sing v0.6.3
	github.com/sagernet/sing-shadowtls v0.2.2-0.20260928201441-a9c0127d5c99
	leaf-plugins/leaf-abi-go v0.0.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace leaf-plugins/leaf-abi-go => ../leaf-abi-go
