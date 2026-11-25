module leaf-plugins/anytls-cabi-go

go 1.26.0

require (
	github.com/anytls/sing-anytls v0.0.13
	github.com/metacubex/utls v1.8.7
	github.com/sagernet/sing v0.6.1
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
