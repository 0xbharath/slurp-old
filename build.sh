#!/bin/sh
env GOOS=darwin GOARCH=amd64 go build -o slurp-macos-amd64
env GOOS=darwin GOARCH=arm64 go build -o slurp-macos-arm64
env GOOS=linux GOARCH=amd64 go build -o slurp-linux-amd64
env GOOS=windows GOARCH=386 go build -o slurp-windows-386.exe
