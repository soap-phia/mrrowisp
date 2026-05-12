#!/bin/bash

rm -rf dist/bin
mkdir -p dist/bin

if [ ! -f "main.go" ]; then
	echo "main.go not found."
	exit 1
fi

for os in linux darwin win32; do
	if [ "$os" = "win32" ]; then
		goos="windows"
	else
		goos=$os
	fi
	for arch in x64 arm64; do
		if [ "$arch" = "x64" ]; then
			goarch="amd64"
		else
			goarch=$arch
		fi
		if [ "$os" = "win32" ]; then
			ext=".exe"
		else
			ext=""
		fi
		GOOS=$goos GOARCH=$goarch go build -o ./dist/bin/${os}-${arch}-mrrowisp${ext} main.go
	done
done

echo "Finished building. Binaries in ./dist/bin/"
