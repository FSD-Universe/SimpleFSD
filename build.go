// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package main
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	// 获取git版本
	gitVersion, err := exec.Command("git", "describe", "--tags", "--always", "--dirty").Output()
	if err != nil {
		gitVersion = []byte("unknown")
	}

	// 获取git commit
	gitCommit, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		gitCommit = []byte("unknown")
	}

	buildTime := time.Now().Format(time.RFC3339)

	flags := []string{
		"-w",
		"-s",
		"-X 'github.com/half-nothing/simple-fsd/internal/interfaces/global.BuildTime=%s'",
		"-X 'github.com/half-nothing/simple-fsd/internal/interfaces/global.GitCommit=%s'",
		"-X 'github.com/half-nothing/simple-fsd/internal/interfaces/global.GitVersion=%s'",
	}

	ldflags := fmt.Sprintf(strings.Join(flags, " "),
		buildTime,
		strings.TrimSpace(string(gitCommit)),
		strings.TrimSpace(string(gitVersion)))

	outputName := fmt.Sprintf("fsd-%s-%s-%s", os.Getenv("GOOS"), os.Getenv("GOARCH"), string(gitCommit[:7]))
	if os.Getenv("GOOS") == "windows" {
		outputName += ".exe"
	}

	fmt.Printf("Build argument:\n")
	fmt.Printf("os: %s\n", os.Getenv("GOOS"))
	fmt.Printf("arch: %s\n", os.Getenv("GOARCH"))
	fmt.Printf("ldflags: %s\n", ldflags)
	fmt.Printf("outputName: %s\n", outputName)

	fmt.Println("Building binary...")

	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", outputName, "./cmd/fsd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("Build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Build completed successfully!")

	fmt.Println("Compressing binary...")

	_, err = exec.Command("upx", "--version").Output()
	if err != nil {
		fmt.Println("upx not found, skipping compression")
	} else {
		cmd = exec.Command("upx", "-fq", "-9", outputName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Compression failed: %v\n", err)
			os.Exit(1)
		}
	}

	zipFile, err := os.Create(fmt.Sprintf("%s.zip", os.Getenv("GOOS")))
	if err != nil {
		fmt.Printf("Failed to create zip file: %v\n", err)
		os.Exit(1)
	}
	defer func(zipFile *os.File) { _ = zipFile.Close() }(zipFile)

	zipWriter := zip.NewWriter(zipFile)
	defer func(zipWriter *zip.Writer) { _ = zipWriter.Close() }(zipWriter)

	header := &zip.FileHeader{
		Name:   outputName,
		Method: zip.Deflate,
	}
	header.SetMode(0744)

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		fmt.Printf("Failed to create zip file header: %v\n", err)
		os.Exit(1)
	}

	file, err := os.Open(outputName)
	defer func(file *os.File) { _ = file.Close() }(file)
	if err != nil {
		fmt.Printf("Failed to open output file: %v\n", err)
		os.Exit(1)
	}
	_, err = io.Copy(writer, file)
	if err != nil {
		fmt.Printf("Failed to copy output file to zip: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Zip file created successfully!")

	fmt.Println("Output file:", outputName)
	fmt.Println("Zip file:", fmt.Sprintf("%s.zip", os.Getenv("GOOS")))
}
