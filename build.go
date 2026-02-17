// Copyright (c) 2026 Half_nothing
// SPDX-License-Identifier: MIT

// Package main
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var (
	DockerBuild = flag.Bool("docker", false, "build in docker")
)

func main() {
	flag.Parse()

	if *DockerBuild {
		fmt.Printf("Git status output:\n")
		cmd := exec.Command("git", "status", "--porcelain")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	}

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

	ldflags := fmt.Sprintf(
		strings.Join(flags, " "),
		buildTime,
		strings.TrimSpace(string(gitCommit)),
		strings.TrimSpace(string(gitVersion)),
	)

	goos := os.Getenv("GOOS")
	if goos == "" {
		goos = runtime.GOOS
	}

	goarch := os.Getenv("GOARCH")
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	var outputName string
	if *DockerBuild {
		outputName = "fsd"
	} else {
		outputName = fmt.Sprintf("fsd-%s-%s-%s", goos, goarch, string(gitCommit[:7]))
	}
	if goos == "windows" {
		outputName += ".exe"
	}

	fmt.Printf("Build argument:\n")
	fmt.Printf("os: %s\n", goos)
	fmt.Printf("arch: %s\n", goarch)
	fmt.Printf("ldflags: %s\n", ldflags)
	fmt.Printf("outputName: %s\n", outputName)

	fmt.Println("Building binary...")

	args := []string{"build", "-ldflags", ldflags, "-o", outputName}
	if os.Getenv("BUILD_OPUS") == "1" {
		args = append(args, "-tags", "opus nolibopusfile")
		fmt.Println("Build with -tags opus nolibopusfile (ATIS voice encoding enabled, no libopusfile)")
	}
	args = append(args, "./cmd/fsd")
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("Build failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Build completed.")

	if *DockerBuild {
		fmt.Println("Output file:", outputName)
		return
	}

	compressBinary(outputName)
	compressZip(outputName, goos)

	fmt.Println("Output file:", outputName)
	fmt.Println("Zip file:", fmt.Sprintf("%s.zip", goos))
	return
}

func compressBinary(outputName string) {
	fmt.Println("Compressing binary...")

	_, err := exec.Command("upx", "--version").Output()
	if err != nil {
		fmt.Println("upx not found, skipping compression")
	} else {
		cmd := exec.Command("upx", "-fq", "-9", outputName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("Compression failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Compression completed.")
	}
}

func compressZip(outputName string, goos string) {
	zipFile, err := os.Create(fmt.Sprintf("%s.zip", goos))
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

	fmt.Println("Zip file created.")
}
