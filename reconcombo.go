package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func intro() {
	art := `______                     _____                 _           _____       
| ___ \                   /  __ \               | |         |  __ \      
| |_/ /___  ___ ___  _ __ | /  \/ ___  _ __ ___ | |__   ___ | |  \/ ___  
|    // _ \/ __/ _ \| '_ \| |    / _ \| '_ ` + "`" + ` _ \| '_ \ / _ \| | __ / _ \ 
| |\ \  __/ (_| (_) | | | | \__/\ (_) | | | | | | |_) | (_) | |_\ \ (_) |
\_| \_\___|\___\___/|_| |_|\____/\___/|_| |_| |_|_.__/ \___/ \____/\___/ `
	fmt.Println(art + "\n")
	fmt.Println("made by someonenamenicky\n")
}

// ReconProgress tracks the progress of reconnaissance for resume functionality
type ReconProgress struct {
	Domain            string    `json:"domain"`
	SubdomainsDone    bool      `json:"subdomains_done"`
	URLCollectionDone bool      `json:"url_collection_done"`
	DirectoriesDone   bool      `json:"directories_done"`
	GFPatternsDone    bool      `json:"gf_patterns_done"`
	JSFilesDone       bool      `json:"js_files_done"`
	Completed         bool      `json:"completed"`
	LastUpdated       time.Time `json:"last_updated"`
}

// Save progress to a resume file
func saveProgress(outputDir string, progress *ReconProgress) error {
	progress.LastUpdated = time.Now()

	resumeFile := filepath.Join(outputDir, ".resume.json")
	data, err := json.MarshalIndent(progress, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(resumeFile, data, 0644)
}

// Load progress from resume file
func loadProgress(outputDir string) (*ReconProgress, error) {
	resumeFile := filepath.Join(outputDir, ".resume.json")

	data, err := os.ReadFile(resumeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No resume file exists
		}
		return nil, err
	}

	var progress ReconProgress
	err = json.Unmarshal(data, &progress)
	if err != nil {
		return nil, err
	}

	return &progress, nil
}

// Setup signal handler for graceful shutdown
func setupSignalHandler(outputDir string, progress *ReconProgress) chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n[!] Received interrupt signal (Ctrl+C)")
		fmt.Println("[*] Saving progress...")

		if err := saveProgress(outputDir, progress); err != nil {
			fmt.Printf("[!] Error saving progress: %v\n", err)
		} else {
			fmt.Printf("[✓] Progress saved to %s/.resume.json\n", outputDir)
			fmt.Println("[*] You can resume this scan by running the same command again")
		}

		fmt.Println("\n[*] Exiting gracefully...")
		os.Exit(0)
	}()

	return sigChan
}

// Check if a tool is installed
func checkTool(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// Check all required tools
func checkAllTools() bool {
	tools := []string{
		"subfinder",
		"httpx-toolkit",
		"gau",
		"ffuf",
		"nuclei",
		"anew",
		"katana",
		"uro",
		"feroxbuster",
		"dirsearch",
		"gf",
	}

	fmt.Println("Checking for required tools...\n")
	time.Sleep(500 * time.Millisecond)

	allInstalled := true
	for _, tool := range tools {
		if checkTool(tool) {
			fmt.Printf("✓✓✓ %s is installed ✓✓✓\n", tool)
			time.Sleep(10 * time.Millisecond)
		} else {
			fmt.Printf("✗✗✗ %s is NOT installed! Please install it before running.\n", tool)
			allInstalled = false
		}
	}

	fmt.Println()
	return allInstalled
}

// Create output directory structure
func createOutputDir(domain string) (string, error) {
	baseDir := "reconcombo"
	domainDir := filepath.Join(baseDir, domain)

	err := os.MkdirAll(domainDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create directory: %v", err)
	}

	return domainDir, nil
}

// Run command and save output to file
func runCommand(name string, args []string, outputFile string) error {
	cmd := exec.Command(name, args...)

	if outputFile != "" {
		outFile, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer outFile.Close()
		cmd.Stdout = outFile
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	return cmd.Run()
}

// Run shell command (for pipes and complex commands)
func runShellCommand(command string, outputFile string) error {
	cmd := exec.Command("bash", "-c", command)

	if outputFile != "" {
		outFile, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer outFile.Close()
		cmd.Stdout = outFile
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	return cmd.Run()
}

// Count lines in a file
func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}

	return count, scanner.Err()
}

// Perform subdomain enumeration
func enumerateSubdomains(domain, outputDir string, progress *ReconProgress) error {
	if progress.SubdomainsDone {
		fmt.Printf("[*] Subdomain enumeration already completed (resuming)\n\n")
		return nil
	}

	fmt.Printf("[*] Starting subdomain enumeration for %s...\n", domain)

	subdomainFile := filepath.Join(outputDir, "subdomains_tmp.txt")
	subdomainLiveFile := filepath.Join(outputDir, "subdomains_live.txt")

	err := runCommand("subfinder", []string{"-d", domain, "-o", subdomainFile}, "")
	if err != nil {
		return fmt.Errorf("subfinder failed: %v", err)
	}

	count, _ := countLines(subdomainFile)
	fmt.Printf("  - Found %d subdomains\n", count)

	// Filter with httpx to get only 200 OK responses
	fmt.Println("  - Filtering live subdomains with httpx (200 OK only)...")
	err = runCommand("httpx-toolkit", []string{
		"-l", subdomainFile,
		"-mc", "200",
		"-silent",
		"-o", subdomainLiveFile,
	}, "")
	if err != nil {
		fmt.Printf("  [!] Warning: httpx filtering failed: %v\n", err)
	}

	liveCount, _ := countLines(subdomainLiveFile)
	fmt.Printf("[✓] Found %d live subdomains (200 OK)\n\n", liveCount)

	progress.SubdomainsDone = true
	saveProgress(outputDir, progress)

	return nil
}

// Collect URLs from various sources
func collectURLs(domain, outputDir string, progress *ReconProgress) error {
	if progress.URLCollectionDone {
		fmt.Printf("[*] URL collection already completed (resuming)\n\n")
		return nil
	}

	fmt.Printf("[*] Collecting URLs from multiple sources...\n")

	subdomainLiveFile := filepath.Join(outputDir, "subdomains_live.txt")
	gauOutput := filepath.Join(outputDir, "gau_tmp.txt")
	uroOutput := filepath.Join(outputDir, "uro_tmp.txt")
	urlsFile := filepath.Join(outputDir, "urls.txt")

	// Use gau on domain and subdomains
	fmt.Println("  - Running gau on domain...")
	err := runCommand("gau", []string{domain}, gauOutput)
	if err != nil {
		fmt.Printf("  [!] Warning: gau failed: %v\n", err)
	}

	// Run gau on live subdomains if they exist
	if _, err := os.Stat(subdomainLiveFile); err == nil {
		fmt.Println("  - Running gau on live subdomains...")
		cmd := fmt.Sprintf("cat %s | gau >> %s", subdomainLiveFile, gauOutput)
		runShellCommand(cmd, "")
	}

	// Fuzzing with ffuf (basic example - you may want to customize)
	fmt.Println("  - Running ffuf for URL discovery...")
	// Note: You'll need a wordlist. Adjust path as needed
	// ffufOutput := filepath.Join(outputDir, "ffuf_tmp.txt")
	// This is commented out as it needs proper configuration
	// runCommand("ffuf", []string{"-w", "wordlist.txt", "-u", "https://" + domain + "/FUZZ"}, ffufOutput)

	// Filter and deduplicate with uro
	fmt.Println("  - Filtering and deduplicating URLs with uro...")
	cmd := fmt.Sprintf("cat %s | uro > %s", gauOutput, uroOutput)
	err = runShellCommand(cmd, "")
	if err != nil {
		return fmt.Errorf("uro filtering failed: %v", err)
	}

	// Filter URLs with httpx to get only 200 OK responses
	fmt.Println("  - Filtering URLs with httpx (200 OK only)...")
	err = runCommand("httpx-toolkit", []string{
		"-l", uroOutput,
		"-mc", "200",
		"-silent",
		"-o", urlsFile,
	}, "")
	if err != nil {
		return fmt.Errorf("httpx filtering failed: %v", err)
	}

	count, _ := countLines(urlsFile)
	fmt.Printf("[✓] Collected and filtered %d unique URLs (200 OK)\n\n", count)

	progress.URLCollectionDone = true
	saveProgress(outputDir, progress)

	return nil
}

// Find directories and endpoints
func findDirectories(domain, outputDir string, progress *ReconProgress) error {
	if progress.DirectoriesDone {
		fmt.Printf("[*] Directory scanning already completed (resuming)\n\n")
		return nil
	}

	fmt.Printf("[*] Scanning for directories and endpoints...\n")

	subdomainLiveFile := filepath.Join(outputDir, "subdomains_live.txt")
	dirFileTmp := filepath.Join(outputDir, "directories_tmp.txt")
	dirFile := filepath.Join(outputDir, "directories.txt")

	// Read live subdomains
	subdomains := []string{"https://" + domain}

	if file, err := os.Open(subdomainLiveFile); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomain := strings.TrimSpace(scanner.Text())
			if subdomain != "" {
				// httpx already adds https://, so check if it's already there
				if !strings.HasPrefix(subdomain, "http://") && !strings.HasPrefix(subdomain, "https://") {
					subdomain = "https://" + subdomain
				}
				subdomains = append(subdomains, subdomain)
			}
		}
		file.Close()
	}

	// Use feroxbuster and dirsearch on subdomains
	tempFiles := []string{}

	for i, target := range subdomains {
		if i >= 5 { // Limit to first 5 targets for demo
			break
		}

		fmt.Printf("  - Scanning %s with feroxbuster...\n", target)
		feroxOutput := filepath.Join(outputDir, fmt.Sprintf("ferox_tmp_%d.txt", i))
		tempFiles = append(tempFiles, feroxOutput)

		// Run feroxbuster (basic scan)
		err := runCommand("feroxbuster", []string{
			"-u", target,
			"-o", feroxOutput,
			"--silent",
			"-t", "10",
		}, "")

		if err != nil {
			fmt.Printf("  [!] Warning: feroxbuster failed for %s\n", target)
		}
	}

	// Combine all results
	fmt.Println("  - Combining and deduplicating results...")
	cmd := fmt.Sprintf("cat %s 2>/dev/null | grep -oE 'https?://[^[:space:]]+' | sort -u > %s || true",
		filepath.Join(outputDir, "ferox_tmp_*.txt"),
		dirFileTmp)
	runShellCommand(cmd, "")

	// Filter with httpx to get only 200 OK responses
	fmt.Println("  - Filtering directories with httpx (200 OK only)...")
	err := runCommand("httpx-toolkit", []string{
		"-l", dirFileTmp,
		"-mc", "200",
		"-silent",
		"-o", dirFile,
	}, "")
	if err != nil {
		fmt.Printf("  [!] Warning: httpx filtering failed: %v\n", err)
	}

	count, _ := countLines(dirFile)
	fmt.Printf("[✓] Found %d directories/endpoints (200 OK)\n\n", count)

	progress.DirectoriesDone = true
	saveProgress(outputDir, progress)

	return nil
}

// Extract GF patterns
func extractGFPatterns(domain, outputDir string, progress *ReconProgress) error {
	if progress.GFPatternsDone {
		fmt.Printf("[*] GF pattern extraction already completed (resuming)\n\n")
		return nil
	}

	fmt.Printf("[*] Extracting GF patterns...\n")

	urlsFile := filepath.Join(outputDir, "urls.txt")
	gfFileTmp := filepath.Join(outputDir, "gfpatterns_tmp.txt")
	gfFile := filepath.Join(outputDir, "gfpatterns.txt")

	if _, err := os.Stat(urlsFile); os.IsNotExist(err) {
		return fmt.Errorf("urls.txt not found")
	}

	// Common GF patterns
	patterns := []string{"xss", "sqli", "ssrf", "redirect", "lfi", "rce", "idor"}

	tempFiles := []string{}
	for _, pattern := range patterns {
		tempFile := filepath.Join(outputDir, fmt.Sprintf("gf_%s_tmp.txt", pattern))
		tempFiles = append(tempFiles, tempFile)

		fmt.Printf("  - Searching for %s patterns...\n", pattern)
		cmd := fmt.Sprintf("cat %s | gf %s > %s 2>/dev/null || true", urlsFile, pattern, tempFile)
		runShellCommand(cmd, "")
	}

	// Combine all GF results
	cmd := fmt.Sprintf("cat %s 2>/dev/null | sort -u > %s || true",
		filepath.Join(outputDir, "gf_*_tmp.txt"),
		gfFileTmp)
	runShellCommand(cmd, "")

	// Filter with httpx to get only 200 OK responses
	if _, err := os.Stat(gfFileTmp); err == nil {
		count, _ := countLines(gfFileTmp)
		if count > 0 {
			fmt.Println("  - Filtering GF patterns with httpx (200 OK only)...")
			err := runCommand("httpx-toolkit", []string{
				"-l", gfFileTmp,
				"-mc", "200",
				"-silent",
				"-o", gfFile,
			}, "")
			if err != nil {
				fmt.Printf("  [!] Warning: httpx filtering failed: %v\n", err)
			}
		} else {
			// If no patterns found, create empty file
			os.Create(gfFile)
		}
	}

	count, _ := countLines(gfFile)
	fmt.Printf("[✓] Found %d URLs matching GF patterns (200 OK)\n\n", count)

	progress.GFPatternsDone = true
	saveProgress(outputDir, progress)

	return nil
}

// Extract JavaScript files
func extractJSFiles(domain, outputDir string, progress *ReconProgress) error {
	if progress.JSFilesDone {
		fmt.Printf("[*] JavaScript extraction already completed (resuming)\n\n")
		return nil
	}

	fmt.Printf("[*] Extracting JavaScript files...\n")

	urlsFile := filepath.Join(outputDir, "urls.txt")
	jsFileTmp := filepath.Join(outputDir, "jsfiles_tmp.txt")
	jsFile := filepath.Join(outputDir, "jsfiles.txt")

	if _, err := os.Stat(urlsFile); os.IsNotExist(err) {
		return fmt.Errorf("urls.txt not found")
	}

	// Filter JS files from URLs
	cmd := fmt.Sprintf("cat %s | grep -iE '\\.js($|\\?)' | sort -u > %s", urlsFile, jsFileTmp)
	err := runShellCommand(cmd, "")
	if err != nil {
		return fmt.Errorf("JS extraction failed: %v", err)
	}

	// Filter with httpx to get only 200 OK responses
	tmpCount, _ := countLines(jsFileTmp)
	if tmpCount > 0 {
		fmt.Println("  - Filtering JS files with httpx (200 OK only)...")
		err = runCommand("httpx-toolkit", []string{
			"-l", jsFileTmp,
			"-mc", "200",
			"-silent",
			"-o", jsFile,
		}, "")
		if err != nil {
			fmt.Printf("  [!] Warning: httpx filtering failed: %v\n", err)
		}
	} else {
		// Create empty file if no JS files found
		os.Create(jsFile)
	}

	count, _ := countLines(jsFile)
	fmt.Printf("[✓] Found %d JavaScript files (200 OK)\n\n", count)

	progress.JSFilesDone = true
	saveProgress(outputDir, progress)

	return nil
}

// Perform full reconnaissance on a domain
func performRecon(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("empty domain")
	}

	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("Starting reconnaissance for: %s\n", domain)
	fmt.Printf(strings.Repeat("=", 60) + "\n\n")

	// Create output directory
	outputDir, err := createOutputDir(domain)
	if err != nil {
		return err
	}

	// Load existing progress or create new
	progress, err := loadProgress(outputDir)
	if err != nil {
		fmt.Printf("[!] Error loading progress: %v\n", err)
		progress = nil
	}

	if progress == nil {
		progress = &ReconProgress{
			Domain: domain,
		}
		fmt.Println("[*] Starting new scan...")
	} else {
		fmt.Println("[*] Resuming previous scan...")
		fmt.Printf("    - Subdomains: %v\n", progress.SubdomainsDone)
		fmt.Printf("    - URLs: %v\n", progress.URLCollectionDone)
		fmt.Printf("    - Directories: %v\n", progress.DirectoriesDone)
		fmt.Printf("    - GF Patterns: %v\n", progress.GFPatternsDone)
		fmt.Printf("    - JS Files: %v\n", progress.JSFilesDone)
		fmt.Println()
	}

	// Setup signal handler for Ctrl+C
	setupSignalHandler(outputDir, progress)

	// 1. Subdomain enumeration
	if err := enumerateSubdomains(domain, outputDir, progress); err != nil {
		fmt.Printf("[!] Error during subdomain enumeration: %v\n", err)
	}

	// 2. Collect URLs
	if err := collectURLs(domain, outputDir, progress); err != nil {
		fmt.Printf("[!] Error during URL collection: %v\n", err)
	}

	// 3. Find directories and endpoints
	if err := findDirectories(domain, outputDir, progress); err != nil {
		fmt.Printf("[!] Error during directory scanning: %v\n", err)
	}

	// 4. Extract GF patterns
	if err := extractGFPatterns(domain, outputDir, progress); err != nil {
		fmt.Printf("[!] Error during GF pattern extraction: %v\n", err)
	}

	// 5. Extract JS files
	if err := extractJSFiles(domain, outputDir, progress); err != nil {
		fmt.Printf("[!] Error during JS extraction: %v\n", err)
	}

	// Mark as completed
	progress.Completed = true
	saveProgress(outputDir, progress)

	fmt.Printf("\n[✓✓✓] Reconnaissance completed for %s!\n", domain)
	fmt.Printf("[*] Results saved in: %s\n", outputDir)

	// Clean up resume file since scan is complete
	resumeFile := filepath.Join(outputDir, ".resume.json")
	os.Remove(resumeFile)
	fmt.Printf("[*] Resume file cleaned up\n\n")

	return nil
}

func main() {
	// Define flags
	urlPtr := flag.String("url", "", "Target domain (e.g., example.com)")
	listPtr := flag.String("l", "", "File containing list of domains")

	// Parse flags
	flag.Parse()

	// Show intro
	intro()

	// Check if flags are provided
	if *urlPtr == "" && *listPtr == "" {
		fmt.Println("Error: Please provide either --url or -l flag")
		fmt.Println("\nUsage:")
		fmt.Println("  Single domain:  reconcombo --url example.com")
		fmt.Println("  Multiple domains: reconcombo -l domains.txt")
		os.Exit(1)
	}

	// Check all tools
	if !checkAllTools() {
		fmt.Println("\n[!] Please install missing tools before proceeding.")
		os.Exit(1)
	}

	fmt.Println("[✓] All tools are installed! Proceeding...\n")
	time.Sleep(500 * time.Millisecond)

	// Process single domain
	if *urlPtr != "" {
		if err := performRecon(*urlPtr); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Process domain list
	if *listPtr != "" {
		file, err := os.Open(*listPtr)
		if err != nil {
			fmt.Printf("[!] Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 3) // Limit concurrent scans

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if domain == "" || strings.HasPrefix(domain, "#") {
				continue
			}

			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore

			go func(d string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				if err := performRecon(d); err != nil {
					fmt.Printf("[!] Error processing %s: %v\n", d, err)
				}
			}(domain)
		}

		wg.Wait()

		if err := scanner.Err(); err != nil {
			fmt.Printf("[!] Error reading file: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("\n[✓✓✓] All reconnaissance tasks completed!")
}
