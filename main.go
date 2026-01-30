// android_triage_pro.go
// Professional Android Forensic Tool - Complete Implementation
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Version      = "1.0.0"
	MaxWorkers   = 4  // Concurrent operations
	CommandTimeout = 300 // seconds
)

type DeviceInfo struct {
	AndroidID        string `json:"android_id"`
	Manufacturer     string `json:"manufacturer"`
	Product          string `json:"product"`
	AndroidVersion   string `json:"android_version"`
	Serial           string `json:"serial"`
	Device           string `json:"device"`
	BuildDate        string `json:"build_date"`
	Fingerprint      string `json:"fingerprint"`
	IMEI1            string `json:"imei_1"`
	IMEI2            string `json:"imei_2"`
	PhoneNumber      string `json:"phone_number"`
	NetworkOperator  string `json:"network_operator"`
	IsRooted         bool   `json:"is_rooted"`
	SDKVersion       int    `json:"sdk_version"`
	Encryption       string `json:"encryption"`
	EncryptionType   string `json:"encryption_type"`
	BluetoothMAC     string `json:"bluetooth_mac"`
	BluetoothName    string `json:"bluetooth_name"`
	Timezone         string `json:"timezone"`
	SecurityPatch    string `json:"security_patch"`
	BasebandVersion  string `json:"baseband_version"`
	StorageSize      string `json:"storage_size"`
	KernelVersion    string `json:"kernel_version"`
	Bootloader       string `json:"bootloader"`
	BuildID          string `json:"build_id"`
	AirplaneMode     bool   `json:"airplane_mode"`
	USBConfiguration string `json:"usb_configuration"`
	CountryCode      string `json:"country_code"`
	Uptime           string `json:"uptime"`
}

type Acquisition struct {
	Name        string    `json:"name"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    string    `json:"duration"`
	OutputDir   string    `json:"output_dir"`
	Files       []string  `json:"files"`
	Hashes      map[string]string `json:"hashes"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
}

type AcquisitionManager struct {
	Device      *DeviceInfo
	Acquisitions []*Acquisition
	BaseDir     string
	Logger      *log.Logger
	WorkerPool  chan struct{}
}

// ==================== MAIN FUNCTION ====================
func main() {
	
	
	// Initialize logger
	logFile, err := os.OpenFile("android_triage.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	
	logger := log.New(io.MultiWriter(os.Stdout, logFile), "ANDROID_TRIAGE: ", log.LstdFlags)
	
	// Check ADB
	if !checkADB() {
		fmt.Println("[-] ADB not found!")
		fmt.Println("   Please ensure ADB is installed and in PATH")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	fmt.Println("[*] Checking for connected devices...")

	// Check if device is connected
	if !checkDeviceConnected() {
		fmt.Println("\n[-] No authorized device found!")
		fmt.Println("Please connect device and enable USB debugging")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	fmt.Println("[+] Device connected")

	// Get comprehensive device info
	dev := getDeviceInfoComprehensive()
	
	// Create acquisition manager
	am := &AcquisitionManager{
		Device:     dev,
		BaseDir:    dev.AndroidID,
		Logger:     logger,
		WorkerPool: make(chan struct{}, MaxWorkers),
	}
	
	// Initialize worker pool
	for i := 0; i < MaxWorkers; i++ {
		am.WorkerPool <- struct{}{}
	}
	
	// Create base directory
	if err := os.MkdirAll(dev.AndroidID, 0755); err != nil {
		logger.Printf("Failed to create base directory: %v", err)
	}

	// Run main menu
	runInteractiveMenu(am)
}

// ==================== CORE UTILITIES ====================
func getTimestamp() string {
	return time.Now().Format("20060102_150405")
}

func createDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func boolToYesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

func calculateSHA256(filepath string) string {
	file, err := os.Open(filepath)
	if err != nil {
		return "ERROR_OPEN_FILE"
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "ERROR_CALC_HASH"
	}
	
	return hex.EncodeToString(hash.Sum(nil))
}

// ==================== COMMAND EXECUTION ====================
func runCmdWithTimeout(cmd string, args []string, timeoutSec int) (string, error) {
	ctx := context.Background()
	if timeoutSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
		defer cancel()
	}

	command := exec.CommandContext(ctx, cmd, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &out
	command.Stderr = &stderr

	err := command.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("command timed out after %d seconds", timeoutSec)
		}
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}
	return out.String(), nil
}

func runADB(args ...string) (string, error) {
	adbCmd := "adb"
	if runtime.GOOS == "windows" {
		adbCmd = "adb.exe"
	}
	return runCmdWithTimeout(adbCmd, args, CommandTimeout)
}

func runADBShell(cmd string) (string, error) {
	if strings.Contains(cmd, "|") || strings.Contains(cmd, "cut") || strings.Contains(cmd, "tr") {
		// Complex shell command with pipes
		return runADB("shell", "sh", "-c", fmt.Sprintf("%q", cmd))
	}
	return runADB("shell", cmd)
}

func runADBShellSafe(cmd string) string {
	output, err := runADBShell(cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func checkADB() bool {
	adbCmd := "adb"
	if runtime.GOOS == "windows" {
		adbCmd = "adb.exe"
		if _, err := os.Stat(adbCmd); err == nil {
			return true
		}
	}

	_, err := exec.LookPath(adbCmd)
	return err == nil
}

func checkDeviceConnected() bool {
	output, err := runADB("devices")
	if err != nil {
		return false
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "device") && !strings.Contains(line, "unauthorized") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[1] == "device" {
				return true
			}
		}
	}
	return false
}

// ==================== COMPREHENSIVE DEVICE INFO ====================
func getDeviceInfoComprehensive() *DeviceInfo {
	dev := &DeviceInfo{}
	
	fmt.Println("\n[*] Gathering comprehensive device information...")
	
	// Fast Path: Get all properties in one go
	output := runADBShellSafe("getprop")
	props := parseGetProp(output)
	
	dev.Manufacturer = props["ro.product.manufacturer"]
	dev.Product = props["ro.product.model"]
	dev.AndroidVersion = props["ro.build.version.release"]
	dev.Serial = props["ro.serialno"]
	dev.Device = props["ro.product.device"]
	dev.BuildDate = props["ro.build.date"]
	dev.Fingerprint = props["ro.build.fingerprint"]
	dev.NetworkOperator = props["gsm.operator.alpha"]
	dev.Encryption = props["ro.crypto.state"]
	dev.EncryptionType = props["ro.crypto.type"]
	dev.SecurityPatch = props["ro.build.version.security_patch"]
	dev.BasebandVersion = props["gsm.version.baseband"]
	dev.StorageSize = props["storage.mmc.size"]
	dev.Timezone = props["persist.sys.timezone"]
	dev.Bootloader = props["ro.boot.bootloader"]
	dev.BuildID = props["ro.build.id"]
	dev.CountryCode = props["ro.csc.country_code"]
	dev.USBConfiguration = props["persist.sys.usb.config"]
	
	// Integers and Booleans
	if sdk, err := strconv.Atoi(props["ro.build.version.sdk"]); err == nil {
		dev.SDKVersion = sdk
	}
	
	// Additional specific queries (concurrently)
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		output := runADBShellSafe("settings get global airplane_mode_on")
		mu.Lock()
		dev.AirplaneMode = output == "1"
		mu.Unlock()
	}()
	
	// Android ID
	wg.Add(1)
	go func() {
		defer wg.Done()
		output := runADBShellSafe("settings get secure android_id")
		mu.Lock()
		dev.AndroidID = output
		if dev.AndroidID == "null" || dev.AndroidID == "" {
			dev.AndroidID = "unknown_" + strconv.FormatInt(time.Now().Unix(), 10)
		}
		mu.Unlock()
	}()
	
	// IMEI extraction
	wg.Add(1)
	go func() {
		defer wg.Done()
		imei1, imei2 := extractIMEIComprehensive()
		mu.Lock()
		dev.IMEI1 = imei1
		dev.IMEI2 = imei2
		mu.Unlock()
	}()
	
	// Bluetooth info
	wg.Add(1)
	go func() {
		defer wg.Done()
		mu.Lock()
		dev.BluetoothMAC = runADBShellSafe("settings get secure bluetooth_address")
		dev.BluetoothName = runADBShellSafe("settings get secure bluetooth_name")
		mu.Unlock()
	}()
	
	// Kernel version
	wg.Add(1)
	go func() {
		defer wg.Done()
		output := runADBShellSafe("cat /proc/version")
		mu.Lock()
		dev.KernelVersion = output
		mu.Unlock()
	}()
	
	// Uptime
	wg.Add(1)
	go func() {
		defer wg.Done()
		output := runADBShellSafe("uptime -s")
		mu.Lock()
		dev.Uptime = output
		mu.Unlock()
	}()
	
	// Root detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		output := runADBShellSafe("id")
		isRooted := strings.Contains(output, "root")
		if !isRooted {
			// Try su command
			output := runADBShellSafe("su -c id")
			isRooted = strings.Contains(output, "uid=0")
		}
		mu.Lock()
		dev.IsRooted = isRooted
		mu.Unlock()
	}()
	
	wg.Wait()
	
	fmt.Println("[+] Device information collected")
	return dev
}

func parseGetProp(output string) map[string]string {
	props := make(map[string]string)
	// Normalize line endings and split
	output = strings.ReplaceAll(output, "\r\n", "\n")
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Format is: [key]: [value]
		// We split by "]: [" to get the key and value parts
		parts := strings.SplitN(line, "]: [", 2)
		if len(parts) == 2 {
			key := strings.TrimPrefix(parts[0], "[")
			val := strings.TrimSuffix(parts[1], "]")
			props[key] = strings.TrimSpace(val)
		}
	}
	return props
}

func extractIMEIComprehensive() (string, string) {
	imei1, imei2 := "", ""
	
	// Method 1: Service call (primary method)
	cmd1 := "service call iphonesubinfo 1 s16 com.android.shell | cut -d \"'\" -f 2 -s | tr -d '.[:space:]'"
	output1 := runADBShellSafe(cmd1)
	if isValidIMEI(output1) {
		imei1 = output1
	}
	
	cmd2 := "service call iphonesubinfo 2 s16 com.android.shell | cut -d \"'\" -f 2 -s | tr -d '.[:space:]'"
	output2 := runADBShellSafe(cmd2)
	if isValidIMEI(output2) && output2 != imei1 {
		imei2 = output2
	}
	
	// Method 2: getprop fallback
	if imei1 == "" || imei2 == "" {
		props := []string{"gsm.imei", "gsm.imei1", "gsm.imei2", "ril.imei", "ril.imei1", "ril.imei2"}
		for _, prop := range props {
			output := runADBShellSafe("getprop " + prop)
			if isValidIMEI(output) {
				if imei1 == "" {
					imei1 = output
				} else if imei2 == "" && output != imei1 {
					imei2 = output
				}
			}
		}
	}
	
	// Set defaults
	if imei1 == "" {
		imei1 = "NOT_AVAILABLE"
	}
	if imei2 == "" {
		imei2 = "NOT_AVAILABLE"
	}
	
	return imei1, imei2
}

func isValidIMEI(imei string) bool {
	imei = strings.TrimSpace(imei)
	if len(imei) < 14 || len(imei) > 16 {
		return false
	}
	
	for _, r := range imei {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ==================== ACQUISITION MANAGER ====================
func (am *AcquisitionManager) startAcquisition(name string) *Acquisition {
	acq := &Acquisition{
		Name:      name,
		StartTime: time.Now(),
		OutputDir: filepath.Join(am.BaseDir, getTimestamp()+"_"+strings.ReplaceAll(name, " ", "_")),
		Hashes:    make(map[string]string),
	}
	
	am.Acquisitions = append(am.Acquisitions, acq)
	createDir(acq.OutputDir)
	
	am.Logger.Printf("Starting acquisition: %s", name)
	return acq
}

func (am *AcquisitionManager) completeAcquisition(acq *Acquisition, success bool, errMsg string) {
	acq.EndTime = time.Now()
	acq.Duration = acq.EndTime.Sub(acq.StartTime).String()
	acq.Success = success
	if !success {
		acq.Error = errMsg
	}
	
	// Calculate hashes for all files
	if success {
		fileChan := make(chan string, 100)
		var hashWg sync.WaitGroup
		var hashMu sync.Mutex

		// Worker pool for hashing
		for i := 0; i < MaxWorkers; i++ {
			hashWg.Add(1)
			go func() {
				defer hashWg.Done()
				for path := range fileChan {
					hash := calculateSHA256(path)
					relPath, _ := filepath.Rel(acq.OutputDir, path)
					
					hashMu.Lock()
					acq.Files = append(acq.Files, relPath)
					acq.Hashes[relPath] = hash
					hashMu.Unlock()
				}
			}()
		}

		// Walk and send to workers
		filepath.Walk(acq.OutputDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			fileChan <- path
			return nil
		})
		close(fileChan)
		hashWg.Wait()
		
		// Save acquisition metadata
		metadata, _ := json.MarshalIndent(acq, "", "  ")
		os.WriteFile(filepath.Join(acq.OutputDir, "acquisition_metadata.json"), metadata, 0644)
	}
	
	am.Logger.Printf("Completed acquisition: %s (Success: %v, Duration: %s)", 
		acq.Name, success, acq.Duration)
}

func (am *AcquisitionManager) saveDeviceInfo() {
	acq := am.startAcquisition("Device Information")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	// Save JSON
	devJSON, _ := json.MarshalIndent(am.Device, "", "  ")
	os.WriteFile(filepath.Join(acq.OutputDir, "device_info.json"), devJSON, 0644)
	
	// Save text version
	infoFile, _ := os.Create(filepath.Join(acq.OutputDir, "device_info.txt"))
	defer infoFile.Close()
	
	writer := bufio.NewWriter(infoFile)
	fmt.Fprintf(writer, "=== ANDROID DEVICE INFORMATION ===\n")
	fmt.Fprintf(writer, "Acquisition Time: %s\n", getTimestamp())
	fmt.Fprintf(writer, "Android ID: %s\n", am.Device.AndroidID)
	fmt.Fprintf(writer, "Manufacturer: %s\n", am.Device.Manufacturer)
	fmt.Fprintf(writer, "Product: %s\n", am.Device.Product)
	fmt.Fprintf(writer, "Model: %s\n", am.Device.Device)
	fmt.Fprintf(writer, "Android Version: %s (SDK %d)\n", am.Device.AndroidVersion, am.Device.SDKVersion)
	fmt.Fprintf(writer, "Serial: %s\n", am.Device.Serial)
	fmt.Fprintf(writer, "Build Date: %s\n", am.Device.BuildDate)
	fmt.Fprintf(writer, "Fingerprint: %s\n", am.Device.Fingerprint)
	fmt.Fprintf(writer, "IMEI 1: %s\n", am.Device.IMEI1)
	fmt.Fprintf(writer, "IMEI 2: %s\n", am.Device.IMEI2)
	fmt.Fprintf(writer, "Phone Number: %s\n", am.Device.PhoneNumber)
	fmt.Fprintf(writer, "Network Operator: %s\n", am.Device.NetworkOperator)
	fmt.Fprintf(writer, "Rooted: %s\n", boolToYesNo(am.Device.IsRooted))
	fmt.Fprintf(writer, "Encryption: %s\n", am.Device.Encryption)
	fmt.Fprintf(writer, "Encryption Type: %s\n", am.Device.EncryptionType)
	fmt.Fprintf(writer, "Security Patch: %s\n", am.Device.SecurityPatch)
	fmt.Fprintf(writer, "Kernel: %s\n", am.Device.KernelVersion)
	fmt.Fprintf(writer, "Uptime Since: %s\n", am.Device.Uptime)
	writer.Flush()
	
	// Get additional properties
	props := []string{
		"getprop",
		"settings list system",
		"settings list secure", 
		"settings list global",
		"dumpsys iphonesubinfo",
		"dumpsys telephony.registry",
	}
	
	for _, cmd := range props {
		output, err := runADBShell(cmd)
		if err == nil {
			filename := strings.ReplaceAll(cmd, " ", "_") + ".txt"
			os.WriteFile(filepath.Join(acq.OutputDir, filename), []byte(output), 0644)
		}
	}
	
	am.completeAcquisition(acq, true, "")
}

// ==================== COMPREHENSIVE ACQUISITIONS ====================
func (am *AcquisitionManager) acquireLiveCommands() {
	acq := am.startAcquisition("Live Commands")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	commands := []struct {
		cmd  string
		desc string
	}{
		{"id", "User identity"},
		{"uptime", "System uptime"},
		{"printenv", "Environment variables"},
		{"df -h", "Disk usage"},
		{"mount", "Mounted filesystems"},
		{"ip address show wlan0", "Network interface"},
		{"ifconfig -a", "All interfaces"},
		{"netstat -an", "Network connections"},
		{"lsof", "Open files"},
		{"ps -A -f", "Running processes (Detailed)"},
		{"top -n 1", "Process list"},
		{"vmstat", "Virtual memory stats"},
		{"sysctl -a", "System controls"},
		{"ime list", "Input methods"},
		{"logcat -S -b all", "Logcat buffers"},
		{"logcat -d -b all V:*", "Verbose logs"},
	}
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // Limit concurrent commands
	
	for _, cmd := range commands {
		wg.Add(1)
		go func(cmd, desc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			output, err := runADBShell(cmd)
			if err == nil {
				safeName := strings.NewReplacer(" ", "_", "/", "_", "|", "_", "&", "_", ">", "_", "<", "_").Replace(cmd)
				outfile := filepath.Join(acq.OutputDir, safeName+".txt")
				
				file, err := os.Create(outfile)
				if err == nil {
					writer := bufio.NewWriter(file)
					fmt.Fprintf(writer, "Command: %s\n", cmd)
					fmt.Fprintf(writer, "Description: %s\n", desc)
					fmt.Fprintf(writer, "Time: %s\n", getTimestamp())
					fmt.Fprintf(writer, "\n%s\n", output)
					writer.Flush()
					file.Close()
				}
			}
			time.Sleep(100 * time.Millisecond)
		}(cmd.cmd, cmd.desc)
	}
	
	wg.Wait()
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquireDumpsysComprehensive() {
	acq := am.startAcquisition("Dumpsys Comprehensive")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	dumpsysCommands := []struct {
		cmd  string
		desc string
	}{
		{"dumpsys usagestats", "App Usage Statistics"},
		{"dumpsys account", "Account information"},
		{"dumpsys activity", "Activity manager"},
		{"dumpsys alarm", "Alarm manager"},
		{"dumpsys appops", "Application operations"},
		{"dumpsys battery", "Battery information"},
		{"dumpsys batterystats -c", "Battery statistics"},
		{"dumpsys bluetooth_manager", "Bluetooth manager"},
		{"dumpsys clipboard", "Clipboard manager"},
		{"dumpsys cpuinfo", "CPU information"},
		{"dumpsys device_policy", "Device policy"},
		{"dumpsys diskstats", "Disk statistics"},
		{"dumpsys display", "Display manager"},
		{"dumpsys dropbox", "Dropbox manager"},
		{"dumpsys iphonesubinfo", "Phone subscription"},
		{"dumpsys location", "Location manager"},
		{"dumpsys meminfo -a", "Memory information"},
		{"dumpsys netstats", "Network statistics"},
		{"dumpsys notification", "Notification manager"},
		{"dumpsys package", "Package manager"},
		{"dumpsys power", "Power manager"},
		{"dumpsys procstats --full-details", "Process statistics"},
		{"dumpsys telephony.registry", "Telephony registry"},
		{"dumpsys user", "User manager"},
		{"dumpsys usb", "USB manager"},
		{"dumpsys wifi", "WiFi manager"},
		{"dumpsys window", "Window manager"},
	}
	
	// Create appops directory
	appopsDir := filepath.Join(acq.OutputDir, "appops")
	os.MkdirAll(appopsDir, 0755)
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	
	// Run dumpsys commands
	for _, cmd := range dumpsysCommands {
		wg.Add(1)
		go func(cmd, desc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			output, err := runADBShell(cmd)
			if err == nil {
				safeName := strings.ReplaceAll(desc, " ", "_") + ".txt"
				outfile := filepath.Join(acq.OutputDir, safeName)
				os.WriteFile(outfile, []byte(output), 0644)
			}
			time.Sleep(200 * time.Millisecond)
		}(cmd.cmd, cmd.desc)
	}
	
	// Get bugreport
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		
		bugreportFile := filepath.Join(acq.OutputDir, "bugreport.zip")
		runADB("bugreport", bugreportFile)
	}()
	
	// Get appops for each package
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		
		output, err := runADBShell("pm list packages")
		if err == nil {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "package:") {
					pkg := strings.TrimPrefix(line, "package:")
					cmd := fmt.Sprintf("appops get %s", pkg)
					output, _ := runADBShell(cmd)
					if output != "" {
						safeName := strings.ReplaceAll(pkg, ".", "_") + ".txt"
						os.WriteFile(filepath.Join(appopsDir, safeName), []byte(output), 0644)
					}
				}
			}
		}
	}()
	
	wg.Wait()
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquirePackageManager() {
	acq := am.startAcquisition("Package Manager")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	pmCommands := []struct {
		cmd  string
		desc string
		file string
	}{
		{"pm list packages -f", "All packages with paths", "packages_all.txt"},
		{"pm list packages -d", "Disabled packages", "packages_disabled.txt"},
		{"pm list packages -e", "Enabled packages", "packages_enabled.txt"},
		{"pm list packages -s", "System packages", "packages_system.txt"},
		{"pm list packages -3", "Third-party packages", "packages_thirdparty.txt"},
		{"pm list features", "Device features", "features.txt"},
		{"pm list permission-groups", "Permission groups", "permission_groups.txt"},
		{"pm list libraries", "Shared libraries", "libraries.txt"},
		{"pm list users", "Users on device", "users.txt"},
		{"pm get-max-users", "Maximum users", "max_users.txt"},
		{"pm list instrumentation", "Instrumentation", "instrumentation.txt"},
	}
	
	for _, cmd := range pmCommands {
		output, err := runADBShell(cmd.cmd)
		if err == nil {
			os.WriteFile(filepath.Join(acq.OutputDir, cmd.file), []byte(output), 0644)
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquireContentProviders() {
	acq := am.startAcquisition("Content Providers")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	// Get list of content providers first
	output, err := runADBShell("dumpsys package providers")
	if err == nil {
		os.WriteFile(filepath.Join(acq.OutputDir, "content_providers_list.txt"), []byte(output), 0644)
	}
	
	// Common content provider queries
	queries := []struct {
		uri  string
		name string
	}{
		// Calendar
		{"content://com.android.calendar/calendars", "calendar_calendars"},
		{"content://com.android.calendar/events", "calendar_events"},
		{"content://com.android.calendar/attendees", "calendar_attendees"},
		{"content://com.android.calendar/reminders", "calendar_reminders"},
		
		// Contacts
		{"content://com.android.contacts/contacts", "contacts_contacts"},
		{"content://com.android.contacts/data/phones", "contacts_phones"},
		{"content://com.android.contacts/data/emails", "contacts_emails"},
		{"content://com.android.contacts/raw_contacts", "contacts_raw"},
		
		// Settings
		{"content://settings/system", "settings_system"},
		{"content://settings/secure", "settings_secure"},
		{"content://settings/global", "settings_global"},
		
		// Media
		{"content://media/external/images/media", "media_images"},
		{"content://media/external/audio/media", "media_audio"},
		{"content://media/external/video/media", "media_video"},
		
		// Browser
		{"content://browser/bookmarks", "browser_bookmarks"},
		{"content://browser/searches", "browser_searches"},
		
		// Downloads
		{"content://downloads/my_downloads", "downloads_my_downloads"},
		{"content://downloads/download", "downloads_download"},
		
		// User Dictionary
		{"content://user_dictionary/words", "user_dictionary"},

		// Communications (High Value)
		{"content://sms", "sms_all"},
		{"content://sms/inbox", "sms_inbox"},
		{"content://sms/sent", "sms_sent"},
		{"content://mms", "mms_all"},
		{"content://call_log/calls", "call_log"},
	}
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2)
	
	for _, query := range queries {
		wg.Add(1)
		go func(uri, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			cmd := fmt.Sprintf("content query --uri %s", uri)
			output, err := runADBShell(cmd)
			if err == nil {
				filename := name + ".txt"
				os.WriteFile(filepath.Join(acq.OutputDir, filename), []byte(output), 0644)
			}
			time.Sleep(500 * time.Millisecond)
		}(query.uri, query.name)
	}
	
	wg.Wait()
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquireSDCard() {
	acq := am.startAcquisition("SD Card")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	sdcardPath := filepath.Join(acq.OutputDir, "sdcard")
	os.MkdirAll(sdcardPath, 0755)
	
	fmt.Println("\n[*] Pulling SD card contents...")
	fmt.Println("    This may take several minutes")
	
	// Try different sdcard paths
	paths := []string{"/sdcard/", "/storage/emulated/0/", "/mnt/sdcard/"}
	
	for _, path := range paths {
		fmt.Printf("  [*] Trying path: %s\n", path)
		_, err := runADB("pull", path, sdcardPath)
		if err == nil {
			break
		}
	}
	
	// Create tar archive
	tarFile := filepath.Join(acq.OutputDir, "sdcard.tar")
	fmt.Println("  [*] Creating archive...")
	cmd := exec.Command("tar", "-cf", tarFile, "-C", sdcardPath, ".")
	cmd.Run()
	
	// Calculate hash
	fmt.Println("  [*] Calculating SHA-256...")
	hash := calculateSHA256(tarFile)
	
	// Save metadata
	metaFile := filepath.Join(acq.OutputDir, "sdcard_metadata.txt")
	meta := "SD Card Acquisition\n"
	meta += fmt.Sprintf("Completed: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	meta += fmt.Sprintf("Archive: %s\n", tarFile)
	meta += fmt.Sprintf("SHA-256: %s\n", hash)
	os.WriteFile(metaFile, []byte(meta), 0644)
	
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquireSystemPartition() {
	acq := am.startAcquisition("System Partition")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	systemPath := filepath.Join(acq.OutputDir, "system")
	os.MkdirAll(systemPath, 0755)
	
	fmt.Println("\n[*] Pulling system partition...")
	
	// System directories to pull
	systemDirs := []string{
		"/system/app",
		"/system/priv-app",
		"/system/etc",
		"/system/framework",
		"/system/lib",
		"/system/lib64",
		"/system/bin",
		"/system/xbin",
		"/system/fonts",
		"/system/media",
		"/system/usr",
		"/system/vendor",
		"/system/product",
	}
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2)
	
	for _, dir := range systemDirs {
		wg.Add(1)
		go func(dir string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			targetDir := filepath.Join(systemPath, filepath.Base(dir))
			os.MkdirAll(targetDir, 0755)
			fmt.Printf("  [*] Pulling %s\n", dir)
			runADB("pull", dir, targetDir)
		}(dir)
	}
	
	wg.Wait()
	
	// Create tar archive
	tarFile := filepath.Join(acq.OutputDir, "system.tar")
	fmt.Println("  [*] Creating archive...")
	cmd := exec.Command("tar", "-cf", tarFile, "-C", systemPath, ".")
	cmd.Run()
	
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquireAPKs() {
	acq := am.startAcquisition("APK Files")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	output, err := runADBShell("pm list packages -f -u")
	if err != nil {
		am.completeAcquisition(acq, false, "Failed to get package list")
		return
	}
	
	// Save package list
	os.WriteFile(filepath.Join(acq.OutputDir, "package_list.txt"), []byte(output), 0644)
	
	apkDir := filepath.Join(acq.OutputDir, "apks")
	os.MkdirAll(apkDir, 0755)
	
	lines := strings.Split(output, "\n")
	total := 0
	successful := 0
	
	for _, line := range lines {
		if strings.Contains(line, "package:/data/app/") {
			total++
			
		
			parts := strings.Split(line, "=")
			if len(parts) < 2 {
				continue
			}
			
			apkPath := strings.TrimPrefix(parts[0], "package:")
			pkgName := parts[1]
			
			fmt.Printf("  [*] Extracting: %s\n", pkgName)
			
			_, err := runADB("pull", apkPath, apkDir)
			if err == nil {
				successful++
			}
			
			time.Sleep(50 * time.Millisecond)
		}
	}
	
	fmt.Printf("[+] Extracted %d/%d APKs\n", successful, total)
	am.completeAcquisition(acq, true, "")
}

func (am *AcquisitionManager) acquireADBBackup() {
	acq := am.startAcquisition("ADB Backup")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	
	backupFile := filepath.Join(acq.OutputDir, "backup.ab")
	
	// Try different backup commands
	backupCommands := []string{
		"backup -all -shared -system -apk -obb -keyvalue",
		"backup -all -apk",
		"backup -apk -shared",
	}
	
	success := false
	for _, backupCmd := range backupCommands {
		fmt.Printf("  [*] Trying: %s\n", backupCmd)
		
		cmdArgs := strings.Fields(backupCmd)
		cmdArgs = append(cmdArgs, "-f", backupFile)
		
		done := make(chan error, 1)
		go func() {
			_, err := runADB(cmdArgs...)
			done <- err
		}()
		
		select {
		case <-time.After(60 * time.Second):
			fmt.Println("  [-] Timeout waiting for backup")
		case err := <-done:
			if err == nil {
				// Check if backup was created
				if info, err := os.Stat(backupFile); err == nil {
					fmt.Printf("[+] Backup created: %s (%.2f MB)\n", 
						backupFile, float64(info.Size())/(1024*1024))
					success = true
					break
				}
			}
			fmt.Println("  [-] Backup attempt failed")
		}
		
		time.Sleep(2 * time.Second)
		if success {
			break
		}
	}
	
	if success {
		hash := calculateSHA256(backupFile)
		fmt.Printf("[+] SHA-256: %s\n", hash)
		am.completeAcquisition(acq, true, "")
	} else {
		am.completeAcquisition(acq, false, "All backup attempts failed")
	}
}

func (am *AcquisitionManager) acquireBugreport() {
	acq := am.startAcquisition("Bugreport")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	bugreportFile := filepath.Join(acq.OutputDir, "bugreport.zip")
	
	fmt.Println("\n[*] Generating bugreport...")
	fmt.Println("    This may take 2-5 minutes")
	
	done := make(chan bool, 1)
	go func() {
		runADB("bugreport", bugreportFile)
		done <- true
	}()
	
	// Show progress
	for i := 0; i < 30; i++ {
		select {
		case <-done:
			fmt.Println("\n[+] Bugreport completed")
			goto completed
		default:
			fmt.Print(".")
			time.Sleep(10 * time.Second)
		}
	}
	
	fmt.Println("\n[-] Bugreport timeout")
	am.completeAcquisition(acq, false, "Timeout generating bugreport")
	return
	
completed:
	if info, err := os.Stat(bugreportFile); err == nil {
		fmt.Printf("[+] Bugreport saved: %s (%.2f MB)\n", 
			bugreportFile, float64(info.Size())/(1024*1024))
		
		hash := calculateSHA256(bugreportFile)
		fmt.Printf("[+] SHA-256: %s\n", hash)
		am.completeAcquisition(acq, true, "")
	} else {
		am.completeAcquisition(acq, false, "Bugreport file not created")
	}
}

func (am *AcquisitionManager) acquireFileSystemDump() {
	acq := am.startAcquisition("File System Dump")
	defer func() {
		if r := recover(); r != nil {
			am.completeAcquisition(acq, false, fmt.Sprintf("Panic: %v", r))
		}
	}()
	
	fsDir := filepath.Join(acq.OutputDir, "filesystem")
	os.MkdirAll(fsDir, 0755)
	
	fmt.Println("\n[*] Starting comprehensive file system dump...")
	
	// Concurrent acquisition of different areas
	var wg sync.WaitGroup
	
	// 1. SD Card
	wg.Add(1)
	go func() {
		defer wg.Done()
		sdcardPath := filepath.Join(fsDir, "sdcard")
		os.MkdirAll(sdcardPath, 0755)
		runADB("pull", "/sdcard/", sdcardPath)
	}()
	
	// 2. System partition
	wg.Add(1)
	go func() {
		defer wg.Done()
		systemPath := filepath.Join(fsDir, "system")
		os.MkdirAll(systemPath, 0755)
		runADB("pull", "/system/app", systemPath)
		runADB("pull", "/system/etc", systemPath)
		runADB("pull", "/system/framework", systemPath)
	}()
	
	// 3. APKs
	wg.Add(1)
	go func() {
		defer wg.Done()
		apkPath := filepath.Join(fsDir, "data_app")
		os.MkdirAll(apkPath, 0755)
		
		output, _ := runADBShell("pm list packages -f -u")
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "package:/data/app/") {
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					apkPathStr := strings.TrimPrefix(parts[0], "package:")
					runADB("pull", apkPathStr, apkPath)
				}
			}
		}
	}()
	
	// 4. Important system files
	wg.Add(1)
	go func() {
		defer wg.Done()
		sysfilesPath := filepath.Join(fsDir, "system_files")
		os.MkdirAll(sysfilesPath, 0755)
		
		importantFiles := []string{
			"/proc/version",
			"/proc/cpuinfo",
			"/proc/meminfo",
			"/proc/partitions",
			"/proc/mounts",
			"/etc/hosts",
		}
		
		for _, file := range importantFiles {
			output, _ := runADBShell(fmt.Sprintf("cat %s", file))
			safeName := strings.ReplaceAll(strings.TrimPrefix(file, "/"), "/", "_")
			os.WriteFile(filepath.Join(sysfilesPath, safeName), []byte(output), 0644)
		}
	}()
	
	wg.Wait()
	
	// Create tar archive
	tarFile := filepath.Join(acq.OutputDir, "filesystem.tar")
	fmt.Println("  [*] Creating archive...")
	cmd := exec.Command("tar", "-cf", tarFile, "-C", fsDir, ".")
	cmd.Run()
	
	hash := calculateSHA256(tarFile)
	fmt.Printf("[+] SHA-256: %s\n", hash)
	
	am.completeAcquisition(acq, true, "")
}

// ==================== INTERACTIVE MENU ====================
func showDeviceBanner(dev *DeviceInfo) {
	clearScreen()
	const width = 74 // Fixed total width
	
	border := strings.Repeat("═", width-2)
	
	// Helper to print a centered line with borders
	printCentered := func(s string) {
		padding := width - 2 - len(s)
		if padding < 0 { padding = 0 }
		leftPad := padding / 2
		rightPad := padding - leftPad
		fmt.Printf("║%s%s%s║\n", strings.Repeat(" ", leftPad), s, strings.Repeat(" ", rightPad))
	}

	// Helper to print a Key-Value row with dynamic padding
	printRow := func(key string, value string) {
		rowContent := fmt.Sprintf(" %-16s %s", key+":", value)
		
		// Calculate visual length
		runes := []rune(rowContent)
		l := len(runes)
		
		padding := (width - 2) - l
		if padding < 0 { padding = 0 }
		
		fmt.Printf("║%s%s║\n", rowContent, strings.Repeat(" ", padding))
	}
	
	fmt.Printf("╔%s╗\n", border)
	printCentered(fmt.Sprintf("ANDROID TRIAGE TOOL v%s - DEVICE INFO", Version))
	fmt.Printf("╠%s╣\n", border)
	
	printRow("Device", dev.Product)
	printRow("Manufacturer", dev.Manufacturer)
	printRow("Android", fmt.Sprintf("%s (SDK %d)", dev.AndroidVersion, dev.SDKVersion))
	printRow("Android ID", dev.AndroidID)
	printRow("Serial", dev.Serial)
	printRow("IMEI 1", dev.IMEI1)
	printRow("IMEI 2", dev.IMEI2)
	printRow("Rooted", boolToYesNo(dev.IsRooted))
	
	fmt.Printf("╚%s╝\n", border)
}

func showMainMenu() {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                          MAIN MENU                                     ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  1.  Device Information                                                ║")
	fmt.Println("║  2.  Live Commands Execution                                           ║")
	fmt.Println("║  3.  Package Manager Analysis                                          ║")
	fmt.Println("║  4.  Dumpsys Comprehensive Collection                                  ║")
	fmt.Println("║  5.  Content Provider Extraction                                       ║")
	fmt.Println("║  6.  SD Card Acquisition                                               ║")
	fmt.Println("║  7.  System Partition Acquisition                                      ║")
	fmt.Println("║  8.  APK File Extraction                                               ║")
	fmt.Println("║  9.  ADB Backup (Full device)                                          ║")
	fmt.Println("║  10. Bugreport Generation                                              ║")
	fmt.Println("║  11. File System Dump (Complete)                                       ║")
	fmt.Println("║  12. Run All Acquisitions                                              ║")
	fmt.Println("║  13. Generate Report                                                   ║")
	fmt.Println("║  14. Exit                                                              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nSelect option (1-14): ")
}

func runInteractiveMenu(am *AcquisitionManager) {
	reader := bufio.NewReader(os.Stdin)
	
	for {
		showDeviceBanner(am.Device)
		showMainMenu()
		
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		
		switch input {
		case "1":
			am.saveDeviceInfo()
		case "2":
			am.acquireLiveCommands()
		case "3":
			am.acquirePackageManager()
		case "4":
			am.acquireDumpsysComprehensive()
		case "5":
			am.acquireContentProviders()
		case "6":
			am.acquireSDCard()
		case "7":
			am.acquireSystemPartition()
		case "8":
			am.acquireAPKs()
		case "9":
			am.acquireADBBackup()
		case "10":
			am.acquireBugreport()
		case "11":
			am.acquireFileSystemDump()
		case "12":
			runAllAcquisitions(am)
		case "13":
			generateReport(am)
		case "14":
			fmt.Println("\n[*] Exiting Android Triage Tool...")
			fmt.Println("[*] Thank you for using our professional forensic tool!")
			return
		default:
			fmt.Println("\n[-] Invalid choice. Please enter 1-14.")
		}
		
		if input != "14" {
			fmt.Println("\nPress Enter to continue...")
			reader.ReadString('\n')
		}
	}
}

func runAllAcquisitions(am *AcquisitionManager) {
	fmt.Println("\n[*] Running all acquisitions...")
	fmt.Println("    This will take significant time and storage space")
	fmt.Print("\nAre you sure? (y/n): ")
	
	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "y" {
		return
	}
	
	acquisitions := []func(*AcquisitionManager){
		(*AcquisitionManager).saveDeviceInfo,
		(*AcquisitionManager).acquireLiveCommands,
		(*AcquisitionManager).acquirePackageManager,
		(*AcquisitionManager).acquireDumpsysComprehensive,
		(*AcquisitionManager).acquireContentProviders,
		(*AcquisitionManager).acquireSDCard,
		(*AcquisitionManager).acquireBugreport,
	}
	
	fmt.Println("\n════════════════════════════════════════════════════════")
	fmt.Println("           STARTING COMPREHENSIVE ACQUISITION           ")
	fmt.Println("════════════════════════════════════════════════════════")
	
	for i, acquisition := range acquisitions {
		fmt.Printf("\n[%d/%d] ", i+1, len(acquisitions))
		acquisition(am)
	}
	
	fmt.Println("\n════════════════════════════════════════════════════════")
	fmt.Println("            ALL ACQUISITIONS COMPLETED!                 ")
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Println("[*] Note: ADB Backup requires manual user approval")
	fmt.Println("[*] Data saved to:", am.BaseDir)
}

func generateReport(am *AcquisitionManager) {
	reportDir := filepath.Join(am.BaseDir, "REPORT_"+getTimestamp())
	os.MkdirAll(reportDir, 0755)
	
	fmt.Println("\n[*] Generating comprehensive report...")
	
	// Create HTML report
	htmlReport := filepath.Join(reportDir, "forensic_report.html")
	html := generateHTMLReport(am)
	os.WriteFile(htmlReport, []byte(html), 0644)
	
	// Create JSON summary
	summary := map[string]interface{}{
		"device": am.Device,
		"acquisitions": am.Acquisitions,
		"summary": map[string]interface{}{
			"total_acquisitions": len(am.Acquisitions),
			"successful": countSuccessful(am.Acquisitions),
			"failed": countFailed(am.Acquisitions),
			"total_files": countTotalFiles(am.Acquisitions),
			"report_generated": time.Now().Format("2006-01-02 15:04:05"),
		},
	}
	
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile(filepath.Join(reportDir, "summary.json"), summaryJSON, 0644)
	
	// Create text summary
	textReport := filepath.Join(reportDir, "report_summary.txt")
	var text strings.Builder
	
	text.WriteString("ANDROID FORENSIC REPORT\n")
	text.WriteString("=======================\n\n")
	text.WriteString(fmt.Sprintf("Report Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	text.WriteString(fmt.Sprintf("Tool Version: %s\n", Version))
	text.WriteString(fmt.Sprintf("Device: %s %s\n", am.Device.Manufacturer, am.Device.Product))
	text.WriteString(fmt.Sprintf("Android: %s (SDK %d)\n", am.Device.AndroidVersion, am.Device.SDKVersion))
	text.WriteString(fmt.Sprintf("Android ID: %s\n", am.Device.AndroidID))
	text.WriteString(fmt.Sprintf("IMEI 1: %s\n", am.Device.IMEI1))
	text.WriteString(fmt.Sprintf("IMEI 2: %s\n", am.Device.IMEI2))
	text.WriteString(fmt.Sprintf("Rooted: %s\n", boolToYesNo(am.Device.IsRooted)))
	text.WriteString("\nACQUISITION SUMMARY\n")
	text.WriteString("===================\n")
	
	for _, acq := range am.Acquisitions {
		status := "SUCCESS"
		if !acq.Success {
			status = "FAILED"
		}
		text.WriteString(fmt.Sprintf("%s: %s (%s, %d files)\n", 
			status, acq.Name, acq.Duration, len(acq.Files)))
	}
	
	os.WriteFile(textReport, []byte(text.String()), 0644)
	
	fmt.Printf("[+] Report generated in: %s\n", reportDir)
	fmt.Println("[+] Files created:")
	fmt.Println("    - forensic_report.html (HTML report)")
	fmt.Println("    - summary.json (JSON data)")
	fmt.Println("    - report_summary.txt (Text summary)")
}

func countSuccessful(acqs []*Acquisition) int {
	count := 0
	for _, acq := range acqs {
		if acq.Success {
			count++
		}
	}
	return count
}

func countFailed(acqs []*Acquisition) int {
	count := 0
	for _, acq := range acqs {
		if !acq.Success {
			count++
		}
	}
	return count
}

func countTotalFiles(acqs []*Acquisition) int {
	total := 0
	for _, acq := range acqs {
		total += len(acq.Files)
	}
	return total
}

func generateHTMLReport(am *AcquisitionManager) string {
	var html strings.Builder
	
	html.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Android Forensic Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .device-info { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
        .info-item { background: white; padding: 10px; border-radius: 3px; border-left: 4px solid #3498db; }
        .acquisition { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .success { border-left: 4px solid #2ecc71; }
        .failed { border-left: 4px solid #e74c3c; }
        .file-list { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 12px; }
        .hash { font-family: monospace; color: #7f8c8d; font-size: 11px; }
        .summary { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin: 30px 0; }
        .timestamp { color: #7f8c8d; font-size: 14px; text-align: right; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Android Forensic Report</h1>
        <div class="timestamp">Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>Tool: Android Triage v` + Version + `</p>
            <p>Total Acquisitions: ` + strconv.Itoa(len(am.Acquisitions)) + `</p>
            <p>Successful: ` + strconv.Itoa(countSuccessful(am.Acquisitions)) + ` | Failed: ` + strconv.Itoa(countFailed(am.Acquisitions)) + `</p>
            <p>Total Files Collected: ` + strconv.Itoa(countTotalFiles(am.Acquisitions)) + `</p>
        </div>
        
        <h2>Device Information</h2>
        <div class="device-info">
            <div class="info-grid">
                <div class="info-item"><strong>Device:</strong> ` + am.Device.Product + `</div>
                <div class="info-item"><strong>Manufacturer:</strong> ` + am.Device.Manufacturer + `</div>
                <div class="info-item"><strong>Android:</strong> ` + am.Device.AndroidVersion + ` (SDK ` + strconv.Itoa(am.Device.SDKVersion) + `)</div>
                <div class="info-item"><strong>Android ID:</strong> ` + am.Device.AndroidID + `</div>
                <div class="info-item"><strong>IMEI 1:</strong> ` + am.Device.IMEI1 + `</div>
                <div class="info-item"><strong>IMEI 2:</strong> ` + am.Device.IMEI2 + `</div>
                <div class="info-item"><strong>Serial:</strong> ` + am.Device.Serial + `</div>
                <div class="info-item"><strong>Rooted:</strong> ` + boolToYesNo(am.Device.IsRooted) + `</div>
            </div>
        </div>
        
        <h2>Acquisition Details</h2>`)
	
	for _, acq := range am.Acquisitions {
		statusClass := "success"
		statusIndicator := "[OK]"
		if !acq.Success {
			statusClass = "failed"
			statusIndicator = "[FAIL]"
		}

		html.WriteString(fmt.Sprintf(`
        <div class="acquisition %s">
            <h3>%s %s</h3>
            <p><strong>Duration:</strong> %s | <strong>Files:</strong> %d | <strong>Output:</strong> %s</p>`,
			statusClass, statusIndicator, acq.Name, acq.Duration, len(acq.Files), acq.OutputDir))
		
		if !acq.Success && acq.Error != "" {
			html.WriteString(fmt.Sprintf(`<p><strong>Error:</strong> %s</p>`, acq.Error))
		}
		
		if len(acq.Files) > 0 {
			html.WriteString(`<div class="file-list"><strong>Files:</strong><ul>`)
			for _, file := range acq.Files {
				if len(file) > 100 {
					file = "..." + file[len(file)-100:]
				}
				hash := acq.Hashes[file]
				if len(hash) > 16 {
					hash = hash[:16] + "..."
				}
				html.WriteString(fmt.Sprintf(`<li>%s <span class="hash">[%s]</span></li>`, file, hash))
			}
			html.WriteString(`</ul></div>`)
		}
		
		html.WriteString(`</div>`)
	}
	
	html.WriteString(`
    </div>
</body>
</html>`)
	
	return html.String()
}
