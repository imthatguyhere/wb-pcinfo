package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

func main() {
	// Generate timestamp
	timestamp := time.Now().Format("2006-01-02--03-04-05.000-PM")

	// File name
	filename := fmt.Sprintf("wb-pcinfo--%s.txt", timestamp)

	// Collect PC Info
	pcInfo := collectPCInfo()

	// Write to file
	err := os.WriteFile(filename, []byte(pcInfo), 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("PC info written to %s\n", filename)
}

func collectPCInfo() string {
	var buffer strings.Builder

	// Host Info
	hostInfo, _ := host.Info()
	installDate, relativeTime := getOSInstallDate()
	buffer.WriteString(fmt.Sprintf("PC Name: %s\n", hostInfo.Hostname))
	buffer.WriteString(fmt.Sprintf("Domain: %s\n", getComputerDomain()))
	buffer.WriteString(fmt.Sprintf("OS: %s\n", hostInfo.Platform))
	buffer.WriteString(fmt.Sprintf("OS Version: %s\n", hostInfo.PlatformVersion))
	buffer.WriteString(fmt.Sprintf("OS Install Date: %s (%s)\n", installDate, relativeTime))

	// Last Reboot Time with Relative Time
	lastReboot := formatTime(hostInfo.BootTime)
	uptime := formatUptime(hostInfo.Uptime)
	buffer.WriteString(fmt.Sprintf("Last Reboot Time: %s %s\n", lastReboot, uptime))

	// Active and Logged-in Users
	buffer.WriteString("Current Users:\n")
	buffer.WriteString(collectActiveUsers())

	// CPU Info
	physicalCoreCount, err := cpu.Counts(false)
	if err != nil {
		log.Fatalf("Error getting total physical core count: %v", err)
	}
	cpuInfo, err := cpu.Info()
	numCPUs := len(cpuInfo)
	physicalCoresPerCPU := physicalCoreCount / numCPUs

	buffer.WriteString(fmt.Sprintf("Number of CPUs: %d\n", len(cpuInfo)))
	buffer.WriteString(fmt.Sprintf("Total CPU Cores: %s\n", getCPUCores()))

	if err != nil {
		buffer.WriteString(fmt.Sprintf("Error retrieving CPU information: %v\n", err))
	} else {
		for i, info := range cpuInfo {
			buffer.WriteString(fmt.Sprintf("CPU %d:\n", i+1))
			buffer.WriteString(fmt.Sprintf("  Model: %s\n", info.ModelName))
			buffer.WriteString(fmt.Sprintf("  Speed: %.2f GHz\n", info.Mhz/1000.0))
			buffer.WriteString(fmt.Sprintf("  Total CPU Cores: %d Logical Cores (%d Cores and %d Threads [SMT] <Estimated>) \n", info.Cores, physicalCoresPerCPU, (info.Cores - int32(physicalCoresPerCPU))))
		}
	}

	// Memory Info
	vm, _ := mem.VirtualMemory()
	buffer.WriteString(fmt.Sprintf("RAM Amount: %.2f GB\n", float64(vm.Total)/(1024*1024*1024)))
	buffer.WriteString(fmt.Sprintf("RAM Used: %.2f GB / %.2f GB (%.0f%%)\n", float64(vm.Used)/(1024*1024*1024), float64(vm.Total)/(1024*1024*1024), vm.UsedPercent))
	buffer.WriteString(fmt.Sprintf("RAM Available: %.2f GB\n", float64(vm.Available)/(1024*1024*1024)))
	buffer.WriteString(fmt.Sprintf("RAM Details:\n%s", strings.Replace(convertBytesToMB(addIndentationSpaces(removeEmptyNewlines(getRAMDetails()), 2)), "PartNumber", "Part Number", -1)))

	// GPU Info
	buffer.WriteString(fmt.Sprintf("\nGPU Details:\n%s\n\n", strings.Replace(convertBytesToMB(addIndentationSpaces(removeEmptyNewlines(getGPUDetails()), 2)), "AdapterRAM", "Adapter RAM", -1)))

	// Hard Drive Info
	hardDrives, err := getHardDrivesInfo()
	if err != nil {
		fmt.Printf("Error retrieving hard drive info: %v\n", err)
	}

	for _, drive := range hardDrives {
		buffer.WriteString(fmt.Sprintf("Drive: %s\n", drive.Mapping))
		buffer.WriteString(fmt.Sprintf("  Model: %s\n", drive.Model))
		buffer.WriteString(fmt.Sprintf("  Type: %s\n", drive.Type))
		//buffer.WriteString(fmt.Sprintf("  Form Factor: %s\n", drive.FormFactor))
		buffer.WriteString(fmt.Sprintf("  Total Size: %.2f GB\n", drive.TotalSize))
	}

	// Network Info
	buffer.WriteString(collectNetworkInfo())

	// OS Patches
	buffer.WriteString(fmt.Sprintf("\nLatest OS Patches:\n%s\n", strings.Replace(strings.Replace(convertDates(addIndentationSpaces(removeEmptyNewlines(getLastOSPatch()), 2)), "InstalledOn", "Installed On", -1), "HotFixID ", "HotFix ID", -1)))

	// Top Processes
	buffer.WriteString("\nTop 10 CPU-Using Processes:\n")
	buffer.WriteString(addIndentationSpaces(getTopProcessesByCPU(10), 2))
	buffer.WriteString("\nTop 10 RAM-Using Processes:\n")
	buffer.WriteString(addIndentationSpaces(getTopProcessesByRAM(10), 2))

	return buffer.String()
}

func getCPUCores() string {
	// Get logical core count
	logicalCores, err := cpu.Counts(true)
	if err != nil {
		log.Fatalf("Error getting logical core count: %v", err)
	}

	// Get physical core count
	physicalCores, err := cpu.Counts(false)
	if err != nil {
		log.Fatalf("Error getting physical core count: %v", err)
	}

	out := fmt.Sprintf("%d Logical Cores (%d Cores and %d Threads [SMT])", logicalCores, physicalCores, (logicalCores - physicalCores))

	return string(out)
}
func addIndentationSpaces(input string, spaces int) string {
	indent := strings.Repeat(" ", spaces)
	lines := strings.Split(input, "\n")
	for i := range lines {
		lines[i] = indent + lines[i]
	}
	return strings.Join(lines, "\n")
}

func removeEmptyNewlines(input string) string {
	var result []string
	lines := strings.Split(input, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line) // Trim spaces, tabs, and other invisible characters
		if trimmed != "" {
			result = append(result, trimmed) // Append trimmed line to result
		}
	}
	return strings.Join(result, "\n")
}

func convertDates(input string) string {
	re := regexp.MustCompile(`\b(\d{1,2})/(\d{1,2})/(\d{4})\b`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		// Parse the captured groups for month, day, and year
		matches := re.FindStringSubmatch(match)
		if len(matches) != 4 {
			return match // Return the original string if no match
		}

		// Extract and pad month, day, and year
		month := fmt.Sprintf("%02d", atoi(matches[1])) // Pad month to 2 digits
		day := fmt.Sprintf("%02d", atoi(matches[2]))   // Pad day to 2 digits
		year := matches[3]                             // Year is already 4 digits

		// Return the formatted date
		return fmt.Sprintf("%s-%s-%s", year, month, day)
	})
}

// atoi converts a string to an integer, returning 0 on error
func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func convertBytesToMB(input string) string {
	re := regexp.MustCompile(`\b\d+\b`)
	result := re.ReplaceAllStringFunc(input, func(match string) string {
		bytes, err := strconv.ParseInt(match, 10, 64)
		if err != nil {
			return match
		}

		// Skip numbers smaller than 1MB
		if bytes < 1024*1024 {
			return match
		}

		// Convert bytes to MB
		mb := float64(bytes) / (1024 * 1024)
		newValue := fmt.Sprintf("%.0f MB", mb)

		// Calculate the difference in length
		lengthDiff := len(match) - len(newValue)

		// Add spaces to compensate for the difference
		if lengthDiff > 0 {
			newValue += strings.Repeat(" ", lengthDiff)
		}

		return newValue
	})
	return result
}

func getComputerDomain() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsDomain()
	case "linux":
		return getLinuxDomain()
	case "darwin":
		return getMacOSDomain()
	default:
		return "Unsupported OS for retrieving domain.\n"
	}
}

func getWindowsDomain() string {
	out, err := exec.Command("wmic", "computersystem", "get", "domain").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving domain: %v\n", err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 1 {
		domain := strings.TrimSpace(lines[1])
		if domain != "" && domain != "Domain" { // Exclude header
			return domain
		}
	}
	return "No domain found or not joined to a domain.\n"
}

func getLinuxDomain() string {
	out, err := exec.Command("hostname", "--domain").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving domain: %v\n", err)
	}
	domain := strings.TrimSpace(string(out))
	if domain != "" {
		return domain
	}
	return "No domain found or not joined to a domain.\n"
}

func getMacOSDomain() string {
	out, err := exec.Command("scutil", "--get", "LocalHostName").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving domain: %v\n", err)
	}
	domain := strings.TrimSpace(string(out))
	if domain != "" {
		return domain
	}
	return "No domain found or not joined to a domain.\n"
}

// HardDrive represents the details of a hard drive
type HardDrive struct {
	Mapping        string
	Model          string
	Type           string
	FormFactor     string
	TotalSize      float64
	AvailableSpace float64
}

// getHardDrivesInfo retrieves information about all hard drives on the system
func getHardDrivesInfo() ([]HardDrive, error) {
	switch runtime.GOOS {
	case "windows":
		return getWindowsDrives()
	case "linux":
		return getLinuxDrives()
	case "darwin":
		return getMacOSDrives()
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func inferDriveType(mediaType, interfaceType string) string {
	// Normalize input
	mediaType = strings.ToLower(mediaType)
	interfaceType = strings.ToLower(interfaceType)

	// Use mediaType and interfaceType to infer drive type
	if strings.Contains(mediaType, "ssd") || strings.Contains(interfaceType, "nvme") {
		if strings.Contains(interfaceType, "nvme") {
			return "NVME (PCI connected)"
		}
		return "SSD"
	} else if strings.Contains(mediaType, "hdd") {
		return "HDD"
	} else if strings.Contains(mediaType, "fixed") {
		caser := cases.Title(language.English)
		return caser.String(interfaceType + " " + mediaType)
	} else if strings.Contains(mediaType, "removable") || strings.Contains(interfaceType, "usb") {
		return "External (USB)"
	} else {
		return "Unknown"
	}
}

// getWindowsDrives retrieves hard drive info on Windows
func getWindowsDrives() ([]HardDrive, error) {
	var drives []HardDrive

	// Use WMIC to fetch drive details
	out, err := exec.Command("wmic", "diskdrive", "get", "Caption,DeviceID,Size,MediaType,Model,InterfaceType", "/format:csv").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute wmic diskdrive: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[2:] { // Skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 6 {
			continue
		}

		// Parse WMIC fields
		mapping := fields[2]            // DeviceID (e.g., \\.\PHYSICALDRIVE0)
		model := fields[5]              // Model
		size, _ := parseSize(fields[6]) // Total size in GB
		mediaType := strings.ToLower(fields[4])
		interfaceType := strings.ToLower(fields[3])

		// Determine drive type and form factor
		driveType := inferDriveType(mediaType, interfaceType)
		formFactor := guessFormFactor(driveType, interfaceType)

		// Append the drive info
		drives = append(drives, HardDrive{
			Mapping:    mapping,
			Model:      model,
			Type:       driveType,
			FormFactor: formFactor,
			TotalSize:  size,
		})
	}

	return drives, nil
}

// getLinuxDrives retrieves hard drive info on Linux
func getLinuxDrives() ([]HardDrive, error) {
	var drives []HardDrive

	// Use lsblk to get drive details
	out, err := exec.Command("lsblk", "-o", "NAME,MODEL,SIZE,TYPE,TRAN").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute lsblk: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // Skip header line
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse fields
		device := fmt.Sprintf("/dev/%s", fields[0]) // Full device path
		model := fields[1]                          // Drive model
		size, _ := parseSize(fields[2])             // Size in GB
		deviceType := fields[3]                     // "disk", "part", etc.
		interfaceType := fields[4]                  // Transport type: "sata", "nvme", "usb", etc.

		// Determine drive type
		driveType := inferDriveType(deviceType, interfaceType)

		// Append the drive info
		drives = append(drives, HardDrive{
			Mapping:    device,
			Model:      model,
			Type:       driveType,
			FormFactor: guessFormFactor(driveType, interfaceType),
			TotalSize:  size,
		})
	}

	return drives, nil
}

// getMacOSDrives retrieves hard drive info on macOS
func getMacOSDrives() ([]HardDrive, error) {
	var drives []HardDrive

	// Get all drive information using diskutil
	out, err := exec.Command("diskutil", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute diskutil: %w", err)
	}
	lines := strings.Split(string(out), "\n")

	// Parse each line containing "disk"
	for _, line := range lines {
		if strings.Contains(line, "disk") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}

			// Parse fields
			mapping := fields[0] // e.g., "disk0", "disk1"
			model := fields[2]   // Drive description (may include manufacturer or type)
			size := 0.0          // macOS doesn't directly provide size in `diskutil list`

			// Append the drive info
			drives = append(drives, HardDrive{
				Mapping:    mapping,
				Model:      model,
				Type:       "Unknown", // macOS doesn't directly provide type
				FormFactor: "Unknown", // Form factor determination can be added
				TotalSize:  size,
			})
		}
	}

	return drives, nil
}

// parseSize converts a size string to GB
func parseSize(sizeStr string) (float64, error) {
	size, err := strconv.ParseInt(sizeStr, 10, 64) // Parse size as int64
	if err != nil || size <= 0 {
		return 0, fmt.Errorf("invalid size: %s", sizeStr)
	}
	return float64(size) / (1024 * 1024 * 1024), nil // Convert to GB
}

// parseMediaType converts media type descriptions to a more readable format
func parseMediaType(mediaType string) string {
	switch strings.ToLower(mediaType) {
	case "hdd":
		return "HDD"
	case "ssd":
		return "SSD"
	case "nvme":
		return "NVME (PCI connected)"
	default:
		return "Unknown"
	}
}

// guessFormFactor guesses the form factor based on media type and other hints
func guessFormFactor(driveType, interfaceType string) string {
	driveType = strings.ToLower(driveType)
	interfaceType = strings.ToLower(interfaceType)

	// Map type and interface to likely form factors
	switch {
	case driveType == "hdd" && (interfaceType == "sata" || strings.Contains(interfaceType, "hard") || interfaceType == "scsi"):
		return "3.5 or 2.5in Internal HDD"
	case driveType == "ssd" && interfaceType == "sata":
		return "2.5in Internal SSD"
	case strings.Contains(interfaceType, "nvme"):
		return "m.2"
	case strings.Contains(interfaceType, "usb"):
		return "USB External"
	default:
		return "Unknown"
	}
}
func getRAMDetails() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsRAMDetails()
	case "linux":
		return getLinuxRAMDetails()
	case "darwin":
		return getMacOSRAMDetails()
	default:
		return "Unsupported OS for retrieving RAM details.\n"
	}
}

func getWindowsRAMDetails() string {
	out, err := exec.Command("wmic", "memorychip", "get", "Capacity,Manufacturer,PartNumber").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving RAM details: %v\n", err)
	}
	return string(out)
}

func getLinuxRAMDetails() string {
	out, err := exec.Command("sudo", "dmidecode", "--type", "memory").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving RAM details: %v\n", err)
	}
	return string(out)
}

func getMacOSRAMDetails() string {
	out, err := exec.Command("system_profiler", "SPMemoryDataType").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving RAM details: %v\n", err)
	}
	return string(out)
}

func getGPUDetails() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsGPUDetails()
	case "linux":
		return getLinuxGPUDetails()
	case "darwin":
		return getMacOSGPUDetails()
	default:
		return "Unsupported OS for retrieving GPU details.\n"
	}
}

func getWindowsGPUDetails() string {
	out, err := exec.Command("wmic", "path", "win32_VideoController", "get", "Name,AdapterRAM").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving GPU details: %v\n", err)
	}
	return string(out)
}

func getLinuxGPUDetails() string {
	out, err := exec.Command("lspci", "|", "grep", "-i", "vga").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving GPU details: %v\n", err)
	}
	return string(out)
}

func getMacOSGPUDetails() string {
	out, err := exec.Command("system_profiler", "SPDisplaysDataType").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving GPU details: %v\n", err)
	}
	return string(out)
}

func getLastOSPatch() string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsLastOSPatch()
	case "linux":
		return getLinuxLastOSPatch()
	case "darwin":
		return getMacOSLastOSPatch()
	default:
		return "Unsupported OS for retrieving last OS patch.\n"
	}
}

func getWindowsLastOSPatch() string {
	out, err := exec.Command("wmic", "qfe", "get", "Description,HotfixID,InstalledOn").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving last OS patch: %v\n", err)
	}
	return string(out)
}

func getLinuxLastOSPatch() string {
	out, err := exec.Command("tail", "-n", "1", "/var/log/dpkg.log").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving last OS patch: %v\n", err)
	}
	return string(out)
}

func getMacOSLastOSPatch() string {
	out, err := exec.Command("softwareupdate", "--history").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving last OS patch: %v\n", err)
	}
	return string(out)
}

func getOSInstallDate() (string, string) {
	switch runtime.GOOS {
	case "windows":
		return getWindowsInstallDate()
	case "linux":
		return getLinuxInstallDate()
	case "darwin":
		return getMacOSInstallDate()
	default:
		return "Unsupported OS for retrieving install date.", ""
	}
}

func getWindowsInstallDate() (string, string) {
	out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "InstallDate").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving install date: %v", err), ""
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "InstallDate") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				// Parse the hexadecimal value in the registry
				installTimestamp, err := strconv.ParseInt(fields[2], 0, 64) // `0` detects base from "0x" prefix
				if err != nil {
					return fmt.Sprintf("Error parsing install date: %v", err), ""
				}
				installDate := time.Unix(installTimestamp, 0)
				relativeTime := calculateRelativeTime(installDate)
				return installDate.Format("2006-01-02 15:04:05"), relativeTime
			}
		}
	}
	return "Unable to determine install date.", ""
}

func getLinuxInstallDate() (string, string) {
	out, err := exec.Command("stat", "/lost+found").Output()
	if err != nil {
		return fmt.Sprintf("Error retrieving install date: %v", err), ""
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Birth:") {
			installDate := strings.TrimSpace(strings.TrimPrefix(line, "Birth:"))
			parsedDate, err := time.Parse("2006-01-02 15:04:05", installDate)
			if err != nil {
				return fmt.Sprintf("Error parsing install date: %v", err), ""
			}
			relativeTime := calculateRelativeTime(parsedDate)
			return installDate, relativeTime
		}
	}
	return "Unable to determine install date.", ""
}

func getMacOSInstallDate() (string, string) {
	uptimeSeconds, err := host.Uptime()
	if err != nil {
		return fmt.Sprintf("Error retrieving uptime: %v", err), ""
	}
	uptimeDuration := time.Duration(uptimeSeconds) * time.Second
	installDate := time.Now().Add(-uptimeDuration)
	relativeTime := calculateRelativeTime(installDate)
	return installDate.Format("2006-01-02 15:04:05"), relativeTime
}

func calculateRelativeTime(installDate time.Time) string {
	now := time.Now()
	duration := now.Sub(installDate)

	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60

	return fmt.Sprintf("%d days, %02d hours, %02d minutes ago", days, hours, minutes)
}

// Collects active and logged-in users based on the OS
func collectActiveUsers() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-Command", "Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName").Output()
		if err != nil {
			return fmt.Sprintf("Error fetching users: %v\nEnsure the program is run with administrator privileges.\n", err)
		}
		username := strings.TrimSpace(string(out))
		if username == "" {
			return "No active users found.\n"
		}
		return fmt.Sprintf("  - %s (Active)\n", username)
	case "linux", "darwin":
		out, err := exec.Command("who").Output()
		if err != nil {
			return fmt.Sprintf("Error fetching users: %v\n", err)
		}
		return parseUnixUsers(string(out))
	default:
		return "Unsupported OS for fetching users.\n"
	}
}

func parseUnixUsers(output string) string {
	var result strings.Builder
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result.WriteString(fmt.Sprintf("  - %s (TTY: %s)\n", fields[0], fields[1]))
		}
	}
	return result.String()
}

// Collects network-related information
func collectNetworkInfo() string {
	var result strings.Builder

	// List all network adapters
	adapters, err := net.Interfaces()
	if err != nil {
		return fmt.Sprintf("Error retrieving network adapters: %v\n", err)
	}

	for _, adapter := range adapters {
		result.WriteString(fmt.Sprintf("\nNetwork Adapter: %s\n", adapter.Name))
		if len(adapter.Addrs) > 0 {
			result.WriteString(fmt.Sprintf("  IP Address: %s\n", adapter.Addrs[0].Addr))
		}
		result.WriteString(fmt.Sprintf("  MAC Address: %s\n", adapter.HardwareAddr))
	}

	// Platform-specific logic for additional details
	switch runtime.GOOS {
	case "windows":
		result.WriteString(getWindowsNetworkDetails())
	case "linux":
		result.WriteString(getLinuxNetworkDetails())
	case "darwin":
		result.WriteString(getMacOSNetworkDetails())
	}

	return result.String()
}

// Platform-specific network details
func getWindowsNetworkDetails() string {
	var result strings.Builder

	out, err := exec.Command("cmd", "/C", "netsh wlan show interfaces").Output()
	if err == nil {
		result.WriteString(parseWindowsSSID(string(out)))
	}

	out, err = exec.Command("cmd", "/C", "netsh wlan show profiles").Output()
	if err == nil {
		result.WriteString(parseWindowsSavedNetworks(string(out)))
	}

	return result.String()
}

func parseWindowsSSID(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "SSID") && !strings.Contains(line, "BSSID") {
			return fmt.Sprintf("Active WiFi Network: %s\n", strings.TrimSpace(strings.Split(line, ":")[1]))
		}
	}
	return "No active WiFi network found.\n"
}

func parseWindowsSavedNetworks(output string) string {
	var result strings.Builder
	result.WriteString("Saved WiFi Networks:\n")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "All User Profile") {
			network := strings.TrimSpace(strings.Split(line, ":")[1])
			result.WriteString(fmt.Sprintf("- %s\n", network))
		}
	}
	return result.String()
}

func getLinuxNetworkDetails() string {
	var result strings.Builder

	// Get the active WiFi SSID
	out, err := exec.Command("nmcli", "-t", "-f", "active,ssid", "dev", "wifi").Output()
	if err == nil {
		result.WriteString(parseLinuxSSID(string(out)))
	}

	// Get saved WiFi networks
	out, err = exec.Command("nmcli", "-t", "-f", "ssid", "connection", "show").Output()
	if err == nil {
		result.WriteString(parseLinuxSavedNetworks(string(out)))
	}

	return result.String()
}

func parseLinuxSSID(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) > 1 && fields[0] == "yes" { // "yes" indicates an active connection
			return fmt.Sprintf("Active WiFi Network: %s\n", fields[1])
		}
	}
	return "No active WiFi network found.\n"
}

func parseLinuxSavedNetworks(output string) string {
	var result strings.Builder
	result.WriteString("Saved WiFi Networks:\n")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			result.WriteString(fmt.Sprintf("- %s\n", line))
		}
	}
	return result.String()
}

func getMacOSNetworkDetails() string {
	var result strings.Builder

	// Get the active WiFi SSID
	out, err := exec.Command("networksetup", "-getairportnetwork", "en0").Output()
	if err == nil {
		result.WriteString(parseMacOSSSID(string(out)))
	}

	// Get saved WiFi networks (requires plist parsing, not implemented here)
	result.WriteString("Saved WiFi Networks: Not implemented on macOS.\n")

	return result.String()
}

func parseMacOSSSID(output string) string {
	if strings.Contains(output, "You are not associated with an AirPort network.") {
		return "No active WiFi network found.\n"
	}
	return fmt.Sprintf("Active WiFi Network: %s\n", strings.TrimSpace(strings.Split(output, ":")[1]))
}

// Process-related details
func getTopProcessesByCPU(limit int) string {
	procs, _ := process.Processes()
	var result strings.Builder

	type cpuInfo struct {
		name     string
		location string
		cpu      float64
	}

	var procInfo []cpuInfo
	for _, proc := range procs {
		name, _ := proc.Name()
		exe, _ := proc.Exe()
		cpuPercent, _ := proc.CPUPercent()
		procInfo = append(procInfo, cpuInfo{name: name, location: exe, cpu: cpuPercent})
	}

	sort.Slice(procInfo, func(i, j int) bool {
		return procInfo[i].cpu > procInfo[j].cpu
	})

	for i, p := range procInfo {
		if i >= limit {
			break
		}
		result.WriteString(fmt.Sprintf("%d. %s (%.2f%% CPU) - %s\n", i+1, p.name, p.cpu, p.location))
	}

	return result.String()
}

func getTopProcessesByRAM(limit int) string {
	procs, _ := process.Processes()
	var result strings.Builder

	type ramInfo struct {
		name     string
		location string
		ram      float32
	}

	var procInfo []ramInfo
	for _, proc := range procs {
		name, _ := proc.Name()
		exe, _ := proc.Exe()
		memPercent, _ := proc.MemoryPercent()
		procInfo = append(procInfo, ramInfo{name: name, location: exe, ram: memPercent})
	}

	sort.Slice(procInfo, func(i, j int) bool {
		return procInfo[i].ram > procInfo[j].ram
	})

	for i, p := range procInfo {
		if i >= limit {
			break
		}
		result.WriteString(fmt.Sprintf("%d. %s (%.2f%% RAM) - %s\n", i+1, p.name, p.ram, p.location))
	}

	return result.String()
}

// Utilities
func formatTime(epoch uint64) string {
	t := time.Unix(int64(epoch), 0)
	return t.Format("2006-01-02 15:04:05")
}

func formatUptime(uptime uint64) string {
	duration := time.Duration(uptime) * time.Second
	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60

	return fmt.Sprintf("(%d days, %02d hours, %02d minutes ago)", days, hours, minutes)
}
