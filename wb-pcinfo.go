package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

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
	filename := fmt.Sprintf("pcinfo--%s.txt", timestamp)

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
	buffer.WriteString(fmt.Sprintf("OS: %s\n", hostInfo.Platform))
	buffer.WriteString(fmt.Sprintf("OS Version: %s\n", hostInfo.PlatformVersion))
	buffer.WriteString(fmt.Sprintf("OS Install Date: %s (%s)\n", installDate, relativeTime))

	// Last Reboot Time with Relative Time
	lastReboot := formatTime(hostInfo.BootTime)
	uptime := formatUptime(hostInfo.Uptime)
	buffer.WriteString(fmt.Sprintf("Last Reboot Time: %s (%s)\n", lastReboot, uptime))

	// Active and Logged-in Users
	buffer.WriteString("Current Users:\n")
	buffer.WriteString(collectActiveUsers())

	// CPU Info
	cpuInfo, _ := cpu.Info()
	if len(cpuInfo) > 0 {
		buffer.WriteString(fmt.Sprintf("CPU Model: %s\n", cpuInfo[0].ModelName))
		buffer.WriteString(fmt.Sprintf("CPU Speed: %.2f GHz\n", cpuInfo[0].Mhz/1000.0))
	}

	// Memory Info
	vm, _ := mem.VirtualMemory()
	buffer.WriteString(fmt.Sprintf("RAM Amount: %.2f GB\n", float64(vm.Total)/(1024*1024*1024)))

	// Network Info
	buffer.WriteString(collectNetworkInfo())

	// Top Processes
	buffer.WriteString("\nTop 10 CPU-Using Processes:\n")
	buffer.WriteString(getTopProcessesByCPU(10))
	buffer.WriteString("\nTop 10 RAM-Using Processes:\n")
	buffer.WriteString(getTopProcessesByRAM(10))

	return buffer.String()
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
		return fmt.Sprintf("- %s (Active)\n", username)
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
			result.WriteString(fmt.Sprintf("- %s (TTY: %s)\n", fields[0], fields[1]))
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
