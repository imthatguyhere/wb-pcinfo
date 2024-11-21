package main

import (
	"bytes"
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

// GetOSInstallDate retrieves the OS install date and the relative time since installation.
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

	// Parse the output to extract the install date value
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "InstallDate") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				// Parse the hexadecimal value in the registry
				installTimestamp, err := strconv.ParseInt(fields[2], 0, 64) // `0` auto-detects base from "0x" prefix
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

func collectNetworkInfo() string {
	var buffer bytes.Buffer

	// List all network adapters
	adapters, err := net.Interfaces()
	if err != nil {
		buffer.WriteString(fmt.Sprintf("Error retrieving network adapters: %v\n", err))
		return buffer.String()
	}

	// Display each adapter and its details
	for _, adapter := range adapters {
		buffer.WriteString(fmt.Sprintf("Network Adapter: %s\n", adapter.Name))
		if len(adapter.Addrs) > 0 {
			buffer.WriteString(fmt.Sprintf("  IP Address: %s\n", adapter.Addrs[0].Addr))
		}
		buffer.WriteString(fmt.Sprintf("  MAC Address: %s\n", adapter.HardwareAddr))
		buffer.WriteString(fmt.Sprintf("  Flags: %v\n", adapter.Flags))
	}

	// Platform-specific logic for additional details
	switch runtime.GOOS {
	case "windows":
		buffer.WriteString(collectWindowsNetworkInfo())
	case "linux":
		buffer.WriteString(collectLinuxNetworkInfo())
	case "darwin":
		buffer.WriteString(collectMacOSNetworkInfo())
	default:
		buffer.WriteString("Unsupported OS for detailed network info.\n")
	}

	return buffer.String()
}

// Windows-specific network information
func collectWindowsNetworkInfo() string {
	var buffer bytes.Buffer

	// Get the active WiFi SSID
	out, err := exec.Command("cmd", "/C", "netsh wlan show interfaces").Output()
	if err == nil {
		buffer.WriteString(parseWindowsSSID(string(out)))
	}

	// Get saved WiFi networks
	out, err = exec.Command("cmd", "/C", "netsh wlan show profiles").Output()
	if err == nil {
		buffer.WriteString(parseWindowsSavedNetworks(string(out)))
	}

	return buffer.String()
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
	var buffer bytes.Buffer
	lines := strings.Split(output, "\n")
	buffer.WriteString("Saved WiFi Networks:\n")
	for _, line := range lines {
		if strings.Contains(line, "All User Profile") {
			network := strings.TrimSpace(strings.Split(line, ":")[1])
			buffer.WriteString(fmt.Sprintf("- %s\n", network))
		}
	}
	return buffer.String()
}

// Linux-specific network information
func collectLinuxNetworkInfo() string {
	var buffer bytes.Buffer

	// Get the active WiFi SSID
	out, err := exec.Command("nmcli", "-t", "-f", "active,ssid", "dev", "wifi").Output()
	if err == nil {
		buffer.WriteString(parseLinuxSSID(string(out)))
	}

	// Get saved WiFi networks
	out, err = exec.Command("nmcli", "-t", "-f", "ssid", "connection", "show").Output()
	if err == nil {
		buffer.WriteString(parseLinuxSavedNetworks(string(out)))
	}

	return buffer.String()
}

func parseLinuxSSID(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) > 1 && fields[0] == "yes" {
			return fmt.Sprintf("Active WiFi Network: %s\n", fields[1])
		}
	}
	return "No active WiFi network found.\n"
}

func parseLinuxSavedNetworks(output string) string {
	var buffer bytes.Buffer
	buffer.WriteString("Saved WiFi Networks:\n")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			buffer.WriteString(fmt.Sprintf("- %s\n", line))
		}
	}
	return buffer.String()
}

// macOS-specific network information
func collectMacOSNetworkInfo() string {
	var buffer bytes.Buffer

	// Get the active WiFi SSID
	out, err := exec.Command("networksetup", "-getairportnetwork", "en0").Output()
	if err == nil {
		buffer.WriteString(parseMacOSSSID(string(out)))
	}

	// Get saved WiFi networks
	// This is complex on macOS, as it involves parsing plist files.
	buffer.WriteString("Saved WiFi Networks: Not implemented on macOS.\n")

	return buffer.String()
}

func parseMacOSSSID(output string) string {
	if strings.Contains(output, "You are not associated with an AirPort network.") {
		return "No active WiFi network found.\n"
	}
	return fmt.Sprintf("Active WiFi Network: %s\n", strings.TrimSpace(strings.Split(output, ":")[1]))
}

func collectPCInfo() string {
	var buffer bytes.Buffer

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
	buffer.WriteString(fmt.Sprintf("Last Reboot Time: %s (%s ago)\n", lastReboot, uptime))

	// Active and Logged-in Users
	activeUsers := collectActiveUsers()
	buffer.WriteString(fmt.Sprintf("Current Users:\n%s\n", activeUsers))

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
	collectNetworkInfo()

	// Top Processes
	topCPUProcesses := getTopProcessesByCPU(10)
	topRAMProcesses := getTopProcessesByRAM(10)
	buffer.WriteString("\nTop 10 CPU-Using Processes:\n")
	buffer.WriteString(topCPUProcesses)
	buffer.WriteString("\nTop 10 RAM-Using Processes:\n")
	buffer.WriteString(topRAMProcesses)

	return buffer.String()
}

func collectActiveUsers() string {
	var buffer bytes.Buffer

	switch runtime.GOOS {
	case "windows":
		// Use PowerShell command as an alternative to `query user`
		out, err := exec.Command("powershell", "-Command", "Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName").Output()
		if err != nil {
			buffer.WriteString(fmt.Sprintf("Error fetching users: %v\n", err))
			buffer.WriteString("Ensure the program is run with administrator privileges.\n")
			break
		}
		username := strings.TrimSpace(string(out))
		if username == "" {
			buffer.WriteString("No active users found.\n")
		} else {
			buffer.WriteString(fmt.Sprintf("- %s (Active)\n", username))
		}
	case "linux", "darwin":
		out, err := exec.Command("who").Output()
		if err != nil {
			buffer.WriteString(fmt.Sprintf("Error fetching users: %v\n", err))
			break
		}
		buffer.WriteString(parseUnixUsers(string(out)))
	default:
		buffer.WriteString("Unsupported OS for fetching users.\n")
	}

	return buffer.String()
}

func parseWindowsUsers(output string) string {
	var buffer bytes.Buffer
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			buffer.WriteString(fmt.Sprintf("- %s (Session: %s, Status: %s)\n", fields[0], fields[1], fields[2]))
		}
	}
	return buffer.String()
}

func parseUnixUsers(output string) string {
	var buffer bytes.Buffer
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			buffer.WriteString(fmt.Sprintf("- %s (TTY: %s)\n", fields[0], fields[1]))
		}
	}
	return buffer.String()
}

func getTopProcessesByCPU(limit int) string {
	var buffer bytes.Buffer
	procs, _ := process.Processes()

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
		buffer.WriteString(fmt.Sprintf("%d. %s (%.2f%% CPU) - %s\n", i+1, p.name, p.cpu, p.location))
	}

	return buffer.String()
}

func getTopProcessesByRAM(limit int) string {
	var buffer bytes.Buffer
	procs, _ := process.Processes()

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
		buffer.WriteString(fmt.Sprintf("%d. %s (%.2f%% RAM) - %s\n", i+1, p.name, p.ram, p.location))
	}

	return buffer.String()
}

func formatTime(epoch uint64) string {
	t := time.Unix(int64(epoch), 0)
	return t.Format("2006-01-02 15:04:05")
}

func formatUptime(uptime uint64) string {
	duration := time.Duration(uptime) * time.Second
	return fmt.Sprintf("%d days %02d:%02d:%02d",
		int(duration.Hours())/24,
		int(duration.Hours())%24,
		int(duration.Minutes())%60,
		int(duration.Seconds())%60)
}
