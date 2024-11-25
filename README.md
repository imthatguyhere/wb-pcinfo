# WarpBits PC Information Collector
## wb-pcinfo
### By Imthatguyhere (ITGH | Tyler)

## Latest Release Download
[Download the Latest Release EXE (Click Here)](https://github.com/imthatguyhere/wb-pcinfo/releases/latest/download/wb-pcinfo.exe)

## Description
This software get's important PC Info using Golang, mainly via the `gopsutil` PSUtil port.

## How To Use
Run `wb-pcinfo.exe` and it will create/append the console output (stdout) to `wb-pcinfo.log`, and creates a `wb-pcinfo--timestamp.txt` file with the output.

## Features
- Collects:
  - Host information (name, domain, OS, uptime (from last reboot), OS install time, etc)
  - CPU information (number of cores, cpu details, speed, etc)
  - RAM information (total, used, available, model, location, speed, manufacturer, type, form factor, etc)
  - GPU information (VRAM, Model)
  - Disk information (manufacturer, type, form factor, size, etc)
  - Network information (IP addresses, MAC addresses, adapters)
  - OS Patch information (last OS patch, last os patch date, etc)
  - Process information (top 10 processes by RAM, and top 10 processes by CPU)

## Build Instructions

```
go-winres make && go build
```