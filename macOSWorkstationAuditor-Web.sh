#!/bin/bash

# macOSWorkstationAuditor - Self-Contained Web Version
# Version 2.0.0 - macOS Workstation Audit Script (Manifest-Based Build)
# Platform: macOS 12+ (Monterey and later)
# Requires: bash 3.2+, standard macOS utilities
# Usage: curl -s https://your-url/macOSWorkstationAuditor-Web.sh | bash
# Built: 2025-11-11 12:28:06
# Modules: 10 embedded shell modules

# Parameters can be set via environment variables:
# OUTPUT_PATH - Custom output directory (default: ~/macOSAudit)
# VERBOSE - Set to "true" for verbose output

# Set default output path
OUTPUT_PATH_DEFAULT="$HOME/macOSAudit"
OUTPUT_PATH="${OUTPUT_PATH:-$OUTPUT_PATH_DEFAULT}"

# Embedded Configuration
read -r -d '' EMBEDDED_CONFIG << 'EOF'
{
  "version": "1.0.0",
  "description": "macOS Workstation IT Assessment Configuration",
  "analysis_settings": {
    "analysis_days": 7,
    "max_events_per_query": 1000,
    "enable_deep_scan": false,
    "scan_timeout_seconds": 300
  },
  "security_settings": {
    "check_third_party_av": true,
    "check_remote_access": true,
    "check_privacy_settings": true,
    "check_firewall_config": true
  },
  "software_settings": {
    "scan_applications": true,
    "check_package_managers": true,
    "analyze_browser_security": true,
    "large_file_threshold_gb": 1
  },
  "network_settings": {
    "check_wifi_security": true,
    "analyze_dns_config": true,
    "check_vpn_config": true,
    "scan_listening_ports": true
  },
  "system_settings": {
    "check_disk_space": true,
    "analyze_memory_usage": true,
    "check_process_list": true,
    "verify_system_integrity": true
  },
  "reporting_settings": {
    "generate_markdown": true,
    "generate_json": true,
    "include_raw_data": true,
    "risk_level_colors": {
      "HIGH": "#dc3545",
      "MEDIUM": "#fd7e14", 
      "LOW": "#ffc107",
      "INFO": "#28a745"
    }
  }
}
EOF

# Global variables
START_TIME=$(date +%s)
COMPUTER_NAME=$(hostname | cut -d. -f1)
BASE_FILENAME="${COMPUTER_NAME}_$(date '+%Y%m%d_%H%M%S')"
CONFIG_VERSION="2.0.0"

# Ensure output directory exists
mkdir -p "$OUTPUT_PATH" 2>/dev/null
mkdir -p "$OUTPUT_PATH/logs" 2>/dev/null

# === EMBEDDED MODULES ===

# [SYSTEM] get_system_information - macOS system information collection
# Order: 100
#!/bin/bash

# macOSWorkstationAuditor - System Information Module
# Version 1.0.0

# Global variables for collecting data
declare -a SYSTEM_FINDINGS=()

get_system_information_data() {
    log_message "INFO" "Collecting macOS system information..." "SYSTEM"
    
    # Initialize findings array
    SYSTEM_FINDINGS=()
    
    # Get basic system information
    local os_version=$(sw_vers -productVersion)
    local os_build=$(sw_vers -buildVersion)
    local os_name=$(sw_vers -productName)
    local hardware_model=$(sysctl -n hw.model)
    local cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown CPU")
    local memory_gb=$(echo "scale=2; $(sysctl -n hw.memsize) / 1073741824" | bc)
    local cpu_cores=$(sysctl -n hw.ncpu)
    
    # Get serial number
    local serial_number=$(system_profiler SPHardwareDataType | grep "Serial Number" | awk '{print $4}' 2>/dev/null || echo "Unknown")
    if [[ -z "$serial_number" || "$serial_number" == "" ]]; then
        serial_number=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}' 2>/dev/null || echo "Unknown")
    fi
    
    # Get computer name and hostname
    local computer_name=$(scutil --get ComputerName 2>/dev/null || hostname -s)
    local hostname=$(hostname)
    
    # Get system uptime
    local uptime_seconds=$(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',')
    local current_time=$(date +%s)
    local uptime_days=$(( (current_time - uptime_seconds) / 86400 ))
    
    # Get system architecture
    local arch=$(uname -m)
    
    
    
    # Operating System Information (basic info only - patch module handles version analysis)
    local os_details="Build: $os_build, Architecture: $arch"
    add_finding "System" "Operating System" "$os_name $os_version" "$os_details" "INFO" ""
    
    # Hardware Information
    add_finding "System" "Hardware" "$hardware_model" "CPU: $cpu_brand, Cores: $cpu_cores, RAM: ${memory_gb}GB, Serial: $serial_number" "INFO" ""
    
    # Computer Identity
    add_finding "System" "Computer Name" "$computer_name" "Hostname: $hostname" "INFO" ""
    
    # System Uptime
    local uptime_risk="INFO"
    local uptime_recommendation=""
    if [[ $uptime_days -gt 30 ]]; then
        uptime_risk="LOW"
        uptime_recommendation="Consider restarting to apply pending updates and clear system resources"
    fi
    add_finding "System" "System Uptime" "$uptime_days days" "Last reboot: $(date -r $uptime_seconds)" "$uptime_risk" "$uptime_recommendation"
    
    # Check printer configuration
    check_printer_inventory
    
    # Check for open risky ports
    check_open_ports
    
    log_message "SUCCESS" "System information collection completed - ${#SYSTEM_FINDINGS[@]} findings" "SYSTEM"
}

check_printer_inventory() {
    log_message "INFO" "Checking printer configuration..." "SYSTEM"
    
    # Get installed printers using lpstat
    local printer_count=0
    local printer_names=""
    local risk_level="INFO"
    local recommendation=""
    
    if command -v lpstat >/dev/null 2>&1; then
        # Get list of configured printers
        local printers=$(lpstat -p 2>/dev/null | grep "printer" | awk '{print $2}')
        if [[ -n "$printers" ]]; then
            printer_count=$(echo "$printers" | wc -l | tr -d ' ')
            printer_names=$(echo "$printers" | tr '\n' ', ' | sed 's/, $//')
        fi
        
        # Check for network printers (potential security concern)
        local network_printers=0
        if [[ -n "$printers" ]]; then
            while IFS= read -r printer; do
                if [[ -n "$printer" ]]; then
                    local printer_uri=$(lpstat -v "$printer" 2>/dev/null | awk '{print $4}')
                    if echo "$printer_uri" | grep -qE "^(ipp|ipps|http|https|socket|lpd)://"; then
                        ((network_printers++))
                    fi
                fi
            done <<< "$printers"
        fi
        
        # Assess security risk
        if [[ $network_printers -gt 0 ]]; then
            risk_level="LOW"
            recommendation="$network_printers network printers detected. Ensure they are on trusted networks and use secure protocols"
        fi
        
        # Check for default printer
        local default_printer=$(lpstat -d 2>/dev/null | awk '{print $4}')
        local printer_details="$printer_count total"
        if [[ -n "$default_printer" ]]; then
            printer_details="$printer_details, default: $default_printer"
        fi
        if [[ $network_printers -gt 0 ]]; then
            printer_details="$printer_details, $network_printers network"
        fi
        
        add_finding "Hardware" "Printers" "$printer_count printers" "$printer_details" "$risk_level" "$recommendation"
        
        # List individual printers if any exist
        if [[ $printer_count -gt 0 && $printer_count -le 5 ]]; then
            add_finding "Hardware" "Printer List" "$printer_names" "Configured printer names" "INFO" ""
        fi
        
    else
        add_finding "Hardware" "Printers" "Unable to check" "lpstat command not available" "LOW" ""
    fi
}

check_open_ports() {
    log_message "INFO" "Checking for open risky ports..." "SYSTEM"
    
    # Define risky ports to check for
    local risky_ports=(
        "21:FTP"
        "22:SSH" 
        "23:Telnet"
        "53:DNS"
        "80:HTTP"
        "135:RPC"
        "139:NetBIOS"
        "443:HTTPS"
        "445:SMB"
        "993:IMAPS"
        "995:POP3S"
        "1433:SQL Server"
        "1521:Oracle"
        "3306:MySQL"
        "3389:RDP"
        "5432:PostgreSQL"
        "5900:VNC"
        "6379:Redis"
        "8080:HTTP Alt"
        "27017:MongoDB"
    )
    
    local open_ports=()
    local high_risk_ports=()
    local medium_risk_ports=()
    
    # Check if netstat is available
    if command -v netstat >/dev/null 2>&1; then
        # Get listening ports
        local listening_ports=$(netstat -an | grep LISTEN)
        
        # Check each risky port
        for port_info in "${risky_ports[@]}"; do
            local port=$(echo "$port_info" | cut -d: -f1)
            local service=$(echo "$port_info" | cut -d: -f2)
            
            if echo "$listening_ports" | grep -q ":$port "; then
                open_ports+=("$port ($service)")
                
                # Categorize by risk level
                case "$port" in
                    "21"|"23"|"135"|"139"|"445"|"1433"|"3389"|"5900")
                        high_risk_ports+=("$port ($service)")
                        ;;
                    "22"|"53"|"80"|"443"|"993"|"995"|"3306"|"5432"|"6379"|"8080"|"27017")
                        medium_risk_ports+=("$port ($service)")
                        ;;
                esac
            fi
        done
        
        # Assess overall risk
        local risk_level="INFO"
        local recommendation=""
        local port_summary="${#open_ports[@]} risky ports open"
        
        if [[ ${#high_risk_ports[@]} -gt 0 ]]; then
            risk_level="HIGH"
            local high_risk_list=$(IFS=", "; echo "${high_risk_ports[*]}")
            recommendation="High-risk ports open: $high_risk_list. Close unnecessary services and use firewalls"
            port_summary="$port_summary (${#high_risk_ports[@]} high-risk)"
            
        elif [[ ${#medium_risk_ports[@]} -gt 0 ]]; then
            risk_level="MEDIUM"
            local medium_risk_list=$(IFS=", "; echo "${medium_risk_ports[*]}")
            recommendation="Medium-risk ports open: $medium_risk_list. Ensure proper security configuration"
            port_summary="$port_summary (${#medium_risk_ports[@]} medium-risk)"
            
        elif [[ ${#open_ports[@]} -gt 0 ]]; then
            risk_level="LOW"
            recommendation="Monitor open ports and ensure they are necessary for system operation"
        fi
        
        local port_details=""
        if [[ ${#open_ports[@]} -gt 0 ]]; then
            port_details="Open: $(IFS=", "; echo "${open_ports[*]}")"
        else
            port_details="No risky ports detected listening"
        fi
        
        # Network analysis module handles detailed port analysis
        
    else
        add_finding "Network" "Open Ports" "Unable to check" "netstat command not available" "LOW" "Install network utilities to check open ports"
    fi
}

# Helper function to add findings to the array
add_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    SYSTEM_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_system_findings() {
    printf '%s\n' "${SYSTEM_FINDINGS[@]}"
}

# [SYSTEM] get_disk_space_analysis - Disk space analysis for macOS
# Order: 101
#!/bin/bash

# macOSWorkstationAuditor - Disk Space Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a DISK_FINDINGS=()

get_disk_space_analysis_data() {
    log_message "INFO" "Analyzing disk space..." "STORAGE"
    
    # Initialize findings array
    DISK_FINDINGS=()
    
    # Analyze disk usage for all mounted volumes (basic disk space check only)
    analyze_disk_usage
    
    log_message "SUCCESS" "Disk space analysis completed - ${#DISK_FINDINGS[@]} findings" "STORAGE"
}

analyze_disk_usage() {
    log_message "INFO" "Checking disk usage for mounted volumes..." "STORAGE"
    
    # Get disk usage for all mounted volumes
    while IFS= read -r line; do
        local device=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')
        local used=$(echo "$line" | awk '{print $3}')
        local available=$(echo "$line" | awk '{print $4}')
        local percent=$(echo "$line" | awk '{print $5}' | tr -d '%')
        local mount_point=$(echo "$line" | awk '{for(i=9;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
        
        # Skip if not a real device or mount point
        if [[ "$device" == "Filesystem" ]] || [[ -z "$mount_point" ]] || [[ "$device" == "map"* ]]; then
            continue
        fi
        
        # Skip system volumes that users don't need to see
        case "$mount_point" in
            "/System/Volumes/VM"|"/System/Volumes/Preboot"|"/System/Volumes/Update"|"/System/Volumes/xarts"|"/System/Volumes/iSCPreboot"|"/System/Volumes/Hardware"|"/System/Volumes/Update/"*|"/private/var/vm")
                continue
                ;;
        esac
        
        # Determine risk level based on usage percentage
        local risk_level="INFO"
        local recommendation=""
        
        if [[ $percent -ge 95 ]]; then
            risk_level="HIGH"
            recommendation="Critical: Disk space is critically low. Free up space immediately to prevent system issues"
        elif [[ $percent -ge 90 ]]; then
            risk_level="HIGH"
            recommendation="Disk space is very low. Clean up unnecessary files to prevent performance degradation"
        elif [[ $percent -ge 80 ]]; then
            risk_level="MEDIUM"
            recommendation="Disk space is getting low. Monitor usage and consider cleanup"
        elif [[ $percent -ge 70 ]]; then
            risk_level="LOW"
            recommendation="Disk usage is moderate. Consider regular cleanup maintenance"
        fi
        
        local details="Used: $used ($percent%), Available: $available, Total: $size"
        add_disk_finding "Storage" "Disk Usage: $mount_point" "$percent% used" "$details" "$risk_level" "$recommendation"
        
        
    done < <(df -h | grep -E '^/dev/')
}


check_storage_optimization() {
    log_message "INFO" "Checking storage optimization features..." "STORAGE"
    
    # Check if storage optimization is enabled (macOS Sierra+)
    local optimization_enabled="Unknown"
    
    # Check for optimized storage settings
    local optimize_storage=$(defaults read com.apple.finder "OptimizeStorage" 2>/dev/null || echo "unknown")
    
    if [[ "$optimize_storage" == "1" ]]; then
        optimization_enabled="Enabled"
    elif [[ "$optimize_storage" == "0" ]]; then
        optimization_enabled="Disabled"
        add_disk_finding "Storage" "Storage Optimization" "$optimization_enabled" "Automatic storage optimization is disabled" "LOW" "Consider enabling storage optimization to automatically manage disk space"
    else
        optimization_enabled="Unknown"
    fi
    
    if [[ "$optimization_enabled" != "Unknown" ]]; then
        add_disk_finding "Storage" "Storage Optimization" "$optimization_enabled" "Automatic storage management status" "INFO" ""
    fi
    
    # Check for Time Machine local snapshots
    check_time_machine_snapshots
    
    # Check Trash/Bin usage
    check_trash_usage
}

check_time_machine_snapshots() {
    log_message "INFO" "Checking Time Machine local snapshots..." "STORAGE"
    
    # Check for local Time Machine snapshots
    if command -v tmutil >/dev/null 2>&1; then
        local snapshots=$(tmutil listlocalsnapshotdates 2>/dev/null | grep -v "Listing" | wc -l | tr -d ' ')
        
        if [[ $snapshots -gt 0 ]]; then
            local risk_level="INFO"
            local recommendation=""
            
            if [[ $snapshots -gt 10 ]]; then
                risk_level="LOW"
                recommendation="Many Time Machine snapshots detected. These consume disk space but are automatically managed"
            fi
            
            add_disk_finding "Storage" "Time Machine Snapshots" "$snapshots snapshots" "Local Time Machine snapshots on disk" "$risk_level" "$recommendation"
        else
            add_disk_finding "Storage" "Time Machine Snapshots" "None" "No local Time Machine snapshots found" "INFO" ""
        fi
    fi
}


# Helper function to add disk findings to the array
add_disk_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    DISK_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_disk_findings() {
    printf '%s\n' "${DISK_FINDINGS[@]}"
}

# [SYSTEM] get_memory_analysis - Memory utilization analysis for macOS
# Order: 102
#!/bin/bash

# macOSWorkstationAuditor - Memory Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a MEMORY_FINDINGS=()

get_memory_analysis_data() {
    log_message "INFO" "Analyzing memory usage..." "MEMORY"
    
    # Initialize findings array
    MEMORY_FINDINGS=()
    
    # Get memory information
    analyze_memory_usage
    
    log_message "SUCCESS" "Memory analysis completed - ${#MEMORY_FINDINGS[@]} findings" "MEMORY"
}

analyze_memory_usage() {
    log_message "INFO" "Checking memory configuration and usage..." "MEMORY"
    
    # Get total physical memory
    local total_memory_bytes=$(sysctl -n hw.memsize)
    local total_memory_gb=$(echo "scale=2; $total_memory_bytes / 1073741824" | bc)
    
    # Get memory pressure information
    local memory_pressure=$(memory_pressure 2>/dev/null | head -20)
    
    # Extract key memory metrics and get correct page size
    local page_size=$(echo "$memory_pressure" | grep "page size" | sed 's/.*page size of \([0-9]*\).*/\1/')
    local pages_free=$(echo "$memory_pressure" | grep "Pages free:" | awk '{print $3}' | tr -d '.')
    local pages_active=$(echo "$memory_pressure" | grep "Pages active:" | awk '{print $3}' | tr -d '.')
    local pages_inactive=$(echo "$memory_pressure" | grep "Pages inactive:" | awk '{print $3}' | tr -d '.')
    local pages_wired=$(echo "$memory_pressure" | grep "Pages wired down:" | awk '{print $4}' | tr -d '.')
    local pages_compressed=$(echo "$memory_pressure" | grep "used by compressor:" | awk '{print $5}' | tr -d '.')
    
    # Set default page size if not found
    [[ -z "$page_size" ]] && page_size=16384
    
    # Calculate memory usage if we have the data
    if [[ -n "$pages_free" && -n "$pages_active" && -n "$pages_wired" ]]; then
        local free_memory_bytes=$((pages_free * page_size))
        local active_memory_bytes=$((pages_active * page_size))
        local wired_memory_bytes=$((pages_wired * page_size))
        local inactive_memory_bytes=$((${pages_inactive:-0} * page_size))
        local compressed_memory_bytes=$((${pages_compressed:-0} * page_size))
        
        # Calculate used memory (active + wired + compressed)
        local used_memory_bytes=$((active_memory_bytes + wired_memory_bytes + compressed_memory_bytes))
        
        # Calculate available/free memory (total - used)
        local available_memory_bytes=$((total_memory_bytes - used_memory_bytes))
        local available_memory_gb=$(echo "scale=2; $available_memory_bytes / 1073741824" | bc)
        
        local active_memory_gb=$(echo "scale=2; $active_memory_bytes / 1073741824" | bc)
        local used_memory_gb=$(echo "scale=2; $used_memory_bytes / 1073741824" | bc)
        
        local memory_usage_percent=$(echo "scale=1; ($used_memory_bytes * 100) / $total_memory_bytes" | bc)
        
        # Assess memory status
        local risk_level="INFO"
        local recommendation=""
        
        # Convert to integer for bash 3.2 compatibility
        local memory_usage_int=$(echo "$memory_usage_percent" | cut -d. -f1)
        if [[ $memory_usage_int -gt 90 ]]; then
            risk_level="HIGH"
            recommendation="Memory usage is critically high. Close unnecessary applications or add more RAM"
        elif [[ $memory_usage_int -gt 80 ]]; then
            risk_level="MEDIUM"
            recommendation="Memory usage is high. Monitor memory-intensive applications"
        elif [[ $memory_usage_int -gt 70 ]]; then
            risk_level="LOW"
            recommendation="Memory usage is moderate. Consider monitoring memory usage patterns"
        fi
        
        add_memory_finding "Memory" "Memory Usage" "${memory_usage_percent}%" "Total: ${total_memory_gb}GB, Used: ${used_memory_gb}GB, Available: ${available_memory_gb}GB" "$risk_level" "$recommendation"
        
        # Check memory pressure indicators - only report compression issues on Intel Macs
        if [[ -n "$pages_compressed" && "$pages_compressed" != "0" ]]; then
            local compressed_gb=$(echo "scale=2; ($pages_compressed * $page_size) / 1073741824" | bc)
            
            # Check if this is Apple Silicon (M-series) - compression is normal, don't report it
            local cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
            if [[ "$cpu_brand" != *"Apple"* ]]; then
                # Only report on Intel Macs where high compression might indicate memory pressure
                if (( $(echo "$compressed_gb > 2" | bc -l) )); then
                    add_memory_finding "Memory" "Memory Compression" "${compressed_gb}GB compressed" "High memory compression may indicate memory pressure" "LOW" "Consider monitoring memory usage or adding more RAM"
                fi
            fi
        fi
    else
        # Fallback to basic memory info
        add_memory_finding "Memory" "Total Physical Memory" "${total_memory_gb}GB" "Installed RAM capacity" "INFO" ""
        add_memory_finding "Memory" "Memory Pressure" "Unable to determine" "Could not read detailed memory usage" "LOW" "Check system performance tools for memory usage"
    fi
    
    # Note: Swap usage analysis integrated into main memory analysis above
    
    # Check for memory-intensive processes
    check_memory_intensive_processes
}

# check_swap_usage() - REMOVED: Redundant with main memory analysis
# This function was removed as swap usage is already covered in the main memory pressure analysis

# Function to convert process names to human-readable format
get_human_readable_process_name() {
    local raw_name="$1"
    local clean_name=""
    
    # Remove common prefixes and clean up the name
    clean_name=$(echo "$raw_name" | sed 's/^.*\///g')  # Remove path
    
    # Map common macOS processes to readable names
    case "$clean_name" in
        "com.apple.WebKit.WebContent")
            echo "Safari Web Content"
            ;;
        "WindowServer")
            echo "Window Server (Graphics)"
            ;;
        "kernel_task")
            echo "Kernel Task (System)"
            ;;
        "launchd")
            echo "Launch Daemon (System)"
            ;;
        "Finder")
            echo "Finder"
            ;;
        "Safari")
            echo "Safari Browser"
            ;;
        "Google Chrome Helper"*)
            echo "Chrome Helper Process"
            ;;
        "Google Chrome")
            echo "Google Chrome"
            ;;
        "Firefox")
            echo "Mozilla Firefox"
            ;;
        "Microsoft Edge")
            echo "Microsoft Edge"
            ;;
        "Code")
            echo "Visual Studio Code"
            ;;
        "Xcode")
            echo "Xcode IDE"
            ;;
        "Docker Desktop")
            echo "Docker Desktop"
            ;;
        "VirtualBox"*)
            echo "VirtualBox VM"
            ;;
        "VMware Fusion"*)
            echo "VMware Fusion"
            ;;
        "Parallels Desktop"*)
            echo "Parallels Desktop"
            ;;
        "com.apple."*)
            # Generic Apple system process
            local apple_name=$(echo "$clean_name" | sed 's/com\.apple\.//' | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //')
            echo "Apple $apple_name"
            ;;
        *".app"*)
            # Generic app name extraction
            echo "$clean_name" | sed 's/\.app.*//' | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //'
            ;;
        *)
            # Handle truncated or encoded process names
            if [[ ${#clean_name} -gt 15 && "$clean_name" =~ ^[A-Za-z0-9+/=]+$ ]]; then
                echo "Process (${clean_name:0:10}...)"
            else
                # Return the clean name with camel case separated
                echo "$clean_name" | sed 's/\([A-Z]\)/ \1/g' | sed 's/^ //'
            fi
            ;;
    esac
}

check_memory_intensive_processes() {
    log_message "INFO" "Checking for memory-intensive processes..." "MEMORY"
    
    # Get top memory-consuming processes with better formatting
    local top_processes=$(ps -axo pid,ppid,%mem,rss,command -r | head -6 | tail -5)
    local high_memory_count=0
    local total_top5_memory=0
    local high_memory_details=()
    local top5_process_details=()
    
    while IFS= read -r process_line; do
        if [[ -n "$process_line" ]]; then
            local mem_percent=$(echo "$process_line" | awk '{print $3}')
            local mem_rss_kb=$(echo "$process_line" | awk '{print $4}')
            local raw_command=$(echo "$process_line" | awk '{for(i=5;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
            
            # Extract the executable name and get human-readable version
            local exe_name=$(echo "$raw_command" | awk '{print $1}')
            local process_name=$(get_human_readable_process_name "$exe_name")
            
            # Check if process is using significant memory (>5% or >500MB)
            # Convert to integer first to handle floating point values from top command
            local mem_rss_kb_int=$(echo "$mem_rss_kb" | awk '{print int($1)}')
            local mem_mb=$((mem_rss_kb_int / 1024))
            total_top5_memory=$((total_top5_memory + mem_mb))
            
            # Add to top 5 list with readable names
            top5_process_details+=("$process_name: ${mem_percent}% (${mem_mb}MB)")
            
            # Convert percentage to integer for comparison
            local mem_percent_int=$(echo "$mem_percent" | cut -d. -f1)
            if [[ $mem_percent_int -gt 10 ]] || [[ $mem_mb -gt 500 ]]; then
                ((high_memory_count++))
                high_memory_details+=("$process_name: ${mem_percent}% (${mem_mb}MB)")
            fi
        fi
    done <<< "$top_processes"
    
    if [[ $high_memory_count -gt 0 ]]; then
        local risk_level="LOW"
        local recommendation="Monitor memory-intensive applications for performance impact"
        
        if [[ $high_memory_count -gt 2 ]]; then
            risk_level="MEDIUM"
            recommendation="Multiple memory-intensive processes detected. Consider closing unnecessary applications"
        fi
        
        # Create detailed list of high-memory processes
        local high_memory_list=$(IFS=", "; echo "${high_memory_details[*]}")
        add_memory_finding "Memory" "Memory-Intensive Processes" "$high_memory_count processes" "High usage: $high_memory_list" "$risk_level" "$recommendation"
    fi
    
    # Report detailed top 5 process memory usage
    if [[ $total_top5_memory -gt 0 ]]; then
        local total_top5_gb=$(echo "scale=2; $total_top5_memory / 1024" | bc)
        local top5_list=$(IFS=", "; echo "${top5_process_details[*]}")
        add_memory_finding "Memory" "Top 5 Process Memory Usage" "${total_top5_gb}GB total" "Details: $top5_list" "INFO" ""
    fi
}

# Helper function to add memory findings to the array
add_memory_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    MEMORY_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_memory_findings() {
    printf '%s\n' "${MEMORY_FINDINGS[@]}"
}

# [SYSTEM] get_process_analysis - Process analysis for macOS
# Order: 103
#!/bin/bash

# macOSWorkstationAuditor - Process Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a PROCESS_FINDINGS=()

get_process_analysis_data() {
    log_message "INFO" "Analyzing running processes..." "PROCESSES"
    
    # Initialize findings array
    PROCESS_FINDINGS=()
    
    # Analyze running processes
    analyze_running_processes

    # Analyze resource usage
    analyze_cpu_usage
    analyze_process_memory_usage

    # Suspicious process detection removed - not appropriate for IT audit tool
    
    log_message "SUCCESS" "Process analysis completed - ${#PROCESS_FINDINGS[@]} findings" "PROCESSES"
}

analyze_running_processes() {
    log_message "INFO" "Collecting running process information..." "PROCESSES"
    
    # Get process count
    local total_processes=$(ps -ax | wc -l | tr -d ' ')
    ((total_processes--))  # Remove header line
    
    # Get user processes vs system processes for consolidated report
    local user_processes=$(ps -axo user,pid,command | grep -v "^root\|^_\|^daemon" | wc -l | tr -d ' ')
    local system_processes=$((total_processes - user_processes))
    
    add_process_finding "System" "Process Activity" "$total_processes total" "User: $user_processes, System: $system_processes" "INFO" ""
}

analyze_cpu_usage() {
    log_message "INFO" "Analyzing CPU usage by processes..." "PROCESSES"

    # Get top 5 CPU processes with actual data format
    local top_cpu_data=$(ps -axo pid,%cpu,command | sort -nr -k2 | head -6 | tail -5)

    if [[ -n "$top_cpu_data" ]]; then
        local cpu_total="0.0"
        local cpu_details=""

        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local cpu_percent=$(echo "$line" | awk '{print $2}')
                local process_name=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/.*\///g' | cut -d' ' -f1 | head -c 20)

                if [[ -n "$cpu_details" ]]; then
                    cpu_details="$cpu_details,$process_name: ${cpu_percent}%"
                else
                    cpu_details="$process_name: ${cpu_percent}%"
                fi

                cpu_total=$(echo "$cpu_total + $cpu_percent" | bc 2>/dev/null || echo "$cpu_total")
            fi
        done <<< "$top_cpu_data"

        add_process_finding "System" "Top 5 Process CPU Usage" "${cpu_total}% total" "Details: $cpu_details" "INFO" ""
    fi
}

analyze_process_memory_usage() {
    log_message "INFO" "Analyzing memory usage by processes..." "PROCESSES"

    # Get top 5 memory processes using RSS (Resident Set Size)
    local top_mem_data=$(ps -axo pid,rss,command | sort -nr -k2 | head -6 | tail -5)

    if [[ -n "$top_mem_data" ]]; then
        local mem_total_kb=0
        local mem_details=""

        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local mem_kb=$(echo "$line" | awk '{print $2}')
                local process_name=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/.*\///g' | cut -d' ' -f1 | head -c 20)

                # Convert KB to MB
                local mem_mb=$((mem_kb / 1024))

                # Calculate percentage of 16GB (total system memory)
                local mem_percent=$(echo "scale=1; $mem_kb / 16384 / 1024 * 100" | bc 2>/dev/null || echo "0.0")

                if [[ -n "$mem_details" ]]; then
                    mem_details="$mem_details,$process_name: ${mem_percent}% (${mem_mb}MB)"
                else
                    mem_details="$process_name: ${mem_percent}% (${mem_mb}MB)"
                fi

                mem_total_kb=$((mem_total_kb + mem_kb))
            fi
        done <<< "$top_mem_data"

        local mem_total_gb=$(echo "scale=2; $mem_total_kb / 1024 / 1024" | bc 2>/dev/null || echo "0.00")

    fi
}

# Suspicious process detection function removed - not appropriate for enterprise IT audit tool
# This is not an antimalware solution and should not pretend to detect threats

check_high_cpu_processes() {
    log_message "INFO" "Checking for high CPU usage processes..." "PROCESSES"
    
    # Get top CPU consuming processes
    local high_cpu_processes=$(ps -axo pid,ppid,%cpu,command -r | awk '$3 > 50.0' | grep -v "%CPU")
    local high_cpu_count=0
    
    if [[ -n "$high_cpu_processes" ]]; then
        high_cpu_count=$(echo "$high_cpu_processes" | wc -l | tr -d ' ')
    fi
    
    if [[ $high_cpu_count -gt 0 ]]; then
        local risk_level="MEDIUM"
        local recommendation="High CPU usage processes detected. Monitor system performance and investigate if necessary"
        
        if [[ $high_cpu_count -gt 3 ]]; then
            risk_level="HIGH"
            recommendation="Multiple high CPU processes detected. This may indicate system issues or malware"
        fi
        
        # Extract process names and CPU percentages for details
        local process_details=$(echo "$high_cpu_processes" | awk '{print $4 ": " $3 "%"}' | head -5 | tr '\n' ', ' | sed 's/, $//')
        
        add_process_finding "Performance" "High CPU Processes" "$high_cpu_count processes >50%" "High CPU usage: $process_details" "$risk_level" "$recommendation"
    else
        add_process_finding "Performance" "High CPU Processes" "None detected" "No processes using excessive CPU" "INFO" ""
    fi
}

check_network_processes() {
    log_message "INFO" "Checking for network-related processes..." "PROCESSES"
    
    # Check for common network/remote access processes with detailed pattern matching
    local network_patterns=(
        "sshd.*ssh"
        "ssh "
        "vnc"
        "teamviewer"
        "anydesk"
        "screensharing"
        "ARDAgent"
        "Remote Desktop"
        "AppleVNC"
        "tightvnc"
        "realvnc"
        "logmein"
        "gotomypc"
    )
    
    local found_network_details=()
    local risk_level="INFO"
    local high_risk_count=0
    local medium_risk_count=0
    
    # Get detailed process information
    local all_processes=$(ps -axo pid,ppid,user,command)
    
    for pattern in "${network_patterns[@]}"; do
        local matches=$(echo "$all_processes" | grep -i "$pattern" | grep -v "grep")
        
        if [[ -n "$matches" ]]; then
            # Extract specific details for each match
            while IFS= read -r process_line; do
                if [[ -n "$process_line" ]]; then
                    local pid=$(echo "$process_line" | awk '{print $1}')
                    local user=$(echo "$process_line" | awk '{print $3}')
                    local command=$(echo "$process_line" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                    
                    # Extract just the executable name for cleaner display
                    local exe_name=$(basename "$(echo "$command" | awk '{print $1}')")
                    
                    # Check for listening ports related to this process
                    local listening_ports=""
                    if command -v lsof >/dev/null 2>&1; then
                        listening_ports=$(lsof -Pan -p "$pid" -i 2>/dev/null | grep LISTEN | awk '{print $9}' | cut -d: -f2 | tr '\n' ',' | sed 's/,$//')
                    fi
                    
                    # Build detailed description
                    local detail_desc="PID:$pid User:$user"
                    if [[ -n "$listening_ports" ]]; then
                        detail_desc="$detail_desc Ports:$listening_ports"
                    fi
                    
                    # Determine risk level for this specific process
                    case "$exe_name" in
                        "sshd")
                            detail_desc="SSH Server - $detail_desc"
                            ((medium_risk_count++))
                            ;;
                        "ssh")
                            detail_desc="SSH Client - $detail_desc"
                            ;;
                        "teamviewer"|"TeamViewer")
                            detail_desc="TeamViewer - $detail_desc"
                            ((high_risk_count++))
                            ;;
                        "anydesk"|"AnyDesk")
                            detail_desc="AnyDesk - $detail_desc"
                            ((high_risk_count++))
                            ;;
                        "vnc"*|"VNC"*|"AppleVNC"|"tightvnc"|"realvnc")
                            detail_desc="VNC Server - $detail_desc"
                            ((high_risk_count++))
                            ;;
                        "screensharing"|"ARDAgent")
                            detail_desc="Apple Remote Desktop - $detail_desc"
                            ((medium_risk_count++))
                            ;;
                        *)
                            detail_desc="$exe_name - $detail_desc"
                            ;;
                    esac
                    
                    found_network_details+=("$detail_desc")
                fi
            done <<< "$matches"
        fi
    done
    
    # Also check for processes with active network connections
    if command -v lsof >/dev/null 2>&1; then
        local network_connections=$(lsof -i -n | grep -E "ESTABLISHED|LISTEN" | awk '{print $2 ":" $1}' | sort -u | head -10)
        if [[ -n "$network_connections" ]]; then
            local connection_count=$(echo "$network_connections" | wc -l | tr -d ' ')
            
            # Format the connections in a more readable way - just process names
            local formatted_connections=""
            local seen_processes=()
            while IFS= read -r connection; do
                if [[ -n "$connection" ]]; then
                    local process=$(echo "$connection" | cut -d: -f2)
                    # Clean up process name - remove path, truncate, and fix encoding
                    process=$(basename "$process" | cut -c1-15)
                    # Remove hex encoding and clean up names
                    process=$(echo "$process" | sed 's/\\x20/ /g' | sed 's/\\x[0-9A-Fa-f][0-9A-Fa-f]//g' | tr -d '\\')
                    # Remove extra whitespace and truncate
                    process=$(echo "$process" | sed 's/[[:space:]]*$//' | sed 's/^[[:space:]]*//' | cut -c1-12)
                    
                    # Skip empty or very short process names
                    if [[ -n "$process" && ${#process} -gt 2 ]]; then
                        # Only add if not already seen
                        if [[ ! " ${seen_processes[*]} " =~ " ${process} " ]]; then
                            seen_processes+=("$process")
                            if [[ -n "$formatted_connections" ]]; then
                                formatted_connections="$formatted_connections, $process"
                            else
                                formatted_connections="$process"
                            fi
                        fi
                    fi
                fi
            done <<< "$network_connections"
            
            add_process_finding "Network" "Active Network Connections" "${#seen_processes[@]} unique processes" "Processes with network activity: $formatted_connections" "INFO" ""
        fi
    fi
    
    # Determine overall risk level and recommendation
    local recommendation=""
    if [[ $high_risk_count -gt 0 ]]; then
        risk_level="HIGH"
        recommendation="High-risk remote access software detected ($high_risk_count). Verify authorization and disable if not needed"
    elif [[ $medium_risk_count -gt 0 ]]; then
        risk_level="MEDIUM"
        recommendation="Network services detected ($medium_risk_count). Ensure proper security configuration and authorization"
    elif [[ ${#found_network_details[@]} -gt 0 ]]; then
        risk_level="LOW"
        recommendation="Network/remote processes active. Monitor for unauthorized access"
    fi
    
    # Report findings
    if [[ ${#found_network_details[@]} -gt 0 ]]; then
        local details_summary=""
        if [[ ${#found_network_details[@]} -le 3 ]]; then
            # Show all details if few processes
            details_summary=$(IFS="; "; echo "${found_network_details[*]}")
        else
            # Show first 3 and count for many processes
            local first_three=("${found_network_details[@]:0:3}")
            details_summary="$(IFS="; "; echo "${first_three[*]}") and $((${#found_network_details[@]} - 3)) more"
        fi
        
        add_process_finding "Security" "Network/Remote Processes" "${#found_network_details[@]} active" "$details_summary" "$risk_level" "$recommendation"
    else
        add_process_finding "Security" "Network/Remote Processes" "None detected" "No remote access processes found" "INFO" ""
    fi
}

# Helper function to add process findings to the array
add_process_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    PROCESS_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_process_findings() {
    printf '%s\n' "${PROCESS_FINDINGS[@]}"
}

# [INVENTORY] get_software_inventory - Software inventory for macOS
# Order: 110
#!/bin/bash

# macOSWorkstationAuditor - Software Inventory Module
# Version 1.0.0

# Global variables for collecting data
declare -a SOFTWARE_FINDINGS=()

get_software_inventory_data() {
    log_message "INFO" "Collecting macOS software inventory..." "SOFTWARE"
    
    # Initialize findings array
    SOFTWARE_FINDINGS=()
    
    # Collect applications from /Applications
    collect_applications_inventory
    
    # Check for critical software versions
    check_critical_software
    
    # Check for development tools
    check_development_tools
    
    # Check for remote access software
    check_remote_access_software
    
    # Check for browser plugins and extensions
    check_browser_security
    
    # Check for package managers
    check_package_managers
    
    log_message "SUCCESS" "Software inventory completed - ${#SOFTWARE_FINDINGS[@]} findings" "SOFTWARE"
}

collect_applications_inventory() {
    log_message "INFO" "Scanning /Applications directory..." "SOFTWARE"
    
    local app_count=0
    local system_app_count=0
    local user_app_count=0
    
    # Count applications in /Applications
    if [[ -d "/Applications" ]]; then
        app_count=$(find /Applications -maxdepth 1 -name "*.app" -type d | wc -l | tr -d ' ')
    fi
    
    # Count system applications in /System/Applications (macOS Catalina+)
    if [[ -d "/System/Applications" ]]; then
        system_app_count=$(find /System/Applications -maxdepth 1 -name "*.app" -type d | wc -l | tr -d ' ')
    fi
    
    # Count user applications in ~/Applications
    if [[ -d "$HOME/Applications" ]]; then
        user_app_count=$(find "$HOME/Applications" -maxdepth 1 -name "*.app" -type d | wc -l | tr -d ' ')
    fi
    
    local total_apps=$((app_count + system_app_count + user_app_count))
    
    add_software_finding "Software" "Total Installed Applications" "$total_apps" "Applications: $app_count, System: $system_app_count, User: $user_app_count" "INFO" ""
    
    # Check for suspicious application counts
    if [[ $app_count -gt 200 ]]; then
        add_software_finding "Software" "Application Count" "High" "Large number of applications may indicate software sprawl" "LOW" "Review installed applications and remove unused software"
    fi
}

check_critical_software() {
    log_message "INFO" "Checking critical software versions..." "SOFTWARE"
    
    # Check critical applications (bash 3.2 compatible) - prioritize by security importance
    
    # Browsers (security critical)
    check_single_application "Google Chrome" "/Applications/Google Chrome.app"
    check_single_application "Mozilla Firefox" "/Applications/Firefox.app" 
    check_single_application "Microsoft Edge" "/Applications/Microsoft Edge.app"
    # Safari is reported separately as default macOS browser
    
    # Communication & Remote Access (business critical)
    check_single_application "Zoom" "/Applications/zoom.us.app"
    check_single_application "Slack" "/Applications/Slack.app"
    check_single_application "Microsoft Teams" "/Applications/Microsoft Teams.app"
    check_single_application "Discord" "/Applications/Discord.app"
    check_single_application "TeamViewer" "/Applications/TeamViewer.app"
    
    # Cloud Storage & Sync (data security)
    check_single_application "Dropbox" "/Applications/Dropbox.app"
    check_single_application "Google Drive" "/Applications/Google Drive.app"
    check_single_application "OneDrive" "/Applications/OneDrive.app"
    check_single_application "iCloud Drive" "/System/Applications/iCloud Drive.app"
    
    # Development Tools (if present)
    check_single_application "Docker Desktop" "/Applications/Docker.app"
    check_single_application "Visual Studio Code" "/Applications/Visual Studio Code.app"
    check_single_application "JetBrains Toolbox" "/Applications/JetBrains Toolbox.app"
    
    # Security & VPN
    check_single_application "1Password" "/Applications/1Password 7 - Password Manager.app"
    check_single_application "Malwarebytes" "/Applications/Malwarebytes for Mac.app"
    check_single_application "Little Snitch" "/Applications/Little Snitch.app"
    
    # Special handling for Office suite and Adobe (high priority due to update frequency)
    check_microsoft_office
    check_adobe_acrobat
}

check_single_application() {
    local app_name="$1"
    local app_path="$2"
    
    if [[ -d "$app_path" ]]; then
        local version="Unknown"
        local install_date="Unknown"
        local risk_level="INFO"
        local recommendation=""
        
        # Try to get version from Info.plist
        local info_plist="$app_path/Contents/Info.plist"
        if [[ -f "$info_plist" ]]; then
            version=$(defaults read "$info_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            
            # Get installation/modification date
            local mod_time=$(stat -f "%Sm" -t "%Y-%m-%d" "$app_path" 2>/dev/null || echo "Unknown")
            install_date="$mod_time"
            
            # Check age of application (based on modification time)
            if [[ "$mod_time" != "Unknown" ]]; then
                local mod_timestamp=$(date -j -f "%Y-%m-%d" "$mod_time" "+%s" 2>/dev/null || echo "0")
                local current_timestamp=$(date +%s)
                local age_days=$(( (current_timestamp - mod_timestamp) / 86400 ))
                
                if [[ $age_days -gt 365 ]]; then
                    risk_level="MEDIUM"
                    recommendation="Application is over 1 year old. Check for updates"
                elif [[ $age_days -gt 180 ]]; then
                    risk_level="LOW"
                    recommendation="Consider checking for application updates"
                fi
            fi
        fi
        
        add_software_finding "Software" "$app_name" "$version" "Install Date: $install_date" "$risk_level" "$recommendation"
    fi
}

check_microsoft_office() {
    # Check for various Office applications
    local office_apps=(
        "Microsoft Word.app"
        "Microsoft Excel.app"
        "Microsoft PowerPoint.app"
        "Microsoft Outlook.app"
        "Microsoft OneNote.app"
    )
    
    local found_office=false
    local office_version="Unknown"
    
    for office_app in "${office_apps[@]}"; do
        local app_path="/Applications/$office_app"
        if [[ -d "$app_path" ]]; then
            found_office=true
            office_version=$(defaults read "$app_path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            break
        fi
    done
    
    if [[ "$found_office" == true ]]; then
        add_software_finding "Software" "Microsoft Office" "$office_version" "Office suite detected" "INFO" ""
    fi
}

check_adobe_acrobat() {
    # Check for various Adobe Acrobat versions
    local adobe_paths=(
        "/Applications/Adobe Acrobat DC/Adobe Acrobat.app"
        "/Applications/Adobe Acrobat Reader DC.app"
        "/Applications/Adobe Reader.app"
    )
    
    for adobe_path in "${adobe_paths[@]}"; do
        if [[ -d "$adobe_path" ]]; then
            local version=$(defaults read "$adobe_path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
            local app_name=$(basename "$adobe_path" .app)
            add_software_finding "Software" "Adobe Acrobat/Reader" "$version" "Found: $app_name" "INFO" ""
            return
        fi
    done
}

check_development_tools() {
    log_message "INFO" "Checking for development tools..." "SOFTWARE"
    
    # Check for Xcode
    if [[ -d "/Applications/Xcode.app" ]]; then
        local xcode_version=$(defaults read "/Applications/Xcode.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Xcode" "$xcode_version" "Apple development environment" "INFO" ""
    fi
    
    # Check for command line tools
    if xcode-select -p >/dev/null 2>&1; then
        local cli_path=$(xcode-select -p 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Command Line Tools" "Installed" "Path: $cli_path" "INFO" ""
    fi
    
    # Check for common development tools
    local dev_apps=(
        "Visual Studio Code.app"
        "Sublime Text.app"
        "Atom.app"
        "IntelliJ IDEA.app"
        "PyCharm.app"
        "Docker.app"
        "Terminal.app"
        "iTerm.app"
    )
    
    local dev_count=0
    local found_dev_apps=()
    
    for dev_app in "${dev_apps[@]}"; do
        if [[ -d "/Applications/$dev_app" ]]; then
            ((dev_count++))
            local app_name=$(basename "$dev_app" .app)
            found_dev_apps+=("$app_name")
        fi
    done
    
    if [[ $dev_count -gt 0 ]]; then
        local dev_list=$(IFS=", "; echo "${found_dev_apps[*]}")
        add_software_finding "Software" "Development Tools" "$dev_count applications" "Found: $dev_list" "INFO" ""
    fi
}

check_remote_access_software() {
    log_message "INFO" "Checking for remote access software..." "SOFTWARE"
    
    # Common remote access applications
    local remote_apps=(
        "TeamViewer.app"
        "AnyDesk.app"
        "Chrome Remote Desktop Host.app"
        "LogMeIn.app"
        "GoToMyPC.app"
        "Remote Desktop Connection.app"
        "VNC Viewer.app"
        "Screens.app"
        "Jump Desktop.app"
        "ScreenConnect Client.app"
        "ConnectWise Control.app"
        "Splashtop Business.app"
        "Splashtop Streamer.app"
        "Apple Remote Desktop.app"
        "RealVNC.app"
        "TightVNC.app"
        "UltraVNC.app"
        "Parallels Access.app"
        "Remotix.app"
        "Microsoft Remote Desktop.app"
    )
    
    local found_remote=()
    
    # Check standard Applications folder
    for remote_app in "${remote_apps[@]}"; do
        if [[ -d "/Applications/$remote_app" ]]; then
            local app_name=$(basename "$remote_app" .app)
            found_remote+=("$app_name")
        fi
    done
    
    # Check for remote access software by bundle identifier (more reliable)
    local bundle_id_patterns=(
        "com.screenconnect.client:ScreenConnect"
        "com.connectwise.control:ConnectWise Control"  
        "com.teamviewer.TeamViewer:TeamViewer"
        "com.anydesk.AnyDesk:AnyDesk"
        "com.google.chromeremotedesktop:Chrome Remote Desktop"
        "com.logmein.LogMeIn:LogMeIn"
        "com.gotomypc.GoToMyPC:GoToMyPC"
        "com.realvnc.VNCViewer:RealVNC"
        "com.osxvnc.VNCViewer:VNC Viewer"
        "com.parallels.ParallelsAccess:Parallels Access"
        "com.apple.RemoteDesktop:Apple Remote Desktop"
        "com.edovia.SplashDesktop:Splashtop Desktop"
        "com.splashtop.business:Splashtop Business"
        "com.splashtop.streamer:Splashtop Streamer"
    )
    
    # Check all apps for remote access bundle identifiers
    for app_path in /Applications/*.app /Applications/*/*.app; do
        if [[ -d "$app_path" && -f "$app_path/Contents/Info.plist" ]]; then
            local bundle_id=$(defaults read "$app_path/Contents/Info.plist" CFBundleIdentifier 2>/dev/null)
            if [[ -n "$bundle_id" ]]; then
                for pattern in "${bundle_id_patterns[@]}"; do
                    local id_pattern="${pattern%:*}"
                    local display_name="${pattern#*:}"
                    if [[ "$bundle_id" == "$id_pattern" ]]; then
                        found_remote+=("$display_name")
                        break
                    fi
                done
            fi
        fi
    done
    
    # Also check for ScreenConnect/ConnectWise in alternate locations and patterns  
    local screenconnect_patterns=(
        "/Applications/ScreenConnect Client*.app"
        "/Applications/*ScreenConnect*.app"
        "/Applications/ConnectWise*.app"
        "/Applications/*ConnectWise*.app"
        "/opt/screenconnect"
        "/usr/local/bin/screenconnect"
    )
    
    for pattern in "${screenconnect_patterns[@]}"; do
        if ls $pattern >/dev/null 2>&1; then
            # Extract a clean name for ScreenConnect variations
            if [[ "$pattern" == *"ScreenConnect"* ]]; then
                found_remote+=("ScreenConnect")
            elif [[ "$pattern" == *"ConnectWise"* ]]; then
                found_remote+=("ConnectWise Control")
            fi
            break  # Only add once even if multiple matches
        fi
    done
    
    # Remove duplicates
    local unique_remote=()
    for app in "${found_remote[@]}"; do
        if [[ ! " ${unique_remote[*]} " =~ " ${app} " ]]; then
            unique_remote+=("$app")
        fi
    done
    found_remote=("${unique_remote[@]}")
    
    if [[ ${#found_remote[@]} -gt 0 ]]; then
        local remote_list=$(IFS=", "; echo "${found_remote[*]}")
        local risk_level="MEDIUM"
        local recommendation="Review remote access software for security and business justification"
        
        add_software_finding "Security" "Remote Access Software" "${#found_remote[@]} applications" "Found: $remote_list" "$risk_level" "$recommendation"
    else
        add_software_finding "Security" "Remote Access Software" "None Detected" "No remote access applications found" "INFO" ""
    fi
}

check_browser_security() {
    log_message "INFO" "Checking browser security..." "SOFTWARE"
    
    # Check Safari version
    if [[ -d "/Applications/Safari.app" ]]; then
        local safari_version=$(defaults read "/Applications/Safari.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Safari Browser" "$safari_version" "Default macOS browser" "INFO" ""
    fi
    
    # Check for browser security extensions/plugins (simplified check)
    local safari_extensions_dir="$HOME/Library/Safari/Extensions"
    if [[ -d "$safari_extensions_dir" ]]; then
        local ext_count=$(find "$safari_extensions_dir" -name "*.safariextz" 2>/dev/null | wc -l | tr -d ' ')
        if [[ $ext_count -gt 0 ]]; then
            add_software_finding "Software" "Safari Extensions" "$ext_count extensions" "Browser extensions installed" "LOW" "Review browser extensions for security and necessity"
        fi
    fi
    
    # Check for Flash Player (security risk if present)
    local flash_paths=(
        "/Library/Internet Plug-Ins/Flash Player.plugin"
        "/System/Library/Frameworks/Adobe AIR.framework"
    )
    
    local flash_found=false
    for flash_path in "${flash_paths[@]}"; do
        if [[ -e "$flash_path" ]]; then
            flash_found=true
            break
        fi
    done
    
    if [[ "$flash_found" == true ]]; then
        add_software_finding "Security" "Adobe Flash Player" "Detected" "Legacy Flash Player installation found" "HIGH" "Remove Adobe Flash Player as it's no longer supported and poses security risks"
    fi
}

check_package_managers() {
    log_message "INFO" "Checking for package managers..." "SOFTWARE"
    
    # Check for Homebrew
    if command -v brew >/dev/null 2>&1; then
        local brew_version=$(brew --version 2>/dev/null | head -1 | awk '{print $2}' || echo "Unknown")
        local brew_packages=$(brew list 2>/dev/null | wc -l | tr -d ' ')
        add_software_finding "Software" "Homebrew" "$brew_version" "$brew_packages packages installed" "INFO" ""
    fi
    
    # Check for MacPorts
    if command -v port >/dev/null 2>&1; then
        local port_version=$(port version 2>/dev/null | awk '{print $2}' || echo "Unknown")
        add_software_finding "Software" "MacPorts" "$port_version" "Package manager detected" "INFO" ""
    fi
    
    # Check for pip (Python package manager)
    if command -v pip >/dev/null 2>&1; then
        local pip_version=$(pip --version 2>/dev/null | awk '{print $2}' || echo "Unknown")
        add_software_finding "Software" "Python pip" "$pip_version" "Python package manager" "INFO" ""
    fi
    
    # Check for npm (Node.js package manager)
    if command -v npm >/dev/null 2>&1; then
        local npm_version=$(npm --version 2>/dev/null || echo "Unknown")
        add_software_finding "Software" "Node.js npm" "$npm_version" "Node.js package manager" "INFO" ""
    fi
}

# Helper function to add software findings to the array
add_software_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    SOFTWARE_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_software_findings() {
    printf '%s\n' "${SOFTWARE_FINDINGS[@]}"
}

# [SECURITY] get_patch_status - macOS update status analysis
# Order: 120
#!/bin/bash

# macOSWorkstationAuditor - Patch Status Module
# Version 1.0.0

# Global variables for collecting data
declare -a PATCH_FINDINGS=()

get_patch_status_data() {
    log_message "INFO" "Checking patch status and updates..." "PATCHING"
    
    # Initialize findings array
    PATCH_FINDINGS=()
    
    # Check macOS version and updates
    check_macos_version
    
    # Check available updates
    check_available_updates
    
    # Check automatic update settings
    check_auto_update_settings
    
    # Check XProtect updates
    check_xprotect_updates
    
    log_message "SUCCESS" "Patch status analysis completed - ${#PATCH_FINDINGS[@]} findings" "PATCHING"
}

check_macos_version() {
    log_message "INFO" "Checking macOS version..." "PATCHING"
    
    local os_version=$(sw_vers -productVersion)
    local os_build=$(sw_vers -buildVersion)
    local os_name=$(sw_vers -productName)
    
    # Check for beta/developer builds first
    local build_type="Production"
    local is_beta_build=false
    
    # Check for beta/developer build indicators
    if echo "$os_build" | grep -qE "[a-z]$"; then
        build_type="Beta/Developer Build"
        is_beta_build=true
    elif echo "$os_version" | grep -qE "beta|Beta|BETA"; then
        build_type="Beta Build"
        is_beta_build=true
    elif [[ $(date +%Y) -lt 2024 ]] && [[ "${os_version%%.*}" -ge 14 ]]; then
        # Future version detection (basic heuristic)
        build_type="Pre-release Build"
        is_beta_build=true
    fi
    
    # Use the actual marketing version instead of internal version numbers
    # Extract major version from the marketing version (e.g., 15.1 -> 15)
    local marketing_major=$(echo "$os_version" | cut -d. -f1 | tr -d '\n\r ' | sed 's/[^0-9]//g' | head -1)
    local marketing_minor=$(echo "$os_version" | cut -d. -f2 | tr -d '\n\r ' | sed 's/[^0-9]//g' | head -1)
    
    # Ensure they are valid integers
    if [[ -z "$marketing_major" ]] || ! [[ "$marketing_major" =~ ^[0-9]+$ ]]; then
        marketing_major=0
    fi
    if [[ -z "$marketing_minor" ]] || ! [[ "$marketing_minor" =~ ^[0-9]+$ ]]; then
        marketing_minor=0
    fi
    
    # Determine version status based on Apple's official support lifecycle
    # Updated with current end-of-support dates as of 2024/2025
    local version_status="Current Version"
    local risk_level="INFO"
    local recommendation=""
    local current_date=$(date +%Y%m%d)
    local monterey_eol="20241130"  # November 30, 2024
    local ventura_eol="20251130"   # November 30, 2025
    
    case "$marketing_major" in
        "15")
            version_status="Latest Version (Sequoia)"
            # Sequoia is the current latest version, fully supported
            ;;
        "14")
            version_status="Current Supported (Sonoma)"
            # Sonoma is currently supported, no EOL date announced yet
            ;;
        "13")
            version_status="Supported (Ventura)"
            if [[ $current_date -gt $ventura_eol ]]; then
                version_status="End of Life (Ventura)"
                risk_level="HIGH"
                recommendation="macOS 13 Ventura support ended November 30, 2025. Upgrade to macOS 14+ immediately"
            else
                risk_level="LOW"
                recommendation="macOS 13 Ventura support ends November 30, 2025. Plan upgrade to macOS 14+"
            fi
            ;;
        "12")
            if [[ $current_date -gt $monterey_eol ]]; then
                version_status="End of Life (Monterey)"
                risk_level="HIGH"
                recommendation="macOS 12 Monterey support ended November 30, 2024. Upgrade to macOS 13+ immediately"
            else
                version_status="End of Life Soon (Monterey)"
                risk_level="MEDIUM"
                recommendation="macOS 12 Monterey support ends November 30, 2024. Upgrade to macOS 13+ urgently"
            fi
            ;;
        "11")
            version_status="End of Life (Big Sur)"
            risk_level="HIGH"
            recommendation="macOS 11 Big Sur is no longer supported. Upgrade to macOS 13+ immediately"
            ;;
        "10")
            if [[ "$marketing_minor" -ge 15 ]]; then
                version_status="End of Life (Catalina/Legacy)"
                risk_level="HIGH"
                recommendation="macOS 10.15+ reached end of life. Upgrade to macOS 13+ immediately"
            else
                version_status="End of Life (Legacy)"
                risk_level="HIGH"
                recommendation="macOS version is no longer supported. Upgrade to macOS 13+ immediately"
            fi
            ;;
        *)
            # For unknown versions (future or very old), be conservative
            if [[ "$marketing_major" -gt 15 ]]; then
                version_status="Current"
                recommendation=""
            else
                version_status="End of Life (Legacy)"
                risk_level="HIGH"
                recommendation="macOS version is no longer supported. Upgrade to a current version immediately"
            fi
            ;;
    esac
    
    # Override risk level and recommendation for beta/developer builds
    if [[ "$is_beta_build" == true ]]; then
        risk_level="LOW"
        version_status="$build_type"
        case "$build_type" in
            "Beta/Developer Build")
                recommendation="Running a beta or developer build. Consider upgrading to production release for stability and security"
                ;;
            "Beta Build")
                recommendation="Running a beta version. Monitor for stability issues and upgrade when production version available"
                ;;
            "Pre-release Build")
                recommendation="Running a pre-release version. Verify compatibility with enterprise software"
                ;;
        esac
    fi
    
    add_patch_finding "Patching" "macOS Version" "$os_version" "$os_name $os_version (Build: $os_build) - $version_status" "$risk_level" "$recommendation"
}

check_available_updates() {
    log_message "INFO" "Checking for available updates..." "PATCHING"
    
    # Check for software updates
    local update_output=""
    local update_count=0
    local critical_updates=0
    
    # Use softwareupdate to check for available updates (with timeout)
    if command -v softwareupdate >/dev/null 2>&1; then
        log_message "INFO" "Scanning for available updates (30 second timeout)..." "PATCHING"
        # Use timeout to prevent hanging - softwareupdate can be very slow
        if command -v timeout >/dev/null 2>&1; then
            update_output=$(timeout 30 softwareupdate -l 2>&1)
        elif command -v gtimeout >/dev/null 2>&1; then
            update_output=$(gtimeout 30 softwareupdate -l 2>&1)  
        else
            # No timeout available, use a direct approach with shorter timeout
            log_message "INFO" "Using direct softwareupdate check..." "PATCHING"
            update_output=$(softwareupdate -l 2>&1)
            if [[ $? -ne 0 ]] || [[ -z "$update_output" ]]; then
                update_output="Unable to check for updates"
            fi
        fi
        
        if echo "$update_output" | grep -q "No new software available"; then
            add_patch_finding "Patching" "Available Updates" "None" "System is up to date" "INFO" ""
        elif echo "$update_output" | grep -qE "(Software Update found|restart.*required|Title:.*Version:)"; then
            # Count available updates and extract details
            update_count=$(echo "$update_output" | grep -c "Title:" || echo 0)
            
            # Extract update titles for details
            local update_titles=$(echo "$update_output" | grep "Title:" | sed 's/.*Title: //' | sed 's/,.*$//' | tr '\n' ', ' | sed 's/, $//')
            
            # Check for security/critical updates
            critical_updates=$(echo "$update_output" | grep -i -c "security\|critical" 2>/dev/null)
            if [[ -z "$critical_updates" ]]; then
                critical_updates=0
            fi
            critical_updates=$(echo "$critical_updates" | tr -d '[:space:]')
            # Ensure it's a valid number
            if ! [[ "$critical_updates" =~ ^[0-9]+$ ]]; then
                critical_updates=0
            fi
            
            local risk_level="MEDIUM"
            local recommendation="Install available updates to maintain security and stability"
            
            if [[ $critical_updates -gt 0 ]]; then
                risk_level="HIGH"
                recommendation="Critical security updates available. Install immediately"
            fi
            
            local update_details="Available: $update_titles"
            if [[ $critical_updates -gt 0 ]]; then
                update_details="$update_details ($critical_updates critical)"
            fi
            
            add_patch_finding "Patching" "Available Updates" "$update_count updates" "$update_details" "$risk_level" "$recommendation"
        elif echo "$update_output" | grep -q "timeout"; then
            add_patch_finding "Patching" "Update Check" "Timeout" "Software update check timed out after 30 seconds" "MEDIUM" "Check network connectivity and manually verify updates in System Settings"
        else
            # Handle other error cases or unexpected output
            local error_detail="Unknown response from softwareupdate command"
            if [[ -n "$update_output" ]]; then
                error_detail="Unexpected output: $(echo "$update_output" | head -1 | cut -c1-50)"
            fi
            add_patch_finding "Patching" "Update Check" "Check Failed" "$error_detail" "MEDIUM" "Verify softwareupdate command access and check System Settings manually"
        fi
    else
        add_patch_finding "Patching" "Update Tool" "Not Available" "softwareupdate command not found" "LOW" "Check system integrity"
    fi
}

check_auto_update_settings() {
    log_message "INFO" "Checking automatic update settings..." "PATCHING"
    
    # Check various automatic update preferences
    local auto_check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "unknown")
    local auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "unknown")
    local auto_install_os=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "unknown")
    local auto_install_app=$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null || echo "unknown")
    local auto_install_security=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo "unknown")
    local auto_install_system=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo "unknown")
    
    # Assess overall auto-update configuration
    local auto_config_score=0
    local config_issues=()
    
    # Check each setting
    if [[ "$auto_check" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("Automatic check disabled")
    fi
    
    if [[ "$auto_download" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("Automatic download disabled")
    fi
    
    if [[ "$auto_install_security" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("Security updates not auto-installed")
    fi
    
    if [[ "$auto_install_system" == "1" ]]; then
        ((auto_config_score++))
    else
        config_issues+=("System updates not auto-installed")
    fi
    
    # Determine overall status
    local auto_status=""
    local risk_level="INFO"
    local recommendation=""
    
    if [[ $auto_config_score -ge 3 ]]; then
        auto_status="Well Configured"
    elif [[ $auto_config_score -ge 2 ]]; then
        auto_status="Partially Configured"
        risk_level="LOW"
        recommendation="Enable additional automatic update options for better security"
    else
        auto_status="Poorly Configured"
        risk_level="MEDIUM"
        recommendation="Enable automatic updates to ensure timely security patches"
    fi
    
    local details="Check: $auto_check, Download: $auto_download, Security: $auto_install_security, System: $auto_install_system"
    add_patch_finding "Patching" "Automatic Updates" "$auto_status" "$details" "$risk_level" "$recommendation"
    
    if [[ ${#config_issues[@]} -gt 0 ]]; then
        local issues_list=$(IFS=", "; echo "${config_issues[*]}")
        add_patch_finding "Patching" "Update Configuration Issues" "${#config_issues[@]} issues" "$issues_list" "$risk_level" "$recommendation"
    fi
}

check_xprotect_updates() {
    log_message "INFO" "Checking XProtect malware definitions..." "PATCHING"
    
    # Check for macOS version to determine XProtect structure
    local macos_major=$(sw_vers -productVersion | cut -d. -f1)
    local macos_minor=$(sw_vers -productVersion | cut -d. -f2)
    
    # Primary location for macOS 15+ (Sequoia)
    local xprotect_new="/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_new_plist="/var/protected/xprotect/XProtect.bundle/Contents/Info.plist"
    
    # Legacy location (pre-Sequoia and fallback)
    local xprotect_legacy="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_legacy_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    
    # Very old location
    local xprotect_old="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist"
    
    local xprotect_version="Unknown"
    local update_time="Unknown"
    local xprotect_location="Not Found"
    local risk_level="INFO"
    local recommendation=""
    
    # Check new location first (macOS 15+)
    if [[ -f "$xprotect_new" && -f "$xprotect_new_plist" ]]; then
        xprotect_location="New Location (Sequoia+)"
        xprotect_version=$(defaults read "$xprotect_new_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        update_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_new" 2>/dev/null || echo "Unknown")
        local file_timestamp=$(stat -f "%m" "$xprotect_new" 2>/dev/null || echo "0")
        
        # Check if legacy version is newer (indicating update issue)
        if [[ -f "$xprotect_legacy_plist" ]]; then
            local legacy_version=$(defaults read "$xprotect_legacy_plist" CFBundleShortVersionString 2>/dev/null || echo "0")
            local legacy_timestamp=$(stat -f "%m" "$xprotect_legacy" 2>/dev/null || echo "0")
            
            if [[ $legacy_timestamp -gt $file_timestamp ]]; then
                recommendation="Legacy XProtect version appears newer. Run 'sudo xprotect update' to synchronize"
                risk_level="MEDIUM"
            fi
        fi
        
    # Check legacy location
    elif [[ -f "$xprotect_legacy" && -f "$xprotect_legacy_plist" ]]; then
        xprotect_location="Legacy Location"
        xprotect_version=$(defaults read "$xprotect_legacy_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        update_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_legacy" 2>/dev/null || echo "Unknown")
        local file_timestamp=$(stat -f "%m" "$xprotect_legacy" 2>/dev/null || echo "0")
        
        # If on macOS 15+ but only legacy exists, this is concerning
        if [[ $macos_major -ge 15 ]]; then
            risk_level="MEDIUM"
            recommendation="macOS 15+ detected but XProtect not in new location. Check 'sudo xprotect update'"
        fi
        
    # Check very old location (pre-bundle format)
    elif [[ -f "$xprotect_old" ]]; then
        xprotect_location="Very Old Location"
        xprotect_version=$(defaults read "$xprotect_old" Version 2>/dev/null || echo "Unknown")
        update_time=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_old" 2>/dev/null || echo "Unknown")
        local file_timestamp=$(stat -f "%m" "$xprotect_old" 2>/dev/null || echo "0")
        risk_level="HIGH"
        recommendation="Very old XProtect format detected. System may need updating"
    fi
    
    # Calculate age and assess if we found XProtect
    if [[ "$update_time" != "Unknown" && "$file_timestamp" != "0" ]]; then
        local current_timestamp=$(date +%s)
        local age_days=$(( (current_timestamp - file_timestamp) / 86400 ))
        
        # Adjust risk based on age if we found a working XProtect
        if [[ "$risk_level" != "HIGH" ]]; then
            if [[ $age_days -gt 30 ]]; then
                risk_level="MEDIUM"
                recommendation="XProtect definitions are over 30 days old. Check for update issues"
            elif [[ $age_days -gt 7 ]]; then
                risk_level="LOW"
                recommendation="XProtect definitions are over a week old. Monitor for updates"
            else
                risk_level="INFO"
                recommendation=""
            fi
        fi
        
        add_patch_finding "Security" "XProtect Definitions" "Version $xprotect_version ($xprotect_location)" "Last Update: $update_time ($age_days days ago)" "$risk_level" "$recommendation"
    else
        # XProtect not found - this is a real problem
        if [[ "$xprotect_location" == "Not Found" ]]; then
            risk_level="HIGH"
            recommendation="XProtect malware protection not found. This indicates a serious system issue"
        fi
        add_patch_finding "Security" "XProtect Definitions" "$xprotect_location" "Version: $xprotect_version" "$risk_level" "$recommendation"
    fi
    
    # Check XProtect command tool availability (macOS 15+)
    if command -v xprotect >/dev/null 2>&1; then
        local xprotect_status=$(xprotect status 2>/dev/null || echo "Unable to query")
        add_patch_finding "Security" "XProtect Management Tool" "Available" "Status: $xprotect_status" "INFO" ""
    fi
}

# Helper function to add patch findings to the array
add_patch_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    PATCH_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_patch_findings() {
    printf '%s\n' "${PATCH_FINDINGS[@]}"
}

# [SECURITY] get_security_settings - macOS security configuration analysis
# Order: 121
#!/bin/bash

# macOSWorkstationAuditor - Security Settings Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a SECURITY_FINDINGS=()

# Function to add findings to the array (bash 3.2 compatible)
add_security_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"

    # Create JSON finding (bash 3.2 compatible string building)
    local finding="{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}"

    SECURITY_FINDINGS+=("$finding")
}

get_security_settings_data() {
    log_message "INFO" "Analyzing macOS security settings..." "SECURITY"
    
    # Initialize findings array
    SECURITY_FINDINGS=()
    
    # Check XProtect (Apple's built-in malware protection)
    check_xprotect_status
    
    # Check Gatekeeper configuration
    check_gatekeeper_config
    
    # Check System Integrity Protection (SIP)
    check_sip_status
    
    # Check firewall status
    check_firewall_status
    
    # Check FileVault encryption
    check_filevault_status
    
    
    # Check third-party security software
    check_third_party_security

    # Check RMM (Remote Monitoring and Management) tools
    check_rmm_tools

    # Check privacy settings
    check_privacy_settings
    
    # Check screen lock settings
    check_screen_lock
    
    # Check MDM enrollment and management
    check_mdm_enrollment
    
    # Check iCloud status
    check_icloud_status
    
    # Check Find My status
    check_find_my_status
    
    # Check screen sharing settings
    check_screen_sharing_settings
    
    # Check file sharing services
    check_file_sharing_services
    
    # Check AirDrop status
    check_airdrop_status
    
    # Check RMM agents
    check_rmm_agents
    
    # Check backup solutions
    check_backup_solutions
    
    # Check managed login providers
    check_managed_login
    
    # Device information handled by system information module to avoid duplication
    
    log_message "SUCCESS" "Security settings analysis completed - ${#SECURITY_FINDINGS[@]} findings" "SECURITY"
}

check_xprotect_status() {
    log_message "INFO" "Checking XProtect malware protection..." "SECURITY"
    
    local xprotect_status="Unknown"
    local xprotect_version="Unknown"
    local last_update="Unknown"
    local risk_level="INFO"
    local recommendation=""
    local xprotect_location="Not Found"
    
    # Check for macOS version to determine XProtect structure
    local macos_major=$(sw_vers -productVersion | cut -d. -f1)
    
    # Primary location for macOS 15+ (Sequoia)
    local xprotect_new="/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_new_plist="/var/protected/xprotect/XProtect.bundle/Contents/Info.plist"
    
    # Legacy location (pre-Sequoia and fallback)
    local xprotect_legacy="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
    local xprotect_legacy_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    
    # Very old location
    local xprotect_old="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist"
    
    # Check new location first (macOS 15+)
    if [[ -f "$xprotect_new" && -f "$xprotect_new_plist" ]]; then
        xprotect_status="Enabled"
        xprotect_location="Modern (Sequoia+)"
        xprotect_version=$(defaults read "$xprotect_new_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        last_update=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_new" 2>/dev/null || echo "Unknown")
        
    # Check legacy location
    elif [[ -f "$xprotect_legacy" && -f "$xprotect_legacy_plist" ]]; then
        xprotect_status="Enabled"
        xprotect_location="Legacy"
        xprotect_version=$(defaults read "$xprotect_legacy_plist" CFBundleShortVersionString 2>/dev/null || echo "Unknown")
        last_update=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_legacy" 2>/dev/null || echo "Unknown")
        
        if [[ $macos_major -ge 15 ]]; then
            risk_level="LOW"
            recommendation="macOS 15+ detected but XProtect using legacy location. Modern location preferred"
        fi
        
    # Check very old location
    elif [[ -f "$xprotect_old" ]]; then
        xprotect_status="Enabled"
        xprotect_location="Very Old"
        xprotect_version=$(defaults read "$xprotect_old" Version 2>/dev/null || echo "Unknown")
        last_update=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$xprotect_old" 2>/dev/null || echo "Unknown")
        risk_level="MEDIUM"
        recommendation="Very old XProtect format detected. System may need updating"
        
    else
        xprotect_status="Not Found"
        risk_level="HIGH"
        recommendation="XProtect malware protection not found. This is unusual for macOS systems"
    fi
    
    add_security_finding "Security" "XProtect Malware Protection" "$xprotect_status ($xprotect_location)" "Version: $xprotect_version, Last Update: $last_update" "$risk_level" "$recommendation"
}

check_gatekeeper_config() {
    log_message "INFO" "Checking Gatekeeper configuration..." "SECURITY"
    
    local gatekeeper_status="Unknown"
    local risk_level="INFO"
    local recommendation=""
    
    if command -v spctl >/dev/null 2>&1; then
        local gk_output=$(spctl --status 2>/dev/null)
        if echo "$gk_output" | grep -q "assessments enabled"; then
            gatekeeper_status="Enabled"
        elif echo "$gk_output" | grep -q "assessments disabled"; then
            gatekeeper_status="Disabled"
            risk_level="MEDIUM"
            recommendation="Gatekeeper is disabled. Enable it to prevent execution of malicious software"
        else
            gatekeeper_status="Unknown Status"
            risk_level="LOW"
            recommendation="Could not determine Gatekeeper status. Verify security settings"
        fi
    else
        gatekeeper_status="Command Not Available"
        risk_level="LOW"
        recommendation="spctl command not available to check Gatekeeper status"
    fi
    
    # Check for developer mode or reduced security
    local dev_mode_details=""
    if [[ "$gatekeeper_status" == "Enabled" ]]; then
        local gk_assess_output=$(spctl --assess --verbose /Applications/Safari.app 2>&1 || echo "")
        if echo "$gk_assess_output" | grep -q "override"; then
            dev_mode_details="Developer mode or security overrides detected"
            risk_level="LOW"
            recommendation="Review Gatekeeper overrides and developer mode settings for security implications"
        fi
    fi
    
    add_security_finding "Security" "Gatekeeper" "$gatekeeper_status" "Application execution control. $dev_mode_details" "$risk_level" "$recommendation"
}

check_sip_status() {
    log_message "INFO" "Checking System Integrity Protection..." "SECURITY"
    
    local sip_status="Unknown"
    local sip_details=""
    local risk_level="INFO"
    local recommendation=""
    
    if command -v csrutil >/dev/null 2>&1; then
        local sip_output=$(csrutil status 2>/dev/null)
        if echo "$sip_output" | grep -q "enabled"; then
            sip_status="Enabled"
            sip_details="Full kernel-level protection active"
        elif echo "$sip_output" | grep -q "disabled"; then
            sip_status="Disabled"
            sip_details="System protections disabled"
            risk_level="MEDIUM"
            recommendation="SIP is disabled. Enable System Integrity Protection for enhanced security unless specifically required for development"
        else
            sip_status="Partially Disabled"
            sip_details="Some protections may be disabled"
            risk_level="LOW"
            recommendation="Review SIP configuration to ensure appropriate security level"
        fi
    else
        sip_status="Command Not Available"
        risk_level="LOW"
        recommendation="csrutil command not available to check SIP status"
    fi
    
    add_security_finding "Security" "System Integrity Protection" "$sip_status" "$sip_details" "$risk_level" "$recommendation"
}

check_firewall_status() {
    log_message "INFO" "Checking firewall configuration..." "SECURITY"
    
    local firewall_status="Unknown"
    local stealth_mode="Unknown"
    local risk_level="INFO"
    local recommendation=""
    
    # Check application firewall status using multiple methods
    local fw_state=""
    
    # Method 1: Try direct defaults read (most reliable)
    fw_state=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
    
    # Method 2: If that fails, try user domain (sometimes firewall settings are here)
    if [[ -z "$fw_state" ]]; then
        fw_state=$(defaults read ~/Library/Preferences/com.apple.alf globalstate 2>/dev/null)
    fi
    
    # Method 3: Try socketfilterfw command if available
    if [[ -z "$fw_state" ]] && command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null 2>&1; then
        local socketfw_status=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
        if echo "$socketfw_status" | grep -q "enabled"; then
            fw_state="1"  # Default to basic enabled state
        elif echo "$socketfw_status" | grep -q "disabled"; then
            fw_state="0"
        fi
    fi
    
    # Ensure we have a clean integer value
    fw_state=$(echo "$fw_state" | tr -d '[:space:]' | grep -o '^[0-9]')
    
    case "$fw_state" in
        0)
            firewall_status="Disabled"
            risk_level="MEDIUM"
            recommendation="Application firewall is disabled. Enable firewall to protect against unauthorized network connections"
            ;;
        1)
            firewall_status="Enabled (Allow signed software)"
            ;;
        2)
            firewall_status="Enabled (Block all incoming)"
            ;;
        *)
            # Default to showing what we actually detected
            if [[ -n "$fw_state" ]]; then
                firewall_status="Unknown State (detected: $fw_state)"
            else
                firewall_status="Cannot Determine"
                risk_level="LOW"
                recommendation="Unable to read firewall status. Check System Settings > Network > Firewall for current state"
            fi
            ;;
    esac
    
    # Check stealth mode with better error handling
    local stealth_state=""
    stealth_state=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
    
    # Fallback to user domain if system domain fails
    if [[ -z "$stealth_state" ]]; then
        stealth_state=$(defaults read ~/Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
    fi
    
    # Clean the value
    stealth_state=$(echo "$stealth_state" | tr -d '[:space:]' | grep -o '^[0-9]')
    
    if [[ "$stealth_state" == "1" ]]; then
        stealth_mode="Enabled"
    elif [[ "$stealth_state" == "0" ]]; then
        stealth_mode="Disabled"
    else
        stealth_mode="Unknown"
    fi
    
    local details="Stealth mode: $stealth_mode"
    add_security_finding "Security" "Application Firewall" "$firewall_status" "$details" "$risk_level" "$recommendation"
}

check_filevault_status() {
    log_message "INFO" "Checking FileVault encryption..." "SECURITY"
    
    local fv_status="Unknown"
    local risk_level="INFO"
    local recommendation=""
    local details=""
    
    if command -v fdesetup >/dev/null 2>&1; then
        local fv_output=$(fdesetup status 2>/dev/null)
        if echo "$fv_output" | grep -q "FileVault is On"; then
            fv_status="Enabled"
            details="Full disk encryption active"
        elif echo "$fv_output" | grep -q "FileVault is Off"; then
            fv_status="Disabled"
            risk_level="HIGH"
            recommendation="FileVault disk encryption is disabled. Enable FileVault to protect data if device is lost or stolen"
            details="Disk encryption not active - data at risk"
        else
            fv_status="Unknown State"
            risk_level="LOW"
            recommendation="Could not determine FileVault status. Check encryption settings"
            details="FileVault status unclear"
        fi
    else
        fv_status="Command Not Available"
        risk_level="LOW"
        recommendation="fdesetup command not available to check FileVault status"
    fi
    
    add_security_finding "Security" "FileVault Encryption" "$fv_status" "$details" "$risk_level" "$recommendation"
}


check_third_party_security() {
    log_message "INFO" "Checking for third-party security software..." "SECURITY"
    
    local detected_av=()
    local detected_security=()
    
    # Common antivirus applications
    local av_paths=(
        "/Applications/Bitdefender Virus Scanner.app"
        "/Applications/ClamXav.app"
        "/Applications/Malwarebytes Anti-Malware.app"
        "/Applications/Norton Security.app"
        "/Applications/Sophos Endpoint.app"
        "/Applications/Trend Micro Antivirus.app"
        "/Applications/Intego VirusBarrier.app"
        "/Applications/Avast.app"
        "/Applications/AVG AntiVirus.app"
        "/Applications/ESET Cyber Security.app"
        "/Applications/Kaspersky Internet Security.app"
        "/Applications/McAfee Endpoint Security for Mac.app"
    )
    
    # Common security tools
    local security_paths=(
        "/Applications/1Blocker- Ad Blocker & Privacy.app"
        "/Applications/Little Snitch.app"
        "/Applications/Micro Snitch.app"
        "/Applications/BlockBlock.app"
        "/Applications/LuLu.app"
        "/Applications/Radio Silence.app"
    )
    
    # Check for antivirus software
    for av_path in "${av_paths[@]}"; do
        if [[ -d "$av_path" ]]; then
            local av_name=$(basename "$av_path" .app)
            detected_av+=("$av_name")
        fi
    done
    
    # Check for security tools
    for sec_path in "${security_paths[@]}"; do
        if [[ -d "$sec_path" ]]; then
            local sec_name=$(basename "$sec_path" .app)
            detected_security+=("$sec_name")
        fi
    done
    
    # Report antivirus findings
    if [[ ${#detected_av[@]} -gt 0 ]]; then
        local av_list=$(IFS=", "; echo "${detected_av[*]}")
        add_security_finding "Security" "Third-party Antivirus" "Detected" "Found: $av_list" "INFO" ""
    else
        add_security_finding "Security" "Third-party Antivirus" "None Detected" "Relying on built-in XProtect and system security" "INFO" ""
    fi
    
    # Report security tools
    if [[ ${#detected_security[@]} -gt 0 ]]; then
        local sec_list=$(IFS=", "; echo "${detected_security[*]}")
        add_security_finding "Security" "Security Tools" "Detected" "Found: $sec_list" "INFO" ""
    else
        add_security_finding "Security" "Security Tools" "None Detected" "Basic macOS security features detected" "INFO" "Evaluate enterprise security solutions such as CrowdStrike, SentinelOne, or Jamf Protect for comprehensive threat detection"
    fi
}

check_rmm_tools() {
    log_message "INFO" "Checking for RMM (Remote Monitoring and Management) tools..." "SECURITY"

    local detected_rmm=()
    local risk_level="INFO"
    local recommendation=""

    # Actual RMM applications (not screen sharing)
    local rmm_paths=(
        "/Applications/DattoRMM.app"
        "/Applications/Kaseya.app"
        "/Applications/NinjaRMM.app"
        "/Applications/N-able.app"
        "/Applications/Atera.app"
        "/Applications/Pulseway.app"
        "/Applications/Automate.app"
        "/Applications/Datto.app"
        "/Applications/Syncro.app"
        "/Applications/SimpleHelp.app"
        "/Applications/Level.app"
        "/Applications/Tacticalrmm.app"
        "/Applications/Comodo One.app"
        "/Applications/ManageEngine.app"
        "/Applications/SolarWinds.app"
        "/Applications/Continuum.app"
        "/Applications/LabTech.app"
        "/Applications/ConnectWise Automate.app"
        "/Applications/ConnectWise Manage.app"
    )

    # Check for RMM applications
    for rmm_path in "${rmm_paths[@]}"; do
        if [[ -d "$rmm_path" ]]; then
            local rmm_name=$(basename "$rmm_path" .app)
            detected_rmm+=("$rmm_name")
        fi
    done

    # Check running processes for RMM services (not screen sharing)
    local rmm_processes=$(ps -axo comm | grep -iE "(kaseya|ninj|nable|atera|pulseway|datto|syncro|simplehelp)" | head -3)
    if [[ -n "$rmm_processes" ]]; then
        while IFS= read -r process; do
            if [[ -n "$process" ]]; then
                local process_name=$(basename "$process" | cut -d. -f1)
                # Only add if not already detected
                if [[ ! " ${detected_rmm[*]} " =~ " ${process_name} " ]]; then
                    detected_rmm+=("${process_name} (service)")
                fi
            fi
        done <<< "$rmm_processes"
    fi

    # Report RMM findings
    if [[ ${#detected_rmm[@]} -gt 0 ]]; then
        local rmm_list=$(IFS=", "; echo "${detected_rmm[*]}")
        risk_level="INFO"
        recommendation=""
        add_security_finding "Security" "RMM Tools" "Detected" "Found: $rmm_list" "$risk_level" "$recommendation"
    else
        add_security_finding "Security" "RMM Tools" "None Detected" "No remote monitoring or management platforms found" "INFO" ""
    fi
}

check_privacy_settings() {
    log_message "INFO" "Checking privacy and security settings..." "SECURITY"
    
    # Check location services using accurate method
    local location_enabled="Unknown"
    local location_details="Unable to determine location services status"
    
    # Method 1: Check the actual LocationServicesEnabled setting (most reliable)
    local location_pref=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null)
    if [[ "$location_pref" == "1" ]]; then
        location_enabled="Enabled"
        location_details="Location services enabled in system preferences"
    elif [[ "$location_pref" == "0" ]]; then
        location_enabled="Disabled"
        location_details="Location services disabled in system preferences"
    # Method 2: Alternative location for newer macOS versions
    elif [[ -f "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist" ]]; then
        # Try to read the plist directly
        local plist_value=$(plutil -extract LocationServicesEnabled raw "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist" 2>/dev/null)
        if [[ "$plist_value" == "true" ]]; then
            location_enabled="Enabled"
            location_details="Location services enabled (plist configuration)"
        elif [[ "$plist_value" == "false" ]]; then
            location_enabled="Disabled"
            location_details="Location services disabled (plist configuration)"
        else
            location_enabled="Available"
            location_details="Location services configuration present but status unclear"
        fi
    # Method 3: Check user preference for current user
    elif [[ -n "$(defaults read com.apple.locationmenu LocationServicesEnabled 2>/dev/null)" ]]; then
        local user_location=$(defaults read com.apple.locationmenu LocationServicesEnabled 2>/dev/null)
        if [[ "$user_location" == "1" ]]; then
            location_enabled="Enabled"
            location_details="Location services enabled (user preferences)"
        else
            location_enabled="Disabled"
            location_details="Location services disabled (user preferences)"
        fi
    # Method 4: Check if daemon is running as a fallback indicator
    elif pgrep -x "locationd" >/dev/null 2>&1; then
        location_enabled="Enabled"
        location_details="Location daemon active (indicates services are enabled)"
    else
        location_enabled="Disabled"
        location_details="No location daemon or configuration detected"
    fi
    
    add_security_finding "Privacy" "Location Services" "$location_enabled" "$location_details" "INFO" ""
    
    # Check analytics/diagnostics with better detection
    local analytics_enabled="Disabled"
    local analytics_details="Diagnostic data sharing is disabled"
    
    # Method 1: Check system-wide analytics setting
    local analytics_pref=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null)
    if [[ -z "$analytics_pref" ]]; then
        # Method 2: Alternative location
        analytics_pref=$(defaults read com.apple.SubmitDiagInfo AutoSubmit 2>/dev/null)
    fi
    if [[ -z "$analytics_pref" ]]; then
        # Method 3: User-specific setting
        analytics_pref=$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)
        if [[ "$analytics_pref" == "none" ]]; then
            analytics_pref="0"
        elif [[ "$analytics_pref" == "crashreport" || "$analytics_pref" == "server" ]]; then
            analytics_pref="1"
        fi
    fi
    
    if [[ "$analytics_pref" == "1" ]]; then
        analytics_enabled="Enabled"
        analytics_details="System diagnostic data is shared with Apple"
    elif [[ "$analytics_pref" == "0" ]]; then
        analytics_enabled="Disabled"
        analytics_details="Diagnostic data sharing is disabled"
    else
        # Check if user chose to not send crash reports (typical default)
        local crash_reporter_type=$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)
        if [[ "$crash_reporter_type" == "none" ]]; then
            analytics_enabled="Disabled"
            analytics_details="Crash reporting disabled (user preference)"
        elif [[ -f "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" ]]; then
            analytics_enabled="Disabled"
            analytics_details="Diagnostic data sharing disabled (system default)"
        else
            analytics_enabled="Not Configured"
            analytics_details="Analytics preferences have not been configured"
        fi
    fi
    
    add_security_finding "Privacy" "Analytics & Diagnostics" "$analytics_enabled" "$analytics_details" "INFO" ""
}

check_screen_lock() {
    log_message "INFO" "Checking screen lock settings..." "SECURITY"
    
    local ask_for_password=""
    local delay_time=""
    local risk_level="INFO"
    local recommendation=""
    local screen_lock_status="Unknown"
    local detection_method=""
    
    # Check multiple possible locations for screen lock settings
    # Method 1: Try global domain first (modern macOS)
    ask_for_password=$(defaults read -g askForPassword 2>/dev/null)
    if [[ -n "$ask_for_password" ]]; then
        detection_method="Global domain"
        delay_time=$(defaults read -g askForPasswordDelay 2>/dev/null)
    fi
    
    # Method 2: Try screensaver domain (legacy and some modern systems)
    if [[ -z "$ask_for_password" ]]; then
        ask_for_password=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
        if [[ -n "$ask_for_password" ]]; then
            detection_method="Screensaver domain"
            delay_time=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
        fi
    fi
    
    # Method 3: Try current user's screensaver preferences
    if [[ -z "$ask_for_password" ]]; then
        ask_for_password=$(defaults read ~/Library/Preferences/com.apple.screensaver askForPassword 2>/dev/null)
        if [[ -n "$ask_for_password" ]]; then
            detection_method="User screensaver preferences"
            delay_time=$(defaults read ~/Library/Preferences/com.apple.screensaver askForPasswordDelay 2>/dev/null)
        fi
    fi
    
    # Method 4: Check if system has screen lock via login window preferences
    if [[ -z "$ask_for_password" ]]; then
        local loginwindow_lock=$(defaults read /Library/Preferences/com.apple.loginwindow DisableScreenLock 2>/dev/null)
        if [[ "$loginwindow_lock" == "0" || -z "$loginwindow_lock" ]]; then
            # Screen lock is not disabled, assume it's enabled
            ask_for_password="1"
            detection_method="System policy"
            delay_time="0"  # Default to immediate
        fi
    fi
    
    # Method 5: Check for Touch ID/biometric unlock as an indicator of screen security
    local biometric_unlock="No"
    local biometric_processes=""
    if pgrep -x "biometrickitd" >/dev/null 2>&1; then
        biometric_unlock="Available"
        biometric_processes="biometrickitd"
    fi
    
    # Check for Apple Watch unlock capability
    if pgrep -x "watchdog" >/dev/null 2>&1 || [[ -f "/System/Library/PrivateFrameworks/WatchConnectivity.framework/WatchConnectivity" ]]; then
        if [[ "$biometric_unlock" == "Available" ]]; then
            biometric_unlock="Touch ID + Apple Watch"
        else
            biometric_unlock="Apple Watch"
        fi
    fi
    
    # Clean up values
    ask_for_password=$(echo "$ask_for_password" | tr -d '[:space:]')
    delay_time=$(echo "$delay_time" | tr -d '[:space:]')
    
    # If delay_time is empty, default to 0 (immediate)
    if [[ -z "$delay_time" ]]; then
        delay_time="0"
    fi
    
    # Determine screen lock status
    if [[ "$ask_for_password" == "1" ]]; then
        if [[ "$delay_time" == "0" ]]; then
            screen_lock_status="Immediate"
            add_security_finding "Security" "Screen Lock" "Immediate" "Password required immediately after sleep/screensaver, Biometric: $biometric_unlock ($detection_method)" "INFO" ""
        else
            local delay_desc="${delay_time} seconds"
            screen_lock_status="Delayed ($delay_desc)"
            if [[ "$delay_time" -gt 300 ]]; then  # More than 5 minutes
                risk_level="MEDIUM"
                recommendation="Screen lock delay is too long. Reduce delay to 5 minutes or less for better security"
            elif [[ "$delay_time" -gt 60 ]]; then  # More than 1 minute
                risk_level="LOW"
                recommendation="Consider reducing screen lock delay for improved security"
            fi
            add_security_finding "Security" "Screen Lock" "Delayed" "Password required after $delay_desc delay, Biometric: $biometric_unlock ($detection_method)" "$risk_level" "$recommendation"
        fi
    elif [[ "$ask_for_password" == "0" ]]; then
        add_security_finding "Security" "Screen Lock" "Disabled" "No password required after sleep/screensaver ($detection_method)" "HIGH" "Enable screen lock password requirement for security"
    else
        # Check if we can determine screen lock from system security features
        if [[ "$biometric_unlock" != "No" ]]; then
            # If biometrics are available, screen lock is likely configured
            screen_lock_status="Likely Enabled"
            add_security_finding "Security" "Screen Lock" "Likely Enabled" "Biometric unlock ($biometric_unlock) is active, indicating screen security is configured" "INFO" ""
        else
            # Unable to determine - could be controlled by MDM or other policy
            add_security_finding "Security" "Screen Lock" "Cannot Determine" "Screen lock configuration cannot be detected - may be controlled by system policy or MDM" "LOW" "Screen lock status unclear due to system restrictions"
        fi
    fi
}

check_mdm_enrollment() {
    log_message "INFO" "Checking MDM enrollment status..." "SECURITY"
    
    # Check MDM enrollment using profiles command
    local enrollment_status="Unknown"
    local enrollment_details=""
    local risk_level="INFO"
    local recommendation=""
    
    if command -v profiles >/dev/null 2>&1; then
        local profiles_output=$(profiles status -type enrollment 2>/dev/null)
        
        if echo "$profiles_output" | grep -q "Enrolled via DEP: Yes"; then
            enrollment_status="DEP Enrolled"
            enrollment_details="Device Enrollment Program (automated enrollment)"
            
            if echo "$profiles_output" | grep -q "User Approved"; then
                enrollment_details="$enrollment_details - User Approved MDM"
                risk_level="INFO"
            else
                enrollment_details="$enrollment_details - Not User Approved"
                risk_level="LOW"
                recommendation="MDM enrollment detected but not user-approved. Some management features may be limited"
            fi
            
        elif echo "$profiles_output" | grep -q "MDM enrollment: Yes (User Approved)"; then
            enrollment_status="User Enrolled"
            enrollment_details="Manual MDM enrollment with user approval"
            risk_level="INFO"
            
        elif echo "$profiles_output" | grep -q "MDM enrollment: Yes"; then
            enrollment_status="Enrolled (Not User Approved)"
            enrollment_details="MDM enrolled but lacking user approval"
            risk_level="MEDIUM"
            recommendation="MDM enrollment detected but not user-approved. Limited management capabilities"
            
        elif echo "$profiles_output" | grep -q "MDM enrollment: No"; then
            enrollment_status="Not Enrolled"
            enrollment_details="Device is not enrolled in Mobile Device Management"
            risk_level="INFO"
            
        else
            enrollment_status="Unknown"
            enrollment_details="Unable to determine MDM enrollment status"
            risk_level="LOW"
            recommendation="Verify MDM enrollment status manually"
        fi
        
        # Check for specific MDM profiles
        local mdm_profiles=$(profiles -P 2>/dev/null | grep -E "MDM|Device Management|Mobile Device Management" | wc -l | tr -d ' ')
        if [[ $mdm_profiles -gt 0 ]]; then
            enrollment_details="$enrollment_details ($mdm_profiles MDM profiles installed)"
        fi
        
    else
        enrollment_status="Unable to Check"
        enrollment_details="profiles command not available"
        risk_level="LOW"
        recommendation="Install macOS command line tools to check MDM status"
    fi
    
    add_security_finding "Management" "MDM Enrollment" "$enrollment_status" "$enrollment_details" "$risk_level" "$recommendation"
    
    # Check device supervision status
    check_device_supervision
    
    # Check for configuration profiles
    check_configuration_profiles
}

check_device_supervision() {
    log_message "INFO" "Checking device supervision status..." "SECURITY"
    
    local supervision_status="Not Supervised"
    local supervision_details=""
    local dep_status="Not Enrolled"
    local risk_level="INFO"
    local recommendation=""
    
    if command -v profiles >/dev/null 2>&1; then
        # Check supervision status (requires elevated privileges)
        local supervision_output=""
        if [[ $EUID -eq 0 ]]; then
            supervision_output=$(profiles -S 2>/dev/null)
            
            if [[ $? -eq 0 && -n "$supervision_output" ]]; then
                if echo "$supervision_output" | grep -q "Device Enrollment Program.*YES"; then
                    dep_status="DEP Enrolled"
                    supervision_status="Supervised (DEP)"
                    supervision_details="Device is supervised via Device Enrollment Program (Apple Business Manager)"
                    risk_level="INFO"
                elif echo "$supervision_output" | grep -q "Supervision.*YES"; then
                    supervision_status="Supervised (Manual)"
                    supervision_details="Device is manually supervised"
                    risk_level="INFO"
                elif echo "$supervision_output" | grep -q "Supervision.*NO"; then
                    supervision_status="Not Supervised"
                    supervision_details="Device is not under supervision"
                    risk_level="INFO"
                fi
                
                # Check DEP enrollment separately
                if echo "$supervision_output" | grep -q "Device Enrollment Program.*NO"; then
                    dep_status="Not DEP Enrolled"
                fi
            else
                supervision_status="Unable to Check"
                supervision_details="Run with sudo for definitive status"
                dep_status="Unable to Check"
            fi
        else
            # Running without administrative privileges - use alternative detection methods
            supervision_details="Run with sudo for definitive status - using indirect detection"
            
            # Check for MDM-related files and processes as indicators
            local mdm_indicators=0
            
            # Check for MDM processes
            if pgrep -f "mdm" >/dev/null 2>&1; then
                ((mdm_indicators++))
            fi
            
            # Check for configuration profiles directory
            if [[ -d "/var/db/ConfigurationProfiles" ]] && [[ $(ls -1 /var/db/ConfigurationProfiles/ 2>/dev/null | wc -l) -gt 2 ]]; then
                ((mdm_indicators++))
            fi
            
            # Check for common MDM apps
            if [[ -d "/Applications/Company Portal.app" ]] || [[ -d "/Applications/Self Service.app" ]] || [[ -d "/Applications/Munki Managed Software Center.app" ]]; then
                ((mdm_indicators++))
            fi
            
            # Check definitive indicators for unmanaged devices
            local profile_count=$(profiles show 2>/dev/null | grep -c "There are no configuration profiles" || echo "0")
            local system_profiler_check=$(system_profiler SPConfigurationProfileDataType 2>/dev/null | wc -l)

            if [[ "$profile_count" -gt 0 || "$system_profiler_check" -eq 0 ]]; then
                # Definitive evidence of no management
                supervision_status="Not Supervised"
                dep_status="Not Enrolled"
                supervision_details="No configuration profiles installed - personal/unmanaged device"
                risk_level="INFO"
                recommendation=""
            elif [[ $mdm_indicators -gt 0 ]]; then
                supervision_status="Possibly Supervised"
                dep_status="Possibly Enrolled"
                supervision_details="Found $mdm_indicators MDM indicators. Run with administrative privileges for definitive status"
                risk_level="LOW"
                recommendation="Run audit with sudo for complete device management analysis"
            else
                supervision_status="Not Supervised"
                dep_status="Not Enrolled"
                supervision_details="No MDM indicators or configuration profiles detected - personal/unmanaged device"
                risk_level="INFO"
                recommendation=""
            fi
        fi
        
        # Add DEP/Apple Business Manager status as separate finding
        local dep_details=""
        if [[ "$dep_status" == "DEP Enrolled" ]]; then
            dep_details="Device enrolled through Apple Business Manager or Apple School Manager"
        elif [[ "$dep_status" == "Not DEP Enrolled" ]]; then
            dep_details="Device not enrolled via Apple Business Manager - manually managed or personal device"
        elif [[ "$dep_status" == "Requires Administrative Privileges" ]]; then
            dep_details="Apple Business Manager enrollment status requires administrative privileges (see startup message)"
        elif [[ "$dep_status" == "Likely Not Enrolled" ]]; then
            dep_details="No MDM indicators detected - appears to be personal/unmanaged device"
        elif [[ "$dep_status" == "Possibly Enrolled" ]]; then
            dep_details="MDM indicators detected - may be enrolled in device management"
        fi
        
        add_security_finding "Management" "Apple Business Manager" "$dep_status" "$dep_details" "INFO" "$recommendation"
        
    else
        supervision_status="Unable to Check"
        supervision_details="profiles command not available"
        risk_level="LOW"
        recommendation="Install macOS command line tools to check supervision status"
    fi
    
    add_security_finding "Management" "Device Supervision" "$supervision_status" "$supervision_details" "$risk_level" "$recommendation"
}

check_configuration_profiles() {
    log_message "INFO" "Checking configuration profiles..." "SECURITY"
    
    if command -v profiles >/dev/null 2>&1; then
        # Count system profiles
        local system_profiles=$(profiles -P 2>/dev/null | grep -c "System" 2>/dev/null)
        if [[ -z "$system_profiles" ]]; then
            system_profiles=0
        fi
        system_profiles=$(echo "$system_profiles" | tr -d '[:space:]')
        if ! [[ "$system_profiles" =~ ^[0-9]+$ ]]; then
            system_profiles=0
        fi
        
        local user_profiles=$(profiles -P 2>/dev/null | grep -c "User" 2>/dev/null)
        if [[ -z "$user_profiles" ]]; then
            user_profiles=0
        fi
        user_profiles=$(echo "$user_profiles" | tr -d '[:space:]')
        if ! [[ "$user_profiles" =~ ^[0-9]+$ ]]; then
            user_profiles=0
        fi
        
        # Check for concerning profile types
        local security_profiles=$(profiles -P 2>/dev/null | grep -iE "certificate|vpn|wifi|security|restriction" | wc -l | tr -d ' ')
        
        local risk_level="INFO"
        local recommendation=""
        
        if [[ $system_profiles -gt 10 ]]; then
            risk_level="LOW"
            recommendation="Large number of system profiles detected. Review for necessity"
        fi
        
        add_security_finding "Management" "Configuration Profiles" "$system_profiles system, $user_profiles user" "Security-related profiles: $security_profiles" "$risk_level" "$recommendation"
        
        # Check for VPN profiles specifically
        local vpn_profiles=$(profiles -P 2>/dev/null | grep -i "vpn" | wc -l | tr -d ' ')
        if ! [[ "$vpn_profiles" =~ ^[0-9]+$ ]]; then
            vpn_profiles=0
        fi
        if [[ $vpn_profiles -gt 0 ]]; then
            add_security_finding "Network" "VPN Profiles" "$vpn_profiles profiles" "VPN configuration profiles installed" "INFO" ""
        fi
    fi
}



check_screen_sharing_settings() {
    log_message "INFO" "Checking remote access settings..." "SECURITY"
    
    # Check if Screen Sharing and SSH are enabled using proper methods from research
    local screen_sharing_enabled="Disabled"
    local vnc_enabled="Disabled" 
    local remote_management_enabled="Disabled"
    local ssh_enabled="Disabled"
    local details=""
    local risk_level="INFO"
    local recommendation=""
    
    # Method 1: Check for VNC listening port using netstat (no sudo required)
    if netstat -atp tcp 2>/dev/null | grep -q rfb; then
        screen_sharing_enabled="Enabled" 
        vnc_enabled="Enabled"
    fi
    
    # Method 2: Check if VNC port 5900 is listening (fallback)
    if netstat -an 2>/dev/null | grep -q ":5900.*LISTEN"; then
        screen_sharing_enabled="Enabled"
        vnc_enabled="Enabled"
    fi
    
    
    # Check Apple Remote Desktop (ARD) - different from screen sharing
    if pgrep -x "ARDAgent" >/dev/null 2>&1; then
        remote_management_enabled="Enabled"
    fi
    
    # Also check for Remote Management via system preferences (if available)
    if [[ -f "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd" ]]; then
        remote_management_enabled="Enabled"
    fi
    
    # Check SSH (Remote Login) status using multiple methods
    # Method 1: Check if SSH port 22 is listening (no admin required)
    if netstat -an 2>/dev/null | grep -q -E "(\*\.22.*LISTEN|:22.*LISTEN|\*\.ssh.*LISTEN)"; then
        ssh_enabled="Enabled"
    fi
    
    # Method 2: Check if SSH process is running
    if pgrep -x "sshd" >/dev/null 2>&1; then
        ssh_enabled="Enabled"
    fi
    
    # Method 3: Try systemsetup (may require admin)
    local ssh_status=$(systemsetup -getremotelogin 2>/dev/null)
    if [[ "$ssh_status" == *"Remote Login: On"* ]]; then
        ssh_enabled="Enabled"
    elif [[ "$ssh_status" == *"Remote Login: Off"* ]]; then
        ssh_enabled="Disabled"
    fi
    
    
    # Determine overall status and risk level for all remote access services
    local enabled_services=()
    local remote_access_enabled="Disabled"
    
    if [[ "$vnc_enabled" == "Enabled" ]]; then
        enabled_services+=("VNC/Screen Sharing")
        remote_access_enabled="Enabled"
    fi
    
    if [[ "$remote_management_enabled" == "Enabled" ]]; then
        enabled_services+=("Remote Management/ARD")
        remote_access_enabled="Enabled"
    fi
    
    if [[ "$ssh_enabled" == "Enabled" ]]; then
        enabled_services+=("SSH/Remote Login")
        remote_access_enabled="Enabled"
    fi
    
    # Set details and risk assessment based on all remote access services
    if [[ "$remote_access_enabled" == "Enabled" ]]; then
        details="Enabled services: $(IFS=", "; echo "${enabled_services[*]}")"
        
        if [[ ${#enabled_services[@]} -gt 2 ]]; then
            risk_level="HIGH"
            recommendation="Multiple remote access methods enabled (${#enabled_services[@]} services). Review necessity and ensure strong authentication"
        elif [[ ${#enabled_services[@]} -gt 1 ]]; then
            risk_level="MEDIUM"
            recommendation="Multiple remote access methods enabled. Ensure proper authentication and network restrictions"
        else
            risk_level="LOW"  
            recommendation="Remote access enabled. Ensure strong passwords and network access controls"
        fi
    else
        details="No remote access services detected (SSH, VNC, ARD all disabled)"
        risk_level="INFO"
        recommendation=""
    fi
    
    add_security_finding "Security" "Remote Access Services" "$remote_access_enabled" "$details" "$risk_level" "$recommendation"
}

check_file_sharing_services() {
    log_message "INFO" "Checking file sharing services..." "SECURITY"
    
    local file_sharing_enabled="Disabled"
    local enabled_services=()
    local details=""
    local risk_level="INFO"
    local recommendation=""
    
    # Check SMB (Samba) file sharing
    if launchctl list | grep -q smbd 2>/dev/null; then
        enabled_services+=("SMB")
        file_sharing_enabled="Enabled"
    fi
    
    # Check AFP (Apple Filing Protocol) - deprecated but still possible
    if launchctl list | grep -q afpd 2>/dev/null; then
        enabled_services+=("AFP")
        file_sharing_enabled="Enabled"
    fi
    
    # Check FTP service
    if launchctl list | grep -q ftpd 2>/dev/null; then
        enabled_services+=("FTP")
        file_sharing_enabled="Enabled"
    fi
    
    # Check NFS (Network File System) - must be actively listening
    if netstat -an 2>/dev/null | grep -q ":2049.*LISTEN"; then
        enabled_services+=("NFS")
        file_sharing_enabled="Enabled"
    fi
    
    # Alternative method: Check using systemsetup (may require admin)
    local sharing_status=$(systemsetup -getremoteappleevents 2>/dev/null)
    if [[ "$sharing_status" == *"Remote Apple Events: On"* ]]; then
        enabled_services+=("Remote Apple Events")
        file_sharing_enabled="Enabled"
    fi
    
    # Check for listening ports commonly used by file sharing
    if netstat -an 2>/dev/null | grep -E ":445.*LISTEN|:139.*LISTEN|:548.*LISTEN|:21.*LISTEN|:2049.*LISTEN" >/dev/null; then
        if [[ "$file_sharing_enabled" == "Disabled" ]]; then
            enabled_services+=("Unknown File Sharing")
            file_sharing_enabled="Enabled"
        fi
    fi
    
    # Set risk level and details
    if [[ "$file_sharing_enabled" == "Enabled" ]]; then
        details="Active services: $(IFS=", "; echo "${enabled_services[*]}")"
        
        if [[ ${#enabled_services[@]} -gt 2 ]]; then
            risk_level="HIGH"
            recommendation="Multiple file sharing services enabled. Review necessity and ensure proper access controls"
        elif [[ " ${enabled_services[*]} " =~ " FTP " ]]; then
            risk_level="HIGH"
            recommendation="FTP file sharing is insecure. Use SFTP or other secure alternatives"
        else
            risk_level="MEDIUM"
            recommendation="File sharing enabled. Ensure proper authentication and network restrictions"
        fi
    else
        details="No active file sharing services detected (SMB, AFP, FTP, NFS all disabled)"
        risk_level="INFO"
        recommendation=""
    fi
    
    add_security_finding "Security" "File Sharing Services" "$file_sharing_enabled" "$details" "$risk_level" "$recommendation"
}

check_airdrop_status() {
    log_message "INFO" "Checking AirDrop status..." "SECURITY"
    
    local airdrop_status="Disabled"
    local details=""
    local risk_level="INFO"
    local recommendation=""
    
    # Check definitive AirDrop status via system preferences
    local discoverable_mode=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null)
    
    if [[ "$discoverable_mode" == "Off" || -z "$discoverable_mode" ]]; then
        airdrop_status="Disabled"
        details="AirDrop is disabled (DiscoverableMode: Off)"
        risk_level="INFO"
        recommendation=""
    elif [[ "$discoverable_mode" == "Contacts Only" ]]; then
        airdrop_status="Enabled (Contacts Only)"
        details="AirDrop is enabled with contacts-only restriction (DiscoverableMode: $discoverable_mode)"
        risk_level="LOW"
        recommendation="AirDrop is configured securely for contacts only. Consider disabling completely if not needed for business"
    elif [[ "$discoverable_mode" == "Everyone" ]]; then
        airdrop_status="Enabled (Everyone)"
        details="AirDrop is enabled for everyone (DiscoverableMode: $discoverable_mode)"
        risk_level="HIGH"
        recommendation="AirDrop is configured to accept from everyone. Change to 'Contacts Only' or disable in System Settings > General > AirDrop"
    else
        airdrop_status="Enabled"
        details="AirDrop is enabled (DiscoverableMode: $discoverable_mode)"
        risk_level="MEDIUM"
        recommendation="Review AirDrop configuration in System Settings > General > AirDrop"
    fi
    
    add_security_finding "Security" "AirDrop Status" "$airdrop_status" "$details" "$risk_level" "$recommendation"
}

check_rmm_agents() {
    log_message "INFO" "Checking for RMM agents..." "SECURITY"
    
    local rmm_found=()
    local rmm_processes=""
    local rmm_apps=""
    
    # Common RMM agent process names and signatures (matching Windows detection)
    local rmm_patterns=(
        "kaseya"
        "agentmon"
        "n-able"
        "ninja.*rmm"
        "ninja.*one"
        "ninja.*agent"
        "datto.*rmm"
        "centrastage"
        "autotask"
        "atera.*agent"
        "continuum.*agent"
        "labtech"
        "ltservice"
        "connectwise.*automate"
        "solar.*winds.*rmm"
        "n-central"
        "syncro.*agent"
        "repairshopr"
        "pulseway"
        "manageengine"
        "desktop.*central"
        "auvik"
        "prtg"
        "whatsup.*gold"
        "crowdstrike"
        "falcon.*sensor"
        "sentinelone"
        "sentinel.*agent"
        "huntress"
        "bitdefender.*gravity"
        "gravityzone"
        "logmein.*central"
        "gotoassist.*corporate"
        "bomgar"
        "beyondtrust.*remote"
    )
    
    # Check running processes for RMM signatures
    for pattern in "${rmm_patterns[@]}"; do
        if ps -eo comm | grep -qi "$pattern"; then
            local found_processes=$(ps -eo comm | grep -i "$pattern" | sort -u | tr '\n' ',' | sed 's/,$//')
            if [[ -n "$found_processes" ]]; then
                rmm_found+=("$found_processes")
            fi
        fi
    done
    
    # Check installed applications for RMM agent platforms (matching Windows detection)
    local app_paths=(
        "/Applications/Kaseya Agent.app"
        "/Applications/N-able Agent.app"
        "/Applications/Datto RMM.app"
        "/Applications/NinjaRMM.app"
        "/Applications/NinjaOne.app"
        "/Applications/Atera Agent.app"
        "/Applications/ConnectWise Automate.app"
        "/Applications/Syncro.app"
        "/Applications/Pulseway.app"
        "/Applications/ManageEngine Desktop Central.app"
        "/Applications/Auvik.app"
        "/Applications/PRTG.app"
        "/Applications/CrowdStrike Falcon.app"
        "/Applications/SentinelOne.app"
        "/Applications/Huntress.app"
        "/Applications/Bitdefender GravityZone.app"
        "/Applications/LogMeIn Central.app"
        "/Applications/BeyondTrust.app"
        "/Library/Application Support/Kaseya"
        "/Library/Application Support/N-able"
        "/Library/Application Support/Datto"
        "/Library/Application Support/NinjaRMM"
        "/Library/Application Support/NinjaOne"
        "/Library/Application Support/Atera"
        "/Library/Application Support/ConnectWise"
        "/Library/Application Support/Syncro"
        "/Library/Application Support/Pulseway"
        "/Library/Application Support/ManageEngine"
        "/Library/Application Support/CrowdStrike"
        "/Library/Application Support/SentinelOne"
        "/Library/Application Support/Huntress"
        "/Library/Application Support/Bitdefender"
        "/usr/local/bin/kaseya"
        "/usr/local/bin/ninja"
        "/usr/local/bin/crowdstrike"
        "/opt/kaseya"
        "/opt/n-able"
        "/opt/datto"
        "/opt/ninja"
        "/opt/crowdstrike"
        "/opt/sentinelone"
    )
    
    for app_path in "${app_paths[@]}"; do
        if [[ -e "$app_path" ]]; then
            local app_name=$(basename "$app_path" .app)
            rmm_found+=("$app_name")
        fi
    done
    
    # Report findings
    if [[ ${#rmm_found[@]} -gt 0 ]]; then
        local rmm_list=$(printf '%s,' "${rmm_found[@]}" | sed 's/,$//')
        local rmm_count=${#rmm_found[@]}
        
        if [[ $rmm_count -gt 2 ]]; then
            local risk_level="HIGH"
            local recommendation="Multiple RMM agents detected. Review all remote access tools for security and business justification. Remove unauthorized tools immediately."
        else
            local risk_level="MEDIUM"
            local recommendation="RMM agents detected. Verify these tools are authorized and properly secured with strong authentication."
        fi
        
        add_security_finding "Security" "RMM Agents" "$rmm_count agents" "Found: $rmm_list" "$risk_level" "$recommendation"
    else
        add_security_finding "Security" "RMM Agents" "None Detected" "No remote monitoring/management agents found" "INFO" ""
    fi
}

check_backup_solutions() {
    log_message "INFO" "Checking backup solutions..." "SECURITY"
    
    local backup_found=()
    local backup_services=""
    
    # Common backup solution patterns for macOS
    local backup_apps=(
        "/Applications/Time Machine.app"
        "/Applications/Backblaze.app"
        "/Applications/Carbonite.app"
        "/Applications/CrashPlan.app"
        "/Applications/Arq.app"
        "/Applications/ChronoSync.app"
        "/Applications/SuperDuper!.app"
        "/Applications/Carbon Copy Cloner.app"
        "/Applications/Get Backup Pro.app"
        "/Applications/Acronis True Image.app"
        "/Applications/iCloud.app"
        "/System/Library/CoreServices/Applications/Backup and Restore.app"
    )
    
    # Check installed backup applications
    for app_path in "${backup_apps[@]}"; do
        if [[ -e "$app_path" ]]; then
            local app_name=$(basename "$app_path" .app)
            backup_found+=("$app_name")
        fi
    done
    
    # Check for running backup processes
    local backup_processes=(
        "backupd"
        "tmutil"
        "bzagent"
        "carbonite"
        "crashplan"
        "arq"
        "chronosync"
        "ccc"
        "acronis"
    )
    
    for process in "${backup_processes[@]}"; do
        if pgrep -x "$process" >/dev/null 2>&1; then
            backup_found+=("$process (running)")
        fi
    done
    
    # Check Time Machine status specifically
    if command -v tmutil >/dev/null 2>&1; then
        # Check if Time Machine is configured by looking for destination
        local tm_destination=$(tmutil destinationinfo 2>/dev/null)
        
        if [[ -n "$tm_destination" ]]; then
            # Check if Time Machine is currently running a backup
            local tm_running=$(tmutil status 2>/dev/null | grep -E "Running.*[^0]" 2>/dev/null)
            if [[ -n "$tm_running" ]]; then
                backup_found+=("Time Machine (backup in progress)")
            fi
            
            # Get detailed Time Machine backup information
            local latest_backup=$(tmutil latestbackup 2>/dev/null)
            local backup_count=0
            local listbackups_output=$(tmutil listbackups 2>&1)
            
            # Check if we have actual backups (not just an error message)
            if [[ "$listbackups_output" != *"No machine directory found"* ]] && [[ -n "$listbackups_output" ]]; then
                backup_count=$(echo "$listbackups_output" | wc -l | tr -d ' ')
            fi
            
            if [[ $backup_count -gt 0 && -n "$latest_backup" && "$latest_backup" != "No backup found" ]]; then
                # We have completed backups
                backup_found+=("Time Machine (active)")
                
                # Extract date from backup path (format: /Volumes/BackupDisk/Backups.backupdb/MacName/YYYY-MM-DD-HHMMSS)
                local backup_date=$(basename "$latest_backup" | sed 's/-.*//')
                if [[ "$backup_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
                    # Convert date format for better readability
                    local formatted_date=$(date -j -f "%Y-%m-%d" "$backup_date" "+%B %d, %Y" 2>/dev/null || echo "$backup_date")
                    add_security_finding "System" "Time Machine Backups" "$backup_count backups" "Latest: $formatted_date" "INFO" "Regular backups detected - verify backup integrity periodically"
                else
                    add_security_finding "System" "Time Machine Backups" "$backup_count backups" "Latest backup path: $latest_backup" "INFO" "Regular backups detected - verify backup integrity periodically"
                fi
            else
                # Time Machine is configured but no backups completed yet
                add_security_finding "System" "Time Machine Backups" "Configured" "No backups completed yet" "LOW" "Time Machine is configured but no backups have completed. Verify backup destination is accessible"
            fi
        fi
    fi
    
    # Report findings
    if [[ ${#backup_found[@]} -gt 0 ]]; then
        local backup_list=$(printf '%s,' "${backup_found[@]}" | sed 's/,$//')
        local backup_count=${#backup_found[@]}
        
        add_security_finding "System" "Backup Solutions" "$backup_count solutions" "Found: $backup_list" "INFO" "Backup solutions detected - verify they are configured and running properly"
    else
        add_security_finding "System" "Backup Solutions" "None Detected" "No backup solutions found" "MEDIUM" "Consider implementing a backup solution to protect against data loss"
    fi
}

check_managed_login() {
    log_message "INFO" "Checking managed login providers..." "SECURITY"
    
    local managed_login_found=()
    local login_type="Standard"
    
    # Check for Jamf Connect
    if [[ -e "/Applications/Jamf Connect.app" ]] || [[ -e "/usr/local/bin/jamf" ]]; then
        managed_login_found+=("Jamf Connect")
    fi
    
    # Check for NoMAD/Kandji login
    if [[ -e "/Applications/NoMAD.app" ]] || [[ -e "/Library/Application Support/Kandji" ]]; then
        managed_login_found+=("NoMAD/Kandji")
    fi
    
    # Check for Platform SSO (Entra ID integration)
    if defaults read com.apple.extensiond 2>/dev/null | grep -q "com.microsoft.CompanyPortal.ssoextension"; then
        managed_login_found+=("Microsoft Platform SSO")
    fi

    # Report managed login findings
    if [[ ${#managed_login_found[@]} -gt 0 ]]; then
        local managed_list=$(printf '%s,' "${managed_login_found[@]}" | sed 's/,$//')
        login_type="Managed"

        add_security_finding "Authentication" "Login Management" "$login_type" "Managed providers: $managed_list" "INFO" ""
    else
        add_security_finding "Authentication" "Login Management" "$login_type" "No managed login providers detected - using standard macOS authentication" "INFO" ""
    fi
}

check_icloud_status() {
    log_message "INFO" "Checking iCloud status..." "SECURITY"

    # Check if user is signed into iCloud using accurate AccountID detection
    # Handle sudo case - need to read from actual user's preferences, not root's
    local actual_user="${SUDO_USER:-$(whoami)}"
    local user_home=$(eval echo "~$actual_user")
    local icloud_data

    if [[ "$EUID" -eq 0 && -n "$SUDO_USER" ]]; then
        # Running as sudo - read from the actual user's preferences
        icloud_data=$(sudo -u "$SUDO_USER" defaults read MobileMeAccounts Accounts 2>/dev/null)
    else
        # Normal user execution
        icloud_data=$(defaults read MobileMeAccounts Accounts 2>/dev/null)
    fi
    local icloud_account_id=$(echo "$icloud_data" | grep "AccountID" | cut -d'"' -f2)

    # DEBUG OUTPUT

    if [[ -n "$icloud_account_id" ]]; then
        # User is signed into iCloud - extract actual email
        add_security_finding "Security" "iCloud Status" "Signed In" "Account: $icloud_account_id" "INFO" ""

        # Check iCloud backup status - look for actual service data
        local backup_enabled=$(echo "$icloud_data" | grep -A 5 "MOBILE_DOCUMENTS" | grep "Enabled = 1")
        if [[ -n "$backup_enabled" ]]; then
            add_security_finding "Security" "iCloud Backup" "Enabled" "iCloud Drive and backup services active" "INFO" ""
        else
            add_security_finding "Security" "iCloud Backup" "Disabled" "iCloud backup services not active" "INFO" ""
        fi
    else
        # User not signed into iCloud
        add_security_finding "Security" "iCloud Status" "Not Signed In" "No iCloud account configured" "LOW" "Consider signing into iCloud for backup and device synchronization"
        add_security_finding "Security" "iCloud Backup" "Not Available" "Cannot backup without iCloud account" "LOW" "Sign into iCloud and enable backup for data protection"
    fi
}

check_find_my_status() {
    log_message "INFO" "Checking Find My status..." "SECURITY"

    # Check Find My Mac status using accurate service detection
    local actual_user="${SUDO_USER:-$(whoami)}"
    local icloud_data

    if [[ "$EUID" -eq 0 && -n "$SUDO_USER" ]]; then
        icloud_data=$(sudo -u "$SUDO_USER" defaults read MobileMeAccounts Accounts 2>/dev/null)
    else
        icloud_data=$(defaults read MobileMeAccounts Accounts 2>/dev/null)
    fi

    local find_my_service=$(echo "$icloud_data" | grep -A 8 "FIND_MY_MAC")


    if [[ -n "$find_my_service" ]]; then
        # Check if Find My service is properly configured (has authentication and hostnames)
        local find_my_hostname=$(echo "$find_my_service" | grep "hostname")
        local find_my_auth=$(echo "$find_my_service" | grep "authMechanism")


        if [[ -n "$find_my_hostname" && -n "$find_my_auth" ]]; then
            add_security_finding "Security" "Find My" "Enabled" "Find My Mac service is active and configured in iCloud account" "INFO" ""
        else
            add_security_finding "Security" "Find My" "Partially Configured" "Find My Mac service present but incomplete configuration" "LOW" "Complete Find My setup in System Preferences > Apple ID > iCloud"
        fi
    else
        # No iCloud account or Find My service not configured
        local icloud_account_id=$(echo "$icloud_data" | grep "AccountID")
        if [[ -n "$icloud_account_id" ]]; then
            add_security_finding "Security" "Find My" "Not Configured" "iCloud account present but Find My not set up" "LOW" "Enable Find My for device security and theft protection"
        else
            add_security_finding "Security" "Find My" "Not Available" "Requires iCloud account" "LOW" "Sign into iCloud to enable Find My"
        fi
    fi
}

check_screen_sharing_settings() {
    log_message "INFO" "Checking screen sharing settings..." "SECURITY"

    # Check if Screen Sharing is enabled
    local screen_sharing_enabled=false

    # Check system preferences
    local ssh_enabled=$(systemsetup -getremotelogin 2>/dev/null | grep -c "On")
    local vnc_enabled=$(ps aux | grep -c "[S]creenSharingAgent")

    if [[ "$vnc_enabled" -gt 0 ]]; then
        screen_sharing_enabled=true
        add_security_finding "Security" "Screen Sharing" "Enabled" "VNC/Screen Sharing is active" "MEDIUM" "Screen sharing enabled - ensure strong passwords and network access controls"
    else
        add_security_finding "Security" "Screen Sharing" "Disabled" "Screen sharing services not active" "INFO" ""
    fi
}

# Function to get findings for report generation
get_security_findings() {
    printf '%s\n' "${SECURITY_FINDINGS[@]}"
}


# [SECURITY] get_user_account_analysis - User account analysis for macOS
# Order: 122
#!/bin/bash

# macOSWorkstationAuditor - User Account Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a USER_FINDINGS=()

get_user_account_analysis_data() {
    log_message "INFO" "Analyzing user accounts..." "USERS"
    
    # Initialize findings array
    USER_FINDINGS=()
    
    # Analyze local user accounts
    analyze_local_users
    
    # Check administrator accounts
    check_administrator_accounts
    
    # Check for disabled accounts
    check_disabled_accounts
    
    # Check password policies
    check_password_policies
    
    # Check login items
    check_login_items
    
    # Check user groups
    check_user_groups
    
    log_message "SUCCESS" "User account analysis completed - ${#USER_FINDINGS[@]} findings" "USERS"
}

analyze_local_users() {
    log_message "INFO" "Analyzing local user accounts..." "USERS"
    
    # Get list of all local users (UID >= 500, excluding system accounts)
    local all_users=$(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | grep -v "^_")
    local user_count=$(echo "$all_users" | wc -l | tr -d ' ')
    
    if [[ -z "$all_users" ]]; then
        user_count=0
    fi
    
    # Analyze user accounts and categorize
    local active_users=0
    local admin_users=0
    local standard_users=0
    local admin_user_list=()
    local risky_users=()
    
    while IFS= read -r username; do
        if [[ -n "$username" ]]; then
            # Check if user is active (has a home directory)
            if [[ -d "/Users/$username" ]]; then
                ((active_users++))
            fi
            
            # Check if user is admin and categorize
            if dseditgroup -o checkmember -m "$username" admin 2>/dev/null | grep -q "yes"; then
                ((admin_users++))
                admin_user_list+=("$username")
            else
                ((standard_users++))
            fi
            
            # Only report individual users if there are issues/risks
            local user_issues=$(check_user_for_issues "$username")
            if [[ -n "$user_issues" ]]; then
                analyze_single_user "$username"
                risky_users+=("$username")
            fi
        fi
    done <<< "$all_users"
    
    # Create concise user summary
    local user_summary=""
    local admin_list=$(IFS=", "; echo "${admin_user_list[*]}")
    
    if [[ $user_count -eq 1 && $admin_users -eq 1 ]]; then
        user_summary="Single administrator account ($admin_list)"
    elif [[ $admin_users -gt 0 && $standard_users -gt 0 ]]; then
        user_summary="$admin_users administrator(s), $standard_users standard user(s)"
    elif [[ $admin_users -gt 0 ]]; then
        user_summary="$admin_users administrator account(s) only"
    else
        user_summary="$standard_users standard user(s) only"
    fi
    
    add_user_finding "Users" "User Accounts" "$user_count total" "$user_summary" "INFO" ""
}

# Function to check if a user has issues worth individual reporting
check_user_for_issues() {
    local username="$1"
    local issues=""
    
    # Check for disabled account
    local account_policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null)
    if echo "$account_policy" | grep -q "isDisabled=1"; then
        issues="disabled"
    fi
    
    # Check for passwordless account
    local password_hash=$(dscl . read "/Users/$username" AuthenticationAuthority 2>/dev/null)
    if [[ -z "$password_hash" ]] || echo "$password_hash" | grep -q "No such key"; then
        issues="${issues:+$issues,}passwordless"
    fi
    
    # Check for unusual shell
    local shell=$(dscl . read "/Users/$username" UserShell 2>/dev/null | awk '{print $2}')
    case "$shell" in
        "/bin/bash"|"/bin/zsh"|"/bin/sh"|"/usr/bin/false"|"/sbin/nologin")
            # Normal shells - no issue
            ;;
        *)
            issues="${issues:+$issues,}unusual_shell"
            ;;
    esac
    
    echo "$issues"
}

analyze_single_user() {
    local username="$1"
    
    # Get user information
    local real_name=$(dscl . read "/Users/$username" RealName 2>/dev/null | grep -v "RealName:" | sed 's/^ *//' | head -1)
    local uid=$(dscl . read "/Users/$username" UniqueID 2>/dev/null | awk '{print $2}')
    local shell=$(dscl . read "/Users/$username" UserShell 2>/dev/null | awk '{print $2}')
    local home_dir=$(dscl . read "/Users/$username" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    
    # Check last login (simplified)
    local last_login="Unknown"
    if [[ -f "/var/log/wtmp" ]]; then
        last_login=$(last -1 "$username" 2>/dev/null | head -1 | awk '{print $3, $4, $5, $6}' || echo "Unknown")
    fi
    
    # Check if account is locked/disabled
    local account_status="Active"
    local account_policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null)
    if echo "$account_policy" | grep -q "isDisabled=1"; then
        account_status="Disabled"
    fi
    
    # Determine risk level based on various factors
    local risk_level="INFO"
    local recommendation=""
    
    # Check for risky shells
    case "$shell" in
        "/bin/bash"|"/bin/zsh"|"/bin/sh")
            # Normal shells
            ;;
        "/usr/bin/false"|"/sbin/nologin")
            account_status="No Shell Login"
            ;;
        *)
            risk_level="LOW"
            recommendation="Unusual shell detected: $shell"
            ;;
    esac
    
    local details="UID: $uid, Shell: $shell, Last Login: $last_login"
    if [[ -n "$real_name" ]]; then
        details="Real Name: $real_name, $details"
    fi
    
    add_user_finding "Users" "User: $username" "$account_status" "$details" "$risk_level" "$recommendation"
}

check_administrator_accounts() {
    log_message "INFO" "Checking administrator accounts..." "USERS"
    
    # Get list of admin users - try multiple methods for compatibility
    local admin_users=""
    local admin_count=0
    local risky_admins=()
    
    # Method 1: Try dscl (most reliable and consistent)
    if command -v dscl >/dev/null 2>&1; then
        admin_users=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' | tr ' ' '\n' | grep -v "^$" | grep -v "^root$" | grep -v "^_mbsetupuser$" | grep -v "^_" | sort -u)
    fi
    
    # Method 2: If that fails, try dseditgroup (alternative approach)
    if [[ -z "$admin_users" ]] && command -v dseditgroup >/dev/null 2>&1; then
        admin_users=$(dseditgroup -o read admin 2>/dev/null | grep -A 20 "GroupMembership -" | grep "^[[:space:]]*[a-zA-Z][a-zA-Z0-9_]*$" | sed 's/^[[:space:]]*//' | sort -u)
    fi
    
    # Method 3: If still nothing, try checking who's in wheel group
    if [[ -z "$admin_users" ]]; then
        admin_users=$(dscl . -read /Groups/wheel GroupMembership 2>/dev/null | grep -v "GroupMembership:" | tr ' ' '\n' | grep -v "^$" | sort -u)
    fi
    
    # Count admin users and check for issues
    if [[ -n "$admin_users" ]]; then
        while IFS= read -r admin_user; do
            if [[ -n "$admin_user" ]]; then
                ((admin_count++))
                
                # Check for default/generic admin accounts
                case "$admin_user" in
                    "admin"|"administrator"|"root"|"test"|"guest")
                        risky_admins+=("$admin_user")
                        ;;
                esac
            fi
        done <<< "$admin_users"
    fi
    
    # Only report admin accounts if there are issues or concerns
    local should_report=false
    local risk_level="INFO"
    local recommendation=""
    local admin_details=""
    
    if [[ $admin_count -eq 0 ]]; then
        should_report=true
        risk_level="HIGH"
        recommendation="No administrator accounts found. This may indicate a configuration issue"
        admin_details="No administrator accounts found"
    elif [[ $admin_count -gt 5 ]]; then
        should_report=true
        risk_level="MEDIUM"
        recommendation="Large number of administrator accounts. Review and remove unnecessary admin privileges"
        local admin_list=$(echo "$admin_users" | tr '\n' ', ' | sed 's/, $//')
        admin_details="$admin_count admin accounts: $admin_list"
    elif [[ ${#risky_admins[@]} -gt 0 ]]; then
        should_report=true
        risk_level="HIGH"
        local risky_list=$(IFS=", "; echo "${risky_admins[*]}")
        recommendation="Generic/default admin accounts detected: $risky_list. Rename or disable these accounts"
        admin_details="Risky admin accounts found: $risky_list"
    fi
    
    # Report only if there are issues
    if [[ "$should_report" == true ]]; then
        add_user_finding "Security" "Administrator Account Issues" "$admin_count accounts" "$admin_details" "$risk_level" "$recommendation"
    fi
    
    # Check root account status - it should be disabled by default
    local root_auth=$(dscl . read /Users/root AuthenticationAuthority 2>/dev/null)
    if [[ -n "$root_auth" && ! "$root_auth" =~ ";DisabledUser;" ]]; then
        add_user_finding "Security" "Root Account" "Enabled" "System root account is active" "MEDIUM" "Consider disabling root account if not needed"
    fi
}

check_disabled_accounts() {
    log_message "INFO" "Checking for disabled accounts..." "USERS"
    
    local disabled_count=0
    local disabled_users=()
    local all_users=$(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | grep -v "^_")
    
    while IFS= read -r username; do
        if [[ -n "$username" ]]; then
            local account_policy=$(pwpolicy -u "$username" -getpolicy 2>/dev/null)
            if echo "$account_policy" | grep -q "isDisabled=1"; then
                ((disabled_count++))
                disabled_users+=("$username")
            fi
        fi
    done <<< "$all_users"
    
    # Only report if there are disabled accounts
    if [[ $disabled_count -gt 0 ]]; then
        local disabled_list=$(IFS=", "; echo "${disabled_users[*]}")
        add_user_finding "Security" "Disabled Accounts" "$disabled_count accounts" "Disabled users: $disabled_list" "LOW" "Review disabled accounts and remove if no longer needed"
    fi
}

check_password_policies() {
    log_message "INFO" "Checking password policies..." "USERS"
    
    # Check global password policy
    local global_policy=$(pwpolicy -getglobalpolicy 2>/dev/null)
    
    # Extract key policy settings
    local min_length="Unknown"
    local complexity="Unknown"
    local max_age="Unknown"
    local history="Unknown"
    
    if [[ -n "$global_policy" ]]; then
        min_length=$(echo "$global_policy" | grep "minChars=" | sed 's/.*minChars=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$min_length" ]] && min_length="Unknown"
        complexity=$(echo "$global_policy" | grep "requiresAlpha=" | sed 's/.*requiresAlpha=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$complexity" ]] && complexity="Unknown"
        max_age=$(echo "$global_policy" | grep "maxMinutesUntilChangePassword=" | sed 's/.*maxMinutesUntilChangePassword=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$max_age" ]] && max_age="Unknown"
        history=$(echo "$global_policy" | grep "usingHistory=" | sed 's/.*usingHistory=//' | sed 's/[^0-9].*//' | head -1 | tr -d '\n\r ' || echo "Unknown")
        [[ -z "$history" ]] && history="Unknown"
    fi
    
    # Assess password policy strength
    local policy_strength="Unknown"
    local risk_level="INFO"
    local recommendation=""
    
    # Ensure min_length is clean and numeric
    min_length=$(echo "$min_length" | tr -d '\n\r ' | sed 's/[^0-9]//g')
    if [[ -z "$min_length" ]]; then
        min_length="0"
    fi
    
    if [[ "$min_length" =~ ^[0-9]+$ && "$min_length" -ge 8 ]]; then
        policy_strength="Adequate"
    elif [[ "$min_length" =~ ^[0-9]+$ && "$min_length" -lt 8 && "$min_length" -gt 0 ]]; then
        policy_strength="Weak"
        risk_level="MEDIUM"
        recommendation="Password minimum length is less than 8 characters. Increase to at least 8-12 characters"
    else
        policy_strength="Not Configured"
        risk_level="LOW"
        recommendation="Password policy not configured. Consider implementing password complexity requirements"
    fi
    
    local policy_details="Min Length: $min_length, Complexity: $complexity, Max Age: $max_age days, History: $history"
    add_user_finding "Security" "Password Policy" "$policy_strength" "$policy_details" "$risk_level" "$recommendation"
    
    # Check for accounts without passwords (security risk)
    check_passwordless_accounts
}

check_passwordless_accounts() {
    log_message "INFO" "Checking for passwordless accounts..." "USERS"
    
    local passwordless_count=0
    local passwordless_users=()
    local all_users=$(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}' | grep -v "^_")
    
    while IFS= read -r username; do
        if [[ -n "$username" ]]; then
            # Check if user has a password hash
            local password_hash=$(dscl . read "/Users/$username" AuthenticationAuthority 2>/dev/null)
            if [[ -z "$password_hash" ]] || echo "$password_hash" | grep -q "No such key"; then
                ((passwordless_count++))
                passwordless_users+=("$username")
            fi
        fi
    done <<< "$all_users"
    
    # Ensure passwordless_count is a valid integer
    if ! [[ "$passwordless_count" =~ ^[0-9]+$ ]]; then
        passwordless_count=0
    fi
    
    # Only report if there are passwordless accounts (HIGH risk)
    if [[ $passwordless_count -gt 0 ]]; then
        local user_list=$(IFS=", "; echo "${passwordless_users[*]}")
        add_user_finding "Security" "Passwordless Accounts" "$passwordless_count accounts" "Passwordless users: $user_list" "HIGH" "Set passwords for all user accounts to prevent unauthorized access"
    fi
}

check_login_items() {
    log_message "INFO" "Checking login items..." "USERS"
    
    # Check system-wide login items
    local system_login_items=0
    if [[ -f "/Library/Preferences/loginwindow.plist" ]]; then
        system_login_items=$(defaults read /Library/Preferences/loginwindow AutoLaunchedApplicationDictionary 2>/dev/null | grep -c "Path =" || echo 0)
    fi
    
    if [[ $system_login_items -gt 0 ]]; then
        add_user_finding "System" "System Login Items" "$system_login_items items" "Applications launched at system startup" "LOW" "Review system login items for security and performance"
    fi
    
    # Check current user's login items
    local user_login_items=0
    if [[ -f "$HOME/Library/Preferences/loginwindow.plist" ]]; then
        user_login_items=$(defaults read "$HOME/Library/Preferences/loginwindow" AutoLaunchedApplicationDictionary 2>/dev/null | grep -c "Path =" 2>/dev/null)
        if [[ -z "$user_login_items" ]]; then
            user_login_items=0
        fi
        user_login_items=$(echo "$user_login_items" | tr -d '[:space:]')
        # Ensure it's a valid number
        if ! [[ "$user_login_items" =~ ^[0-9]+$ ]]; then
            user_login_items=0
        fi
    fi
    
    if [[ $user_login_items -gt 0 ]]; then
        add_user_finding "Users" "User Login Items" "$user_login_items items" "Applications launched at user login" "INFO" ""
    fi
    
    # Check LaunchAgents and LaunchDaemons with better categorization
    local system_launch_agents=$(find /System/Library/LaunchAgents -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local user_launch_agents=$(find /Library/LaunchAgents ~/Library/LaunchAgents -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local total_launch_agents=$((system_launch_agents + user_launch_agents))
    
    local system_launch_daemons=$(find /System/Library/LaunchDaemons -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local user_launch_daemons=$(find /Library/LaunchDaemons -name "*.plist" 2>/dev/null | wc -l | tr -d ' ')
    local total_launch_daemons=$((system_launch_daemons + user_launch_daemons))
    
    # Get count of actually loaded launch items
    local loaded_items=$(launchctl list 2>/dev/null | wc -l | tr -d ' ')
    # Subtract header line
    if [[ $loaded_items -gt 0 ]]; then
        loaded_items=$((loaded_items - 1))
    fi
    
    # Report with better context
    local agents_details="Total: $total_launch_agents (System: $system_launch_agents, User: $user_launch_agents)"
    local daemons_details="Total: $total_launch_daemons (System: $system_launch_daemons, User: $user_launch_daemons)"
    local loaded_details="Active background processes currently loaded"
    
    # Risk assessment for user-installed items
    local agents_risk="INFO"
    local agents_recommendation=""
    if [[ $user_launch_agents -gt 10 ]]; then
        agents_risk="LOW"
        agents_recommendation="Review user-installed launch agents for unnecessary or suspicious items"
    fi
    
    local daemons_risk="INFO"
    local daemons_recommendation=""
    if [[ $user_launch_daemons -gt 5 ]]; then
        daemons_risk="LOW"
        daemons_recommendation="Review user-installed launch daemons for unnecessary or suspicious items"
    fi
    
    add_user_finding "System" "Launch Agents" "$total_launch_agents items" "$agents_details" "$agents_risk" "$agents_recommendation"
    add_user_finding "System" "Launch Daemons" "$total_launch_daemons items" "$daemons_details" "$daemons_risk" "$daemons_recommendation"
    add_user_finding "System" "Active Launch Items" "$loaded_items loaded" "$loaded_details" "INFO" ""
}

check_user_groups() {
    log_message "INFO" "Checking user group memberships..." "USERS"
    
    # Check for users in sensitive groups
    local sensitive_groups=("admin" "wheel" "_developer" "com.apple.access_ssh")
    
    for group in "${sensitive_groups[@]}"; do
        local group_member_list=$(dseditgroup -o read "$group" 2>/dev/null | grep -E "users:|GroupMembership:" | sed 's/.*: //' | tr ' ' '\n' | grep -v "^$")
        local group_members=$(echo "$group_member_list" | wc -l | tr -d ' ')
        
        # Handle empty group case
        if [[ -z "$group_member_list" ]]; then
            group_members=0
        fi
        
        if [[ $group_members -gt 0 ]]; then
            local risk_level="INFO"
            local recommendation=""
            
            case "$group" in
                "admin"|"wheel")
                    if [[ $group_members -gt 3 ]]; then
                        risk_level="LOW"
                        recommendation="Large number of users in $group group. Review membership"
                    fi
                    ;;
                "_developer")
                    risk_level="LOW"
                    recommendation="Developer group membership detected. Ensure users require development access"
                    ;;
                "com.apple.access_ssh")
                    risk_level="MEDIUM"
                    recommendation="SSH access group detected. Review SSH access requirements"
                    ;;
            esac
            
            # Create member list for details
            local member_names=$(echo "$group_member_list" | tr '\n' ', ' | sed 's/, $//')
            local group_details="Members: $member_names"
            
            add_user_finding "Security" "Group: $group" "$group_members members" "$group_details" "$risk_level" "$recommendation"
        fi
    done
}

# Helper function to add user findings to the array
add_user_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    USER_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to get findings for report generation
get_user_findings() {
    printf '%s\n' "${USER_FINDINGS[@]}"
}

# [NETWORK] get_network_analysis - Network configuration analysis for macOS
# Order: 130
#!/bin/bash

# macOSWorkstationAuditor - Network Analysis Module
# Version 1.0.0

# Global variables for collecting data
declare -a NETWORK_FINDINGS=()

# Helper function to convert hex netmask to dotted decimal format
hex_to_netmask() {
    local hex_mask="$1"
    # Remove 0x prefix
    hex_mask=${hex_mask#0x}
    
    # Convert to decimal and then to dotted decimal notation
    local decimal=$((16#$hex_mask))
    local octet1=$(( (decimal >> 24) & 255 ))
    local octet2=$(( (decimal >> 16) & 255 ))
    local octet3=$(( (decimal >> 8) & 255 ))
    local octet4=$(( decimal & 255 ))
    
    echo "${octet1}.${octet2}.${octet3}.${octet4}"
}

get_network_analysis_data() {
    log_message "INFO" "Analyzing network configuration..." "NETWORK"
    
    # Initialize findings array
    NETWORK_FINDINGS=()
    
    # Check network interfaces
    check_network_interfaces
    
    # Check WiFi configuration
    check_wifi_configuration
    
    # Check DNS settings
    check_dns_configuration
    
    # Check active network connections
    check_network_connections
    
    # Check network sharing services
    check_network_sharing
    
    # Check VPN connections
    check_vpn_connections
    
    log_message "SUCCESS" "Network analysis completed - ${#NETWORK_FINDINGS[@]} findings" "NETWORK"
}

check_network_interfaces() {
    log_message "INFO" "Checking network interfaces..." "NETWORK"
    
    # Get network interface information
    local interfaces=$(networksetup -listallhardwareports 2>/dev/null)
    local active_interfaces=0
    local ethernet_found=false
    local wifi_found=false
    
    # Count active network interfaces and determine connection types
    while IFS= read -r line; do
        if echo "$line" | grep -q "Hardware Port:"; then
            local port_name="$line"
        elif echo "$line" | grep -q "Device:"; then
            local device=$(echo "$line" | awk '{print $2}')
            if ifconfig "$device" 2>/dev/null | grep -q "status: active"; then
                ((active_interfaces++))
                # Determine connection type based on port name and device type
                if echo "$port_name" | grep -qi "ethernet\|usb.*ethernet\|thunderbolt.*ethernet"; then
                    ethernet_found=true
                elif echo "$port_name" | grep -qi "wi-fi\|airport\|wireless"; then
                    wifi_found=true
                else
                    # For ambiguous cases, check the device name pattern and ifconfig output
                    case "$device" in
                        "en0")
                            # en0 is typically Wi-Fi on modern Macs, but check ifconfig for media type
                            if ifconfig "$device" 2>/dev/null | grep -q "media.*Ethernet"; then
                                ethernet_found=true
                            else
                                wifi_found=true
                            fi
                            ;;
                        "en"[1-9]|"en"[1-9][0-9])
                            # en1+ are typically Ethernet adapters
                            ethernet_found=true
                            ;;
                        *)
                            # For other devices, check ifconfig output for clues
                            if ifconfig "$device" 2>/dev/null | grep -q "media.*Ethernet"; then
                                ethernet_found=true
                            elif ifconfig "$device" 2>/dev/null | grep -q "media.*autoselect"; then
                                wifi_found=true
                            fi
                            ;;
                    esac
                fi
            fi
        fi
    done <<< "$interfaces"
    
    # Report interface status
    local interface_details=""
    if [[ "$ethernet_found" == true && "$wifi_found" == true ]]; then
        interface_details="Both Ethernet and Wi-Fi active"
    elif [[ "$ethernet_found" == true ]]; then
        interface_details="Ethernet connection active"
    elif [[ "$wifi_found" == true ]]; then
        interface_details="Wi-Fi connection active"
    else
        interface_details="Connection type unknown"
    fi
    
    add_network_finding "Network" "Active Interfaces" "$active_interfaces" "$interface_details" "INFO" ""
    
    # Get IP configuration for primary interface
    local primary_ip=$(route get default 2>/dev/null | grep interface | awk '{print $2}')
    if [[ -n "$primary_ip" ]]; then
        local ip_address=$(ifconfig "$primary_ip" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        local subnet_mask_hex=$(ifconfig "$primary_ip" 2>/dev/null | grep "inet " | awk '{print $4}' | head -1)
        
        # Convert hex netmask to dotted decimal format
        local subnet_mask="$subnet_mask_hex"
        if [[ "$subnet_mask_hex" =~ ^0x[0-9a-fA-F]+$ ]]; then
            subnet_mask=$(hex_to_netmask "$subnet_mask_hex")
        fi
        
        if [[ -n "$ip_address" ]]; then
            add_network_finding "Network" "Primary IP Address" "$ip_address" "Interface: $primary_ip, Mask: $subnet_mask" "INFO" ""
        fi
    fi
}

check_wifi_configuration() {
    log_message "INFO" "Checking Wi-Fi configuration..." "NETWORK"
    
    # Check if Wi-Fi is enabled
    local wifi_power=$(networksetup -getairportpower en0 2>/dev/null)
    local wifi_status="Unknown"
    
    if echo "$wifi_power" | grep -q "On"; then
        wifi_status="Enabled"
    elif echo "$wifi_power" | grep -q "Off"; then
        wifi_status="Disabled"
    fi
    
    add_network_finding "Network" "Wi-Fi Status" "$wifi_status" "Airport power status" "INFO" ""
    
    # Check current Wi-Fi network
    if [[ "$wifi_status" == "Enabled" ]]; then
        local current_ssid=$(networksetup -getairportnetwork en0 2>/dev/null | cut -d: -f2 | sed 's/^ *//')
        
        if [[ -n "$current_ssid" && "$current_ssid" != "You are not associated with an AirPort network." ]]; then
            # Check for open networks (security risk)
            local security_info=$(security find-generic-password -D "AirPort network password" -a "$current_ssid" -g 2>&1)
            local is_open=false
            
            if echo "$security_info" | grep -q "could not be found"; then
                is_open=true
            fi
            
            local risk_level="INFO"
            local recommendation=""
            
            if [[ "$is_open" == true ]]; then
                risk_level="HIGH"
                recommendation="Connected to open Wi-Fi network. Use VPN or avoid transmitting sensitive data"
            fi
            
            add_network_finding "Network" "Current Wi-Fi Network" "$current_ssid" "Currently connected SSID" "$risk_level" "$recommendation"
        fi
        
        # Check for saved networks (potential security exposure)
        local saved_networks=$(networksetup -listpreferredwirelessnetworks en0 2>/dev/null | grep -v "Preferred networks" | wc -l | tr -d ' ')
        
        local saved_risk="INFO"
        local saved_recommendation=""
        
        if [[ $saved_networks -gt 20 ]]; then
            saved_risk="LOW"
            saved_recommendation="Large number of saved Wi-Fi networks may pose security risk. Consider removing unused networks"
        fi
        
        add_network_finding "Network" "Saved Wi-Fi Networks" "$saved_networks networks" "Stored wireless network profiles" "$saved_risk" "$saved_recommendation"
    fi
}

check_dns_configuration() {
    log_message "INFO" "Checking DNS configuration..." "NETWORK"
    
    # Get DNS servers
    local dns_servers=$(scutil --dns 2>/dev/null | grep nameserver | awk '{print $3}' | sort -u | head -5)
    local dns_count=$(echo "$dns_servers" | wc -l | tr -d ' ')
    
    if [[ -n "$dns_servers" ]]; then
        local dns_list=$(echo "$dns_servers" | tr '\n' ', ' | sed 's/, $//')
        add_network_finding "Network" "DNS Servers" "$dns_count configured" "Servers: $dns_list" "INFO" ""
        
        # Check for common public DNS servers
        local public_dns=false
        while IFS= read -r dns; do
            case "$dns" in
                "8.8.8.8"|"8.8.4.4"|"1.1.1.1"|"1.0.0.1"|"208.67.222.222"|"208.67.220.220")
                    public_dns=true
                    break
                    ;;
            esac
        done <<< "$dns_servers"
        
        if [[ "$public_dns" == true ]]; then
            add_network_finding "Network" "Public DNS Detected" "Yes" "Using public DNS servers (Google, Cloudflare, etc.)" "LOW" "Consider using organization DNS servers for corporate networks"
        fi
    else
        add_network_finding "Network" "DNS Configuration" "Not Found" "Could not determine DNS configuration" "LOW" "Verify DNS settings are properly configured"
    fi
}

check_network_connections() {
    log_message "INFO" "Checking active network connections..." "NETWORK"
    
    # Check for listening services
    local listening_ports=$(netstat -an 2>/dev/null | grep LISTEN | wc -l | tr -d ' ')
    add_network_finding "Network" "Listening Services" "$listening_ports ports" "Services accepting network connections" "INFO" ""
    
    # Check for high-risk ports
    local risky_ports=("22" "23" "80" "443" "3389" "5900" "5901")
    local found_risky=()
    
    for port in "${risky_ports[@]}"; do
        if netstat -an 2>/dev/null | grep LISTEN | grep -q "\\.$port[ 	].*LISTEN"; then
            case "$port" in
                "22") found_risky+=("SSH ($port)") ;;
                "23") found_risky+=("Telnet ($port)") ;;
                "80") found_risky+=("HTTP ($port)") ;;
                "443") found_risky+=("HTTPS ($port)") ;;
                "3389") found_risky+=("RDP ($port)") ;;
                "5900"|"5901") found_risky+=("VNC ($port)") ;;
            esac
        fi
    done
    
    if [[ ${#found_risky[@]} -gt 0 ]]; then
        local risky_list=$(IFS=", "; echo "${found_risky[*]}")
        local risk_level="MEDIUM"
        local recommendation="Review listening services for security implications. Disable unnecessary services"
        
        add_network_finding "Security" "High-Risk Listening Ports" "${#found_risky[@]} detected" "Found: $risky_list" "$risk_level" "$recommendation"
    fi
    
    # Add specific port details for transparency
    add_specific_port_details
    
    # Check for established connections
    local established_connections=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
    add_network_finding "Network" "Established Connections" "$established_connections" "Active outbound network connections" "INFO" ""
}

check_network_sharing() {
    log_message "INFO" "Checking network sharing services..." "NETWORK"
    
    # Check common sharing services
    local sharing_services=(
        "Screen Sharing:ARDAgent"
        "File Sharing:AppleFileServer"
        "Remote Login:RemoteLogin"
        "Remote Management:ARDAgent"
        "Internet Sharing:InternetSharing"
        "Bluetooth Sharing:BluetoothSharing"
    )
    
    local enabled_sharing=()
    local risky_sharing=()
    
    for service in "${sharing_services[@]}"; do
        local service_name=$(echo "$service" | cut -d: -f1)
        local service_process=$(echo "$service" | cut -d: -f2)
        
        # Check if service is running
        if pgrep -f "$service_process" >/dev/null 2>&1; then
            enabled_sharing+=("$service_name")
            
            # Mark potentially risky services
            case "$service_name" in
                "Screen Sharing"|"Remote Login"|"Remote Management")
                    risky_sharing+=("$service_name")
                    ;;
            esac
        fi
    done
    
    if [[ ${#enabled_sharing[@]} -gt 0 ]]; then
        local sharing_list=$(IFS=", "; echo "${enabled_sharing[*]}")
        add_network_finding "Network" "Enabled Sharing Services" "${#enabled_sharing[@]} services" "Active: $sharing_list" "INFO" ""
        
        if [[ ${#risky_sharing[@]} -gt 0 ]]; then
            local risky_list=$(IFS=", "; echo "${risky_sharing[*]}")
            add_network_finding "Security" "Remote Access Services" "${#risky_sharing[@]} enabled" "Services: $risky_list" "MEDIUM" "Review remote access services for security and business justification"
        fi
    else
        add_network_finding "Network" "Sharing Services" "None Active" "No network sharing services detected" "INFO" ""
    fi
}

check_vpn_connections() {
    log_message "INFO" "Checking VPN connections..." "NETWORK"
    
    # Check for VPN interfaces
    local vpn_interfaces=$(ifconfig 2>/dev/null | grep -E "^(utun|ppp|ipsec)" | cut -d: -f1)
    local vpn_count=0
    local active_vpn=false
    local active_vpn_interfaces=()
    local all_vpn_interfaces=()
    
    while IFS= read -r interface; do
        if [[ -n "$interface" ]]; then
            ((vpn_count++))
            all_vpn_interfaces+=("$interface")
            # Check for IPv4 addresses (not IPv6 link-local) to determine if VPN is truly active
            local ipv4_addr=$(ifconfig "$interface" 2>/dev/null | grep "inet " | grep -v "127\." | awk '{print $2}')
            if [[ -n "$ipv4_addr" ]]; then
                active_vpn=true
                active_vpn_interfaces+=("$interface($ipv4_addr)")
            fi
        fi
    done <<< "$vpn_interfaces"
    
    if [[ $vpn_count -gt 0 ]]; then
        local vpn_status="Configured"
        local all_interfaces_list=$(IFS=", "; echo "${all_vpn_interfaces[*]}")
        local vpn_details="$vpn_count VPN interfaces: $all_interfaces_list"
        
        if [[ "$active_vpn" == true ]]; then
            vpn_status="Active"
            local active_list=$(IFS=", "; echo "${active_vpn_interfaces[*]}")
            vpn_details="$vpn_details - Active: $active_list"
        else
            vpn_details="$vpn_count system tunnel interfaces (no active VPN connections)"
        fi
        
        add_network_finding "Network" "VPN Configuration" "$vpn_status" "$vpn_details" "INFO" ""
    else
        add_network_finding "Network" "VPN Configuration" "None Detected" "No VPN interfaces found" "INFO" ""
    fi
    
    # Check for common VPN applications
    local vpn_apps=(
        "NordVPN.app"
        "ExpressVPN.app"
        "Tunnelblick.app"
        "Viscosity.app"
        "SurfShark.app"
        "CyberGhost.app"
        "Private Internet Access.app"
    )
    
    local found_vpn_apps=()
    for vpn_app in "${vpn_apps[@]}"; do
        if [[ -d "/Applications/$vpn_app" ]]; then
            local app_name=$(basename "$vpn_app" .app)
            found_vpn_apps+=("$app_name")
        fi
    done
    
    if [[ ${#found_vpn_apps[@]} -gt 0 ]]; then
        local vpn_app_list=$(IFS=", "; echo "${found_vpn_apps[*]}")
        add_network_finding "Network" "VPN Applications" "${#found_vpn_apps[@]} installed" "Found: $vpn_app_list" "INFO" ""
    fi
}

# Helper function to add network findings to the array
add_network_finding() {
    local category="$1"
    local item="$2"
    local value="$3"
    local details="$4"
    local risk_level="$5"
    local recommendation="$6"
    
    # Escape JSON strings to prevent control character issues
    category=$(escape_json_string "$category")
    item=$(escape_json_string "$item")
    value=$(escape_json_string "$value")
    details=$(escape_json_string "$details")
    risk_level=$(escape_json_string "$risk_level")
    recommendation=$(escape_json_string "$recommendation")
    
    NETWORK_FINDINGS+=("{\"category\":\"$category\",\"item\":\"$item\",\"value\":\"$value\",\"details\":\"$details\",\"risk_level\":\"$risk_level\",\"recommendation\":\"$recommendation\"}")
}

# Function to add specific port details like Windows report
add_specific_port_details() {
    # Get listening ports with process information
    if command -v lsof >/dev/null 2>&1; then
        # Get listening TCP ports with process info
        local port_details=$(lsof -iTCP -sTCP:LISTEN -n 2>/dev/null | grep -v COMMAND)
        
        # Function to get port description (bash 3.2 compatible)
        get_port_description() {
            case "$1" in
                "22") echo "SSH" ;;
                "80") echo "HTTP" ;;
                "88") echo "Kerberos" ;;
                "443") echo "HTTPS" ;;
                "445") echo "SMB/CIFS" ;;
                "993") echo "IMAPS" ;;
                "995") echo "POP3S" ;;
                "5000") echo "UPnP/Flask Dev" ;;
                "7000") echo "Development Server" ;;
                "8080") echo "HTTP Alternative" ;;
                "8989") echo "Sonarr/Web Service" ;;
                "9993") echo "ZeroTier" ;;
                *) echo "Unknown Service" ;;
            esac
        }
        
        # Track processed ports to avoid duplicates
        local processed_ports=()
        
        # Process each listening port
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local process=$(echo "$line" | awk '{print $1}')
                local pid=$(echo "$line" | awk '{print $2}')
                local port=$(echo "$line" | awk '{print $9}' | sed 's/.*://' | sed 's/(.*//')
                
                # Skip if already processed this port
                local already_processed=false
                for processed in "${processed_ports[@]}"; do
                    if [[ "$processed" == "$port" ]]; then
                        already_processed=true
                        break
                    fi
                done
                
                if [[ "$already_processed" == false && -n "$port" && "$port" =~ ^[0-9]+$ ]]; then
                    processed_ports+=("$port")
                    
                    # Get service description
                    local service_desc=$(get_port_description "$port")
                    
                    # Add port finding
                    add_network_finding "Network" "Port $port" "$service_desc" "Process: $process (PID: $pid)" "INFO" ""
                fi
            fi
        done <<< "$port_details"
    fi
}

# Function to get findings for report generation
get_network_findings() {
    printf '%s\n' "${NETWORK_FINDINGS[@]}"
}

# [EXPORT] export_reports - Report export functionality for macOS
# Order: 200
#!/bin/bash

# macOSWorkstationAuditor - Report Export Module
# Version 1.0.0

# Global variables for report generation (bash 3.2 compatible)
ALL_FINDINGS=()
RISK_COUNT_HIGH=0
RISK_COUNT_MEDIUM=0
RISK_COUNT_LOW=0
RISK_COUNT_INFO=0

export_markdown_report() {
    log_message "INFO" "Generating technician report..." "REPORT"

    # Generate technician report (matching Windows format) - findings already collected
    local report_file="$OUTPUT_PATH/${BASE_FILENAME}_technician_report.md"
    
    generate_markdown_header > "$report_file"
    generate_executive_summary >> "$report_file"
    generate_critical_action_items >> "$report_file"
    generate_system_overview >> "$report_file"
    generate_system_resources >> "$report_file"
    generate_network_interfaces >> "$report_file"
    generate_security_management >> "$report_file"
    generate_security_analysis >> "$report_file"
    generate_software_inventory >> "$report_file"
    generate_recommendations >> "$report_file"
    generate_markdown_footer >> "$report_file"
    
    log_message "SUCCESS" "Technician report generated: $report_file" "REPORT"
}

export_raw_data_json() {
    log_message "INFO" "Generating JSON raw data export..." "REPORT"

    # Use findings already collected - don't collect again
    local json_file="$OUTPUT_PATH/${BASE_FILENAME}_raw_data.json"
    
    # Generate JSON structure matching Windows version format
    cat > "$json_file" << EOF
{
  "metadata": {
    "computer_name": "$COMPUTER_NAME",
    "audit_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "tool_version": "$CONFIG_VERSION",
    "platform": "macOS",
    "os_version": "$(sw_vers -productVersion)",
    "os_build": "$(sw_vers -buildVersion)",
    "audit_duration_seconds": $(($(date +%s) - START_TIME))
  },
  "system_context": {
    "os_info": {
      "caption": "$(sw_vers -productName) $(sw_vers -productVersion)",
      "version": "$(sw_vers -productVersion)",
      "build_number": "$(sw_vers -buildVersion)",
      "architecture": "$(uname -m)",
      "last_boot_time": "$(date -r $(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',') '+%Y-%m-%d %H:%M:%S')"
    },
    "hardware_info": {
      "model": "$(sysctl -n hw.model)",
      "total_memory_gb": $(echo "scale=2; $(sysctl -n hw.memsize) / 1073741824" | bc),
      "cpu_cores": $(sysctl -n hw.ncpu)
    },
    "domain": "$(hostname | cut -d. -f2- || echo 'WORKGROUP')",
    "computer_name": "$COMPUTER_NAME"
  },
  "compliance_framework": {
    "findings": [
EOF

    # Add all findings as JSON
    local first_finding=true
    for finding in "${ALL_FINDINGS[@]}"; do
        if [[ "$first_finding" == true ]]; then
            first_finding=false
        else
            echo "," >> "$json_file"
        fi
        
        # Parse JSON finding using native bash/sed/awk (no Python dependency)
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
        local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
        
        # Set defaults if parsing failed
        [[ -z "$category" ]] && category="Unknown"
        [[ -z "$item" ]] && item="Unknown"
        [[ -z "$value" ]] && value="Unknown"
        [[ -z "$risk_level" ]] && risk_level="INFO"

        # Skip empty or malformed entries
        if [[ "$item" == "Unknown" && "$value" == "Unknown" ]]; then
            continue
        fi

        # Generate finding ID
        local finding_id="macOS-$(echo "$category$item" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd '[:alnum:]-')"
        
        cat >> "$json_file" << EOF
      {
        "finding_id": "$finding_id",
        "category": "$category",
        "item": "$item",
        "value": "$value",
        "requirement": "$details",
        "risk_level": "$risk_level",
        "recommendation": "$recommendation",
        "framework": "macOS_Security_Assessment"
      }
EOF
    done

    cat >> "$json_file" << EOF
    ]
  },
  "summary": {
    "total_findings": ${#ALL_FINDINGS[@]},
    "risk_distribution": {
      "HIGH": $RISK_COUNT_HIGH,
      "MEDIUM": $RISK_COUNT_MEDIUM,
      "LOW": $RISK_COUNT_LOW,
      "INFO": $RISK_COUNT_INFO
    }
  }
}
EOF

    log_message "SUCCESS" "JSON raw data exported: $json_file" "REPORT"
}

collect_all_findings() {
    log_message "INFO" "Collecting findings from all modules..." "REPORT"
    
    # Initialize arrays and counters
    ALL_FINDINGS=()
    RISK_COUNT_HIGH=0
    RISK_COUNT_MEDIUM=0
    RISK_COUNT_LOW=0
    RISK_COUNT_INFO=0
    
    # Collect findings from each module if functions exist
    local module_functions=(
        "get_system_findings"
        "get_security_findings"
        "get_software_findings"
        "get_network_findings"
        "get_user_findings"
        "get_patch_findings"
        "get_disk_findings"
        "get_memory_findings"
        "get_process_findings"
    )
    
    for func in "${module_functions[@]}"; do
        if declare -f "$func" >/dev/null 2>&1; then
            log_message "INFO" "Collecting findings from $func..." "REPORT"
            while IFS= read -r finding; do
                if [[ -n "$finding" ]]; then
                    ALL_FINDINGS+=("$finding")
                    
                    # Count risk levels using native bash
                    local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                    [[ -z "$risk_level" ]] && risk_level="INFO"
                    case "$risk_level" in
                        "HIGH") ((RISK_COUNT_HIGH++)) ;;
                        "MEDIUM") ((RISK_COUNT_MEDIUM++)) ;;
                        "LOW") ((RISK_COUNT_LOW++)) ;;
                        *) ((RISK_COUNT_INFO++)) ;;
                    esac
                fi
            done < <($func 2>/dev/null || echo "")
        fi
    done
    
    log_message "SUCCESS" "Collected ${#ALL_FINDINGS[@]} total findings" "REPORT"
}

generate_markdown_header() {
    cat << EOF
# macOS Workstation Security Audit Report

**Computer:** $COMPUTER_NAME
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool Version:** macOS Workstation Auditor v$CONFIG_VERSION

EOF
}

generate_executive_summary() {
    cat << EOF
## Executive Summary

| Risk Level | Count | Priority |
|------------|-------|----------|
| HIGH | $RISK_COUNT_HIGH | Immediate Action Required |
| MEDIUM | $RISK_COUNT_MEDIUM | Review and Plan Remediation |
| LOW | $RISK_COUNT_LOW | Monitor and Maintain |
| INFO | $RISK_COUNT_INFO | Informational |

EOF
}

generate_critical_action_items() {
    # Only generate this section if there are HIGH or MEDIUM risk items
    if [[ $RISK_COUNT_HIGH -gt 0 || $RISK_COUNT_MEDIUM -gt 0 ]]; then
        cat << EOF
## Critical Action Items

EOF
        
        if [[ $RISK_COUNT_HIGH -gt 0 ]]; then
            cat << EOF
### HIGH PRIORITY (Immediate Action Required)

EOF
            for finding in "${ALL_FINDINGS[@]}"; do
                local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_risk" ]] && finding_risk="INFO"
                
                if [[ "$finding_risk" == "HIGH" ]]; then
                    local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$category" ]] && category="Unknown"
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    
                    cat << EOF
- **$category - $item:** $value
  - Details: $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
  - Recommendation: $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        fi
        
        if [[ $RISK_COUNT_MEDIUM -gt 0 ]]; then
            cat << EOF
### MEDIUM PRIORITY (Review and Plan)

EOF
            for finding in "${ALL_FINDINGS[@]}"; do
                local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_risk" ]] && finding_risk="INFO"
                
                if [[ "$finding_risk" == "MEDIUM" ]]; then
                    local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                    local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                    local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                    local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                    
                    [[ -z "$category" ]] && category="Unknown"
                    [[ -z "$item" ]] && item="Unknown"
                    [[ -z "$value" ]] && value="Unknown"
                    
                    cat << EOF
- **$category - $item:** $value
  - Details: $details
EOF
                    if [[ -n "$recommendation" ]]; then
                        cat << EOF
  - Recommendation: $recommendation
EOF
                    fi
                    echo ""
                fi
            done
        fi
    fi
}

generate_additional_information() {
    # Get LOW and INFO items, grouped by category, excluding categories that appear in Critical Action Items
    local additional_items=()
    local critical_categories=()
    
    # Debug: Log the number of findings we're starting with
    log_message "INFO" "Total findings to process: ${#ALL_FINDINGS[@]}" "REPORT"
    
    # First, collect categories that appear in HIGH/MEDIUM findings
    for finding in "${ALL_FINDINGS[@]}"; do
        local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        [[ -z "$finding_risk" ]] && finding_risk="INFO"
        
        if [[ "$finding_risk" == "HIGH" || "$finding_risk" == "MEDIUM" ]]; then
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            [[ -n "$category" ]] && critical_categories+=("$category")
        fi
    done
    
    # Collect LOW and INFO items not in critical categories
    for finding in "${ALL_FINDINGS[@]}"; do
        local finding_risk=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        [[ -z "$finding_risk" ]] && finding_risk="INFO"
        
        if [[ "$finding_risk" == "LOW" || "$finding_risk" == "INFO" ]]; then
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            
            # Check if this category appears in critical findings
            local is_critical_category=false
            for crit_cat in "${critical_categories[@]}"; do
                if [[ "$category" == "$crit_cat" ]]; then
                    is_critical_category=true
                    break
                fi
            done
            
            # Exclude items that appear in dedicated sections
            local is_dedicated_section_item=false

            # Exclude System Configuration items
            if [[ "$category" == "System" ]]; then
                case "$item" in
                    "Operating System"|"Hardware"|"Computer Name"|"System Uptime"|"Time Machine Backups"|"Backup Solutions")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Management items (now in System Configuration)
            if [[ "$category" == "Management" ]]; then
                case "$item" in
                    "MDM Enrollment"|"Apple Business Manager"|"Device Supervision"|"Configuration Profiles")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Process items (now in Process Analysis)
            if [[ "$category" == "Process" ]]; then
                case "$item" in
                    "Process Activity"|"Top 5 Process CPU Usage"|"Top 5 Process Memory Usage")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Memory items (now in Memory Analysis)
            if [[ "$category" == "Memory" ]]; then
                case "$item" in
                    "Memory Usage"|"Top 5 Process Memory Usage"|"Memory Pressure")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Exclude Storage items (now in Disk Analysis) but allow Directory items to remain excluded
            if [[ ("$category" == "Storage" || "$item" =~ "Disk") && ! "$item" =~ "Directory:" ]]; then
                is_dedicated_section_item=true
            fi

            # Always exclude directory listings (unwanted fluff)
            if [[ "$item" =~ "Directory:" ]]; then
                is_dedicated_section_item=true
            fi

            # Exclude Network items (now in Network Analysis)
            if [[ "$category" == "Network" ]]; then
                case "$item" in
                    "Active Interfaces"|"Primary IP Address"|"Wi-Fi Status"|"Saved Wi-Fi Networks"|"DNS Servers"|"Listening Services"|"Sharing Services"|"VPN Configuration"|"High-Risk Listening Ports")
                        is_dedicated_section_item=true
                        ;;
                esac
            fi

            # Always exclude established connections (unwanted noise)
            if [[ "$item" == "Established Connections" ]]; then
                is_dedicated_section_item=true
            fi

            # Exclude port findings (now in Network Analysis)
            if [[ "$item" =~ "Port " && "$category" == "Network" ]]; then
                is_dedicated_section_item=true
            fi

            # Include only non-critical categories and non-dedicated section items - no duplicates allowed
            if [[ "$is_critical_category" == false && "$is_dedicated_section_item" == false ]]; then
                additional_items+=("$finding")
            fi
        fi
    done
    
    if [[ ${#additional_items[@]} -gt 0 ]]; then
        cat << EOF
## Additional Information

EOF
        
        # Group by category and only output categories that have items
        local categories=()
        log_message "INFO" "Additional items count: ${#additional_items[@]}" "REPORT"
        
        for finding in "${additional_items[@]}"; do
            local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
            [[ -z "$category" ]] && category="Unknown"
            
            log_message "INFO" "Found category: '$category' from finding: $(echo "$finding" | cut -c1-100)..." "REPORT"
            
            # Add to categories if not already present
            local category_exists=false
            for existing_cat in "${categories[@]}"; do
                if [[ "$existing_cat" == "$category" ]]; then
                    category_exists=true
                    break
                fi
            done
            [[ "$category_exists" == false ]] && categories+=("$category")
        done
        
        log_message "INFO" "Categories collected: ${categories[*]}" "REPORT"
        
        # Sort and output categories, but only if they have items
        for category in $(printf '%s\n' "${categories[@]}" | sort); do
            # First check if this category actually has items
            local category_has_items=false
            for finding in "${additional_items[@]}"; do
                local finding_category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                [[ -z "$finding_category" ]] && finding_category="Unknown"
                
                if [[ "$finding_category" == "$category" ]]; then
                    category_has_items=true
                    break
                fi
            done
            
            # Only output the category if it has items
            if [[ "$category_has_items" == true ]]; then
                cat << EOF
### $category

EOF
                
                for finding in "${additional_items[@]}"; do
                    local finding_category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
                    [[ -z "$finding_category" ]] && finding_category="Unknown"
                    
                    if [[ "$finding_category" == "$category" ]]; then
                        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
                        local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                        local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
                        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
                        
                        [[ -z "$item" ]] && item="Unknown"
                        [[ -z "$value" ]] && value="Unknown"
                        [[ -z "$risk_level" ]] && risk_level="INFO"
                        
                        # Skip empty or malformed entries
                        if [[ "$item" == "Unknown" && "$value" == "Unknown" ]]; then
                            continue
                        fi
                        
                        local risk_icon="[INFO]"
                        [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                        
                        cat << EOF
**$risk_icon $item:** $value

- **Details:** $details
EOF
                        if [[ -n "$recommendation" ]]; then
                            cat << EOF
- **Recommendation:** $recommendation
EOF
                        fi
                        echo ""
                    fi
                done
            fi
        done
    fi
}

generate_system_overview() {
    cat << EOF
## System Overview

EOF

    # Core system identification - no duplicates, clean format
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Operating System" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Operating System:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Hardware" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Hardware:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Computer Name" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Computer Name:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "System Uptime" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Uptime:** $value - $details"
            break
        fi
    done

    # Updates section (moved here from buried location)
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Available Updates" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Updates:** $value - $details"
            break
        fi
    done

    echo ""
}

generate_system_resources() {
    cat << EOF
## System Resources

EOF

    # Memory - show once, no duplicates
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Memory Usage" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Memory Usage:** $value - $details"
            break
        fi
    done

    # Top memory processes - show once
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Top 5 Process Memory Usage" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Top Memory Processes:** $value - $details"
            break
        fi
    done

    # Top CPU processes - show if available for consistency
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Top 5 Process CPU Usage" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Top CPU Processes:** $value - $details"
            break
        fi
    done

    # Process count - show once
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Process Activity" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Active Processes:** $value - $details"
            break
        fi
    done

    # Disk usage - show only the main volume, no directory clutter
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" =~ "Disk Usage: /System/Volumes/Data" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            if [[ "$risk_level" == "MEDIUM" || "$risk_level" == "HIGH" ]]; then
                echo "- **Disk Space Warning:** $value - $details"
                if [[ -n "$recommendation" ]]; then
                    echo "  - Action: $recommendation"
                fi
            else
                echo "- **Disk Space:** $value - $details"
            fi
            break
        fi
    done

    echo ""
}

generate_network_interfaces() {
    cat << EOF
## Network Configuration

EOF

    # Network interface basics - no duplicates
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Active Interfaces" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Network Status:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Primary IP Address" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **IP Address:** $value - $details"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "DNS Servers" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **DNS:** $value - $details"
            break
        fi
    done

    # VPN info if present
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "VPN Configuration" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **VPN:** $value - $details"
            break
        fi
    done

    echo ""
}

generate_security_management() {
    cat << EOF
## Security & Management

EOF

    # Authentication
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Login Management" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Authentication:** $value - $details"
            break
        fi
    done

    # MDM and management - consolidated
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "MDM Enrollment" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Device Management:** $value (MDM)"
            break
        fi
    done

    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Device Supervision" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Device Supervision:** $value"
            break
        fi
    done

    # Backup - fix the duplicate issue
    local backup_found=false
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Time Machine Backups" && "$backup_found" == false ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Backup (Time Machine):** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            backup_found=true
            break
        fi
    done

    echo ""
}

generate_security_analysis() {
    cat << EOF
## Security Analysis

EOF

    # High-risk ports - show once at top, no duplicates
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "High-Risk Listening Ports" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Risky Network Ports:** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    # Network services - combine listening services with actual port details
    local listening_count=""
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Listening Services" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            listening_count="$value"
            break
        fi
    done

    # Show specific ports found
    local port_details=""
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" =~ "Port " ]]; then
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            if [[ -n "$port_details" ]]; then
                port_details="$port_details, $details"
            else
                port_details="$details"
            fi
        fi
    done

    if [[ -n "$listening_count" ]]; then
        echo "- **Network Services:** $listening_count"
        if [[ -n "$port_details" ]]; then
            echo "  - Active: $port_details"
        fi
    fi

    # Remote access software
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Remote Access Software" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Remote Access Tools:** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    # Antivirus/Antimalware detection
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Third-party Antivirus" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Antivirus Protection:** $value - $details"
            break
        fi
    done

    # RMM/Remote Management Tools
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "RMM Tools" || "$item" == "Remote Management" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **RMM Tools:** $value - $details"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    # iCloud Status
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "iCloud Status" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **iCloud Status:** $value - $details"
            break
        fi
    done

    # Find My Status
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Find My" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Find My:** $value - $details"
            break
        fi
    done

    # WiFi security concerns
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Saved Wi-Fi Networks" && "$risk_level" == "LOW" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **WiFi Security:** $value saved networks"
            if [[ -n "$recommendation" ]]; then
                echo "  - Action: $recommendation"
            fi
            break
        fi
    done

    echo ""
}

generate_software_inventory() {
    cat << EOF
## Software Inventory

EOF

    # Application count
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Total Installed Applications" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Installed Applications:** $value - $details"
            break
        fi
    done

    # Key applications - show only the important ones
    local key_apps=("Zoom" "Microsoft Office" "Visual Studio Code" "Docker Desktop" "Safari Browser")
    for app in "${key_apps[@]}"; do
        for finding in "${ALL_FINDINGS[@]}"; do
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            if [[ "$item" == "$app" ]]; then
                local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                echo "- **$app:** $value"
                break
            fi
        done
    done

    # Development tools summary
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        if [[ "$item" == "Development Tools" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            echo "- **Development Tools:** $value - $details"
            break
        fi
    done

    echo ""
}

# Old process section function removed - replaced by integrated system resources section

generate_memory_section() {
    cat << EOF
## Memory Analysis

EOF

    # Get memory-related findings
    local memory_items=("Memory Usage" "Top 5 Process Memory Usage" "Memory Pressure")

    for memory_item in "${memory_items[@]}"; do
        for finding in "${ALL_FINDINGS[@]}"; do
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

            if [[ "$item" == "$memory_item" ]]; then
                local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)

                [[ -z "$value" ]] && value="Unknown"
                [[ -z "$risk_level" ]] && risk_level="INFO"

                local risk_icon="[INFO]"
                [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
                [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

                cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
                if [[ -n "$recommendation" ]]; then
                    cat << EOF
  - Recommendation: $recommendation
EOF
                fi
                echo ""
                break
            fi
        done
    done
}

generate_disk_section() {
    cat << EOF
## Disk Analysis

EOF

    # Get disk-related findings - pattern match for disk usage items
    for finding in "${ALL_FINDINGS[@]}"; do
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

        # Include Storage category and disk-related items, but exclude individual directory listings
        if [[ ("$category" == "Storage" || "$item" =~ "Disk") && ! "$item" =~ "Directory:" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)

            [[ -z "$value" ]] && value="Unknown"
            [[ -z "$risk_level" ]] && risk_level="INFO"

            local risk_icon="[INFO]"
            [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
            [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
            [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

            cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
            if [[ -n "$recommendation" ]]; then
                cat << EOF
  - Recommendation: $recommendation
EOF
            fi
            echo ""
        fi
    done
}

generate_network_section() {
    cat << EOF
## Network Analysis

EOF

    # Get network-related findings
    local network_items=("High-Risk Listening Ports" "Active Interfaces" "Primary IP Address" "Wi-Fi Status" "Saved Wi-Fi Networks" "DNS Servers" "Listening Services" "Sharing Services" "VPN Configuration")

    for network_item in "${network_items[@]}"; do
        for finding in "${ALL_FINDINGS[@]}"; do
            local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
            local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

            if [[ "$item" == "$network_item" ]]; then
                local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
                local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
                local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)

                [[ -z "$value" ]] && value="Unknown"
                [[ -z "$risk_level" ]] && risk_level="INFO"

                local risk_icon="[INFO]"
                [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
                [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
                [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

                cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
                if [[ -n "$recommendation" ]]; then
                    cat << EOF
  - Recommendation: $recommendation
EOF
                fi
                echo ""
                break
            fi
        done
    done

    # Also include specific port findings that might not match the standard items
    for finding in "${ALL_FINDINGS[@]}"; do
        local item=$(echo "$finding" | sed -n 's/.*"item":"\([^"]*\)".*/\1/p' | head -1)
        local category=$(echo "$finding" | sed -n 's/.*"category":"\([^"]*\)".*/\1/p' | head -1)

        # Include port findings
        if [[ "$item" =~ "Port " && "$category" == "Network" ]]; then
            local value=$(echo "$finding" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p' | head -1)
            local details=$(echo "$finding" | sed -n 's/.*"details":"\([^"]*\)".*/\1/p' | head -1)
            local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

            [[ -z "$value" ]] && value="Unknown"
            [[ -z "$risk_level" ]] && risk_level="INFO"

            local risk_icon="[INFO]"
            [[ "$risk_level" == "LOW" ]] && risk_icon="[LOW]"
            [[ "$risk_level" == "MEDIUM" ]] && risk_icon="[MEDIUM]"
            [[ "$risk_level" == "HIGH" ]] && risk_icon="[HIGH]"

            cat << EOF
- **$risk_icon $item:** $value
  - Details: $details
EOF
            echo ""
        fi
    done
}

generate_recommendations() {
    # Collect only LOW risk recommendations that aren't already in Critical Action Items
    local recommendations=()
    local rec_counts=()

    # Skip only inappropriate recommendations - let the logic determine what to show based on actual status
    local skip_recommendations=(
        "1 network printers detected. Ensure they are on trusted networks and use secure protocols"
        "Evaluate enterprise security solutions such as CrowdStrike, SentinelOne, or Jamf Protect for comprehensive threat detection"
        "Review remote access software for security and business justification"
        "Time Machine is configured but no backups have completed. Verify backup destination is accessible"
        "Review listening services for security implications. Disable unnecessary services"
        "Disk space is getting low. Monitor usage and consider cleanup"
        "Backup solutions detected - verify they are configured and running properly"
        "Consider signing into iCloud for backup and device synchronization"
        "Sign into iCloud and enable backup for data protection"
        "Enable Find My for device security and theft protection"
        "Sign into iCloud to enable Find My"
    )

    for finding in "${ALL_FINDINGS[@]}"; do
        local recommendation=$(echo "$finding" | sed -n 's/.*"recommendation":"\([^"]*\)".*/\1/p' | head -1)
        local risk_level=$(echo "$finding" | sed -n 's/.*"risk_level":"\([^"]*\)".*/\1/p' | head -1)

        if [[ -n "$recommendation" && "$recommendation" != "" && "$risk_level" == "LOW" ]]; then
            # Check if this recommendation should be skipped
            local should_skip=false
            for skip_rec in "${skip_recommendations[@]}"; do
                if [[ "$recommendation" == "$skip_rec" ]]; then
                    should_skip=true
                    break
                fi
            done

            if [[ "$should_skip" == false ]]; then
                # Check if this recommendation already exists
                local rec_exists=false
                local rec_index=0

                for i in "${!recommendations[@]}"; do
                    if [[ "${recommendations[$i]}" == "$recommendation" ]]; then
                        rec_exists=true
                        rec_index=$i
                        break
                    fi
                done

                if [[ "$rec_exists" == true ]]; then
                    # Increment count
                    rec_counts[$rec_index]=$((${rec_counts[$rec_index]} + 1))
                else
                    # Add new recommendation
                    recommendations+=("$recommendation")
                    rec_counts+=(1)
                fi
            fi
        fi
    done

    if [[ ${#recommendations[@]} -gt 0 ]]; then
        cat << EOF
## Additional Recommendations

EOF

        for i in "${!recommendations[@]}"; do
            cat << EOF
- **${recommendations[$i]}**

EOF
        done
    fi
}

generate_markdown_footer() {
    cat << EOF
---

*This report was generated by macOS Workstation Auditor v$CONFIG_VERSION*

*For detailed data analysis and aggregation, refer to the corresponding JSON export.*

EOF
}

# Main report export functions called by the main script
export_reports() {
    log_message "INFO" "Starting report generation..." "REPORT"

    # Collect findings once from all modules
    collect_all_findings

    # Generate both report formats using the same data
    export_markdown_report
    export_raw_data_json

    log_message "SUCCESS" "All reports generated successfully" "REPORT"
}

# === MAIN SCRIPT LOGIC (MODIFIED FOR WEB DEPLOYMENT) ===

# Override load_module function for web version (modules already embedded)
load_module() {
    local module_name="$1"
    log_message "SUCCESS" "Module available: $module_name" "MODULE"
    return 0
}


# macOSWorkstationAuditor - macOS Workstation IT Assessment Tool
# Version 1.0.0 - Modular Architecture
# Platform: macOS 10.14+ (Mojave and later)
# Requires: bash 3.2+, Administrative privileges recommended

# Parameter handling
OUTPUT_PATH="./output"
CONFIG_PATH="./config"
VERBOSE=false
FORCE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "macOS Workstation IT Assessment Tool v1.0.0"
            echo "Usage: $0 [options]"
            echo "  -o, --output PATH    Output directory (default: ./output)"
            echo "  -c, --config PATH    Configuration directory (default: ./config)"
            echo "  -v, --verbose        Enable verbose logging"
            echo "  -f, --force          Force overwrite existing files"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE=""
START_TIME=$(date +%s)
COMPUTER_NAME=$(hostname -s)
BASE_FILENAME="${COMPUTER_NAME}_$(date '+%Y%m%d_%H%M%S')"
MODULES_PATH="$SCRIPT_DIR/modules"

# Configuration (using bash 3.2 compatible syntax)
CONFIG_VERSION="1.0.0"
CONFIG_ANALYSIS_DAYS=7
CONFIG_MAX_EVENTS=1000

# Color definitions for terminal output
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
COLOR_WHITE='\033[0;37m'
COLOR_BOLD='\033[1m'
COLOR_RESET='\033[0m'

# JSON escape function to handle control characters
escape_json_string() {
    local input="$1"
    # Escape backslashes first, then quotes, then newlines, tabs, and carriage returns, then trim whitespace
    echo "$input" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed 's/\t/\\t/g' | tr '\n' ' ' | tr '\r' ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Logging functions with color support
log_message() {
    local level="$1"
    local message="$2"
    local category="${3:-MAIN}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local log_entry="[$timestamp] [$level] [$category] $message"
    local colored_output=""
    
    # Add colors based on log level (matches Windows PowerShell)
    case "$level" in
        "SUCCESS")
            colored_output="${COLOR_GREEN}$log_entry${COLOR_RESET}"
            ;;
        "ERROR")
            colored_output="${COLOR_RED}$log_entry${COLOR_RESET}"
            ;;
        "WARN"|"WARNING")
            colored_output="${COLOR_YELLOW}$log_entry${COLOR_RESET}"
            ;;
        "INFO")
            colored_output="$log_entry"
            ;;
        *)
            colored_output="$log_entry"
            ;;
    esac
    
    # Display colored output for console
    if [[ "$VERBOSE" == true ]] || [[ "$level" == "ERROR" ]]; then
        echo -e "$colored_output"
    fi
    
    # Log plain text to file
    if [[ -n "$LOG_FILE" ]]; then
        echo "$log_entry" >> "$LOG_FILE"
    fi
}

# Enhanced progress output function with Windows-style rich feedback
# Displays colored status messages with optional timing and finding counts
# Parameters:
#   $1 - status: STARTING|COMPLETE|FAILED|HEADER|PROGRESS|WARNING
#   $2 - message: descriptive text for the operation
#   $3 - findings_count: optional number of findings discovered (for COMPLETE status)
#   $4 - duration: optional execution time in seconds (for COMPLETE status)
print_status() {
    local status="$1"
    local message="$2"
    local findings_count="$3"
    local duration="$4"
    
    case "$status" in
        "STARTING")
            # Simple starting message with ellipsis
            echo "${message}..."
            ;;
        "COMPLETE")
            # Rich completion message with optional metrics
            if [[ -n "$findings_count" && -n "$duration" ]]; then
                # Full metrics: findings count and execution time
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET} ${COLOR_CYAN}($findings_count findings, ${duration}s)${COLOR_RESET}"
            elif [[ -n "$findings_count" ]]; then
                # Findings count only
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET} ${COLOR_CYAN}($findings_count findings)${COLOR_RESET}"
            elif [[ -n "$duration" ]]; then
                # Execution time only
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET} ${COLOR_CYAN}(${duration}s)${COLOR_RESET}"
            else
                # Basic completion message
                echo -e "  ${COLOR_GREEN}→ ${message}: COMPLETE${COLOR_RESET}"
            fi
            ;;
        "FAILED")
            # Error status in red
            echo -e "  ${COLOR_RED}→ ${message}: FAILED${COLOR_RESET}"
            ;;
        "HEADER")
            # Bold blue header text
            echo -e "${COLOR_BOLD}${COLOR_BLUE}${message}${COLOR_RESET}"
            ;;
        "PROGRESS")
            # Yellow progress indicator for intermediate steps
            echo -e "  ${COLOR_YELLOW}→ ${message}${COLOR_RESET}"
            ;;
        "WARNING")
            # Yellow warning with warning symbol
            echo -e "  ${COLOR_YELLOW}⚠ ${message}${COLOR_RESET}"
            ;;
    esac
}

# Module loading system

# Configuration loading
load_configuration() {
    local config_file="$CONFIG_PATH/macos-audit-config.json"
    
    if [[ -f "$config_file" ]]; then
        log_message "INFO" "Loading configuration from: $config_file" "CONFIG"
        
        # Parse JSON using plutil (always available on macOS)
        if command -v plutil >/dev/null 2>&1; then
            local version=$(plutil -extract version raw "$config_file" 2>/dev/null)
            if [[ -n "$version" ]]; then
                CONFIG_VERSION="$version"
                log_message "SUCCESS" "Configuration loaded: v$CONFIG_VERSION" "CONFIG"
            fi
        fi
    else
        log_message "WARNING" "Configuration file not found, using defaults" "CONFIG"
    fi
}

# Initialize environment
initialize_environment() {
    log_message "INFO" "macOS Workstation Auditor v$CONFIG_VERSION starting..." "INIT"
    log_message "INFO" "Computer: $COMPUTER_NAME" "INIT"
    log_message "INFO" "macOS Version: $(sw_vers -productVersion)" "INIT"
    log_message "INFO" "Architecture: $(uname -m)" "INIT"
    
    # Create output and logs directories
    if [[ ! -d "$OUTPUT_PATH" ]]; then
        mkdir -p "$OUTPUT_PATH"
        log_message "INFO" "Created output directory: $OUTPUT_PATH" "INIT"
    fi
    
    local logs_dir="$OUTPUT_PATH/logs"
    if [[ ! -d "$logs_dir" ]]; then
        mkdir -p "$logs_dir"
        log_message "INFO" "Created logs directory: $logs_dir" "INIT"
    fi
    
    # Initialize log file in logs subdirectory (matching Windows format)
    LOG_FILE="$logs_dir/${BASE_FILENAME}_audit.log"
    log_message "INFO" "Log file: $LOG_FILE" "INIT"
    
    # Load configuration
    load_configuration
    
    # Check for administrative privileges
    if [[ $EUID -eq 0 ]]; then
        log_message "INFO" "Running with root privileges" "INIT"
    else
        log_message "WARNING" "Not running as root - some data collection may be limited" "INIT"
    fi
}

# Data collection functions with performance tracking and metrics
# Each collection function tracks execution time and finding counts for rich console feedback

collect_system_information() {
    # Track execution time for performance monitoring
    local start_time=$(date +%s)
    print_status "STARTING" "Collecting system information"
    log_message "INFO" "Collecting system information..." "SYSTEM"
    
    # Load system information module
    if load_module "get_system_information"; then
        # Detailed progress feedback during data collection
        print_status "PROGRESS" "Analyzing hardware configuration..."
        print_status "PROGRESS" "Checking macOS version and build details..."
        print_status "PROGRESS" "Gathering system uptime and boot information..."
        
        # Count findings before and after module execution for delta calculation
        local findings_before=${#SYSTEM_FINDINGS[@]}
        get_system_information_data
        local findings_after=${#SYSTEM_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # System-specific warnings and notifications
        if [[ $findings_count -lt 5 ]]; then
            print_status "WARNING" "Limited system information collected - may need elevated privileges"
        fi
        
        # Calculate execution duration for performance visibility
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        # Display completion with metrics (Windows-style rich feedback)
        print_status "COMPLETE" "System information" "$findings_count" "$duration"
    else
        print_status "FAILED" "System information"
        log_message "ERROR" "Failed to load system information module" "SYSTEM"
    fi
}

collect_security_settings() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing security settings"
    log_message "INFO" "Analyzing security settings..." "SECURITY"
    
    if load_module "get_security_settings"; then
        # Comprehensive security analysis progress
        print_status "PROGRESS" "Checking XProtect malware protection status..."
        print_status "PROGRESS" "Analyzing Gatekeeper and System Integrity Protection..."
        print_status "PROGRESS" "Evaluating FileVault encryption configuration..."
        print_status "PROGRESS" "Scanning for third-party security tools..."
        print_status "PROGRESS" "Checking SSH and remote access services..."
        print_status "PROGRESS" "Analyzing AirDrop and sharing settings..."
        print_status "PROGRESS" "Validating firewall and network security..."
        
        local findings_before=${#SECURITY_FINDINGS[@]}
        get_security_settings_data
        local findings_after=${#SECURITY_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # Security-specific insights
        if [[ $findings_count -gt 20 ]]; then
            print_status "PROGRESS" "Comprehensive security profile detected - $findings_count configurations analyzed"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Security analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Security analysis"
        log_message "ERROR" "Failed to load security settings module" "SECURITY"
    fi
}

collect_software_inventory() {
    local start_time=$(date +%s)
    print_status "STARTING" "Collecting software inventory"
    log_message "INFO" "Collecting software inventory..." "SOFTWARE"
    
    if load_module "get_software_inventory"; then
        local findings_before=${#SOFTWARE_FINDINGS[@]}
        get_software_inventory_data
        local findings_after=${#SOFTWARE_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Software inventory" "$findings_count" "$duration"
    else
        print_status "FAILED" "Software inventory"
        log_message "ERROR" "Failed to load software inventory module" "SOFTWARE"
    fi
}

collect_network_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing network configuration"
    log_message "INFO" "Analyzing network configuration..." "NETWORK"
    
    if load_module "get_network_analysis"; then
        # Detailed network analysis progress
        print_status "PROGRESS" "Scanning active network interfaces and IP configuration..."
        print_status "PROGRESS" "Analyzing listening services and open ports..."
        print_status "PROGRESS" "Checking Wi-Fi networks and saved profiles..."
        print_status "PROGRESS" "Evaluating DNS configuration and VPN status..."
        
        local findings_before=${#NETWORK_FINDINGS[@]}
        get_network_analysis_data
        local findings_after=${#NETWORK_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # Network-specific insights  
        if [[ $findings_count -gt 8 ]]; then
            print_status "PROGRESS" "Complex network configuration detected - $findings_count settings analyzed"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Network analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Network analysis"
        log_message "ERROR" "Failed to load network analysis module" "NETWORK"
    fi
}

collect_user_account_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing user accounts"
    log_message "INFO" "Analyzing user accounts..." "USERS"
    
    if load_module "get_user_account_analysis"; then
        local findings_before=${#USER_FINDINGS[@]}
        get_user_account_analysis_data
        local findings_after=${#USER_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "User account analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "User account analysis"
        log_message "ERROR" "Failed to load user account analysis module" "USERS"
    fi
}

collect_patch_status() {
    local start_time=$(date +%s)
    print_status "STARTING" "Checking patch status"
    print_status "PROGRESS" "Analyzing macOS version lifecycle and support status..."
    print_status "PROGRESS" "Checking automatic update configuration..."
    print_status "WARNING" "Contacting Apple Software Update servers (may take 30+ seconds)..."
    log_message "INFO" "Checking patch status..." "PATCHING"
    
    if load_module "get_patch_status"; then
        print_status "PROGRESS" "Parsing available software updates..."
        print_status "PROGRESS" "Analyzing XProtect malware definition updates..."
        
        local findings_before=${#PATCH_FINDINGS[@]}
        get_patch_status_data
        local findings_after=${#PATCH_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        
        # Patch-specific insights - check for actual updates rather than just counting findings
        local update_findings=0
        for finding in "${PATCH_FINDINGS[@]}"; do
            if echo "$finding" | grep -q '"item":"Available Updates"' && echo "$finding" | grep -qv '"value":"None"'; then
                ((update_findings++))
            fi
        done

        if [[ $update_findings -eq 0 ]]; then
            print_status "PROGRESS" "No updates available - system appears current"
        elif [[ $update_findings -gt 0 ]]; then
            print_status "WARNING" "Software updates available - review for security patches"
        fi
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Patch analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Patch analysis"
        log_message "ERROR" "Failed to load patch status module" "PATCHING"
    fi
}

collect_disk_space_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing disk space"
    log_message "INFO" "Analyzing disk space..." "STORAGE"
    
    if load_module "get_disk_space_analysis"; then
        local findings_before=${#STORAGE_FINDINGS[@]}
        get_disk_space_analysis_data
        local findings_after=${#STORAGE_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Disk analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Disk analysis"
        log_message "ERROR" "Failed to load disk space analysis module" "STORAGE"
    fi
}

collect_memory_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing memory usage"
    log_message "INFO" "Analyzing memory usage..." "MEMORY"
    
    if load_module "get_memory_analysis"; then
        local findings_before=${#MEMORY_FINDINGS[@]}
        get_memory_analysis_data
        local findings_after=${#MEMORY_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Memory analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Memory analysis"
        log_message "ERROR" "Failed to load memory analysis module" "MEMORY"
    fi
}

collect_process_analysis() {
    local start_time=$(date +%s)
    print_status "STARTING" "Analyzing running processes"
    log_message "INFO" "Analyzing running processes..." "PROCESSES"
    
    if load_module "get_process_analysis"; then
        local findings_before=${#PROCESS_FINDINGS[@]}
        get_process_analysis_data
        local findings_after=${#PROCESS_FINDINGS[@]}
        local findings_count=$((findings_after - findings_before))
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Process analysis" "$findings_count" "$duration"
    else
        print_status "FAILED" "Process analysis"
        log_message "ERROR" "Failed to load process analysis module" "PROCESSES"
    fi
}

# Report generation with comprehensive summary statistics
# Aggregates findings from all modules and provides detailed progress feedback
generate_reports() {
    local start_time=$(date +%s)
    print_status "STARTING" "Generating assessment reports"
    log_message "INFO" "Generating assessment reports..." "REPORT"
    
    # Calculate total findings across all 9 analysis modules for summary statistics
    # This provides Windows-style visibility into the scope of data being processed
    local total_findings=$((${#SYSTEM_FINDINGS[@]} + ${#SECURITY_FINDINGS[@]} + ${#SOFTWARE_FINDINGS[@]} + ${#NETWORK_FINDINGS[@]} + ${#USER_FINDINGS[@]} + ${#PATCH_FINDINGS[@]} + ${#STORAGE_FINDINGS[@]} + ${#MEMORY_FINDINGS[@]} + ${#PROCESS_FINDINGS[@]}))
    
    # Display processing scope for user awareness (matching Windows auditor style)
    print_status "PROGRESS" "Processing $total_findings findings across 9 modules..."
    
    # Load report generation module and create both markdown and JSON outputs
    if load_module "export_reports"; then
        export_reports  # Generate both markdown and JSON reports with shared data
        
        # Calculate and display final completion metrics
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_status "COMPLETE" "Report generation" "$total_findings" "$duration"
    else
        print_status "FAILED" "Report generation"
        log_message "ERROR" "Failed to load report generation module" "REPORT"
    fi
}

# Cleanup function
cleanup() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log_message "SUCCESS" "Assessment completed in ${minutes}m ${seconds}s" "COMPLETE"
    log_message "INFO" "Reports saved to: $OUTPUT_PATH" "COMPLETE"
    
    # List generated files
    if [[ -d "$OUTPUT_PATH" ]]; then
        local files=$(ls -la "$OUTPUT_PATH"/${BASE_FILENAME}* 2>/dev/null | wc -l)
        log_message "INFO" "Generated $files output files" "COMPLETE"
    fi
}

# Signal handlers
trap cleanup EXIT
trap 'log_message "ERROR" "Script interrupted by user" "MAIN"; exit 130' INT

# Main execution
main() {
    # START_TIME already set at top of script for performance tracking
    
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_WHITE}macOS Workstation IT Assessment Tool v$CONFIG_VERSION${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Computer: ${COLOR_CYAN}$COMPUTER_NAME${COLOR_RESET}"
    echo -e "${COLOR_BOLD}Started: ${COLOR_CYAN}$(date)${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    
    # Check privilege level and provide guidance
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_YELLOW}WARNING: Running as standard user${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}→ Some security and management features require administrative privileges${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}→ For complete analysis, consider running: ${COLOR_BOLD}sudo $0${COLOR_RESET}"
        echo -e "  ${COLOR_YELLOW}→ Continuing with limited analysis...${COLOR_RESET}"
        echo ""
    else
        echo -e "${COLOR_GREEN}✓ Running with administrative privileges${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}→ Complete system analysis enabled${COLOR_RESET}"
        echo ""
    fi
    
    initialize_environment
    
    # Execute audit modules in sequence
    collect_system_information
    collect_security_settings
    collect_user_account_analysis
    collect_network_analysis
    collect_software_inventory
    collect_patch_status
    collect_disk_space_analysis
    collect_memory_analysis
    collect_process_analysis
    
    # Generate consolidated reports
    generate_reports
    
    # Comprehensive completion summary with detailed statistics
    local total_time=$(($(date +%s) - START_TIME))
    local total_findings=$((${#SYSTEM_FINDINGS[@]} + ${#SECURITY_FINDINGS[@]} + ${#SOFTWARE_FINDINGS[@]} + ${#NETWORK_FINDINGS[@]} + ${#USER_FINDINGS[@]} + ${#PATCH_FINDINGS[@]} + ${#STORAGE_FINDINGS[@]} + ${#MEMORY_FINDINGS[@]} + ${#PROCESS_FINDINGS[@]}))
    
    # Risk level breakdown from generated JSON report
    local latest_json=$(ls -t "$OUTPUT_PATH"/*_raw_data.json 2>/dev/null | head -1)
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    if [[ -f "$latest_json" ]]; then
        high_count=$(grep -c '"risk_level": "HIGH"' "$latest_json" 2>/dev/null || echo 0)
        medium_count=$(grep -c '"risk_level": "MEDIUM"' "$latest_json" 2>/dev/null || echo 0)
        low_count=$(grep -c '"risk_level": "LOW"' "$latest_json" 2>/dev/null || echo 0)
        info_count=$(grep -c '"risk_level": "INFO"' "$latest_json" 2>/dev/null || echo 0)
    fi
    
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_GREEN}✓ Assessment completed successfully!${COLOR_RESET}"
    echo \"\"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}Assessment Summary:${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Total findings collected: ${COLOR_CYAN}$total_findings${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Risk distribution: ${COLOR_RED}$high_count HIGH${COLOR_RESET}, ${COLOR_YELLOW}$medium_count MEDIUM${COLOR_RESET}, ${COLOR_GREEN}$low_count LOW${COLOR_RESET}, ${COLOR_BLUE}$info_count INFO${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Total execution time: ${COLOR_CYAN}${total_time}s${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Modules analyzed: ${COLOR_CYAN}9/9 completed${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Computer: ${COLOR_CYAN}$(scutil --get ComputerName 2>/dev/null || hostname)${COLOR_RESET}"
    
    
    echo \"\"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}Generated Reports:${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Technician report: ${COLOR_CYAN}$(ls $OUTPUT_PATH/*_technician_report.md 2>/dev/null | head -1 | sed 's|.*/||')${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Raw data export: ${COLOR_CYAN}$(ls $OUTPUT_PATH/*_raw_data.json 2>/dev/null | head -1 | sed 's|.*/||')${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Execution log: ${COLOR_CYAN}$(ls $OUTPUT_PATH/logs/*_audit.log 2>/dev/null | head -1 | sed 's|.*/||')${COLOR_RESET}"
    echo -e "  ${COLOR_WHITE}• Report location: ${COLOR_CYAN}$OUTPUT_PATH${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}================================================${COLOR_RESET}"
}

# Execute main function
main "$@"
