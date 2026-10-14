<#
.SYNOPSIS
    Dredge Collection Script — Windows Endpoint Security Auditor
.DESCRIPTION
    Collects comprehensive security-relevant data from a Windows machine
    (Desktop or Server, 2010+). Outputs a single JSON file for analysis
    by the Dredge Python analysis engine.
.PARAMETER OutputPath
    Directory to write the collection JSON. Default: current directory.
.PARAMETER Skip
    Section names to skip. Valid: system_info, updates, installed_software,
    network_config, open_ports, active_connections, firewall, processes,
    services, scheduled_tasks, user_accounts, security_policy,
    registry_hardening, active_directory, certificates, shares,
    browser_chrome, browser_edge, browser_firefox, server_software,
    remote_management, cloud_software, event_logs, startup_items,
    bitlocker, windows_backup, credential_exposure, privilege_escalation,
    defender_detailed, adcs, persistence_mechanisms, powershell_config,
    laps_config, print_config, dns_config, privacy_artifacts,
    disk_storage, hardware_inventory
.PARAMETER Quiet
    Suppress progress output.
.PARAMETER NoHash
    Skip SHA256 hashing of process executables (faster collection).
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".",
    [string[]]$Skip = @(),
    [switch]$Quiet,
    [switch]$NoHash
)

$ErrorActionPreference = "Continue"
$DredgeVersion = "1.3.3"
$StartTime = Get-Date
$Hostname = $env:COMPUTERNAME
$OutputFile = Join-Path $OutputPath ("dredge_collection_{0}_{1}.json" -f $Hostname, (Get-Date -Format "yyyyMMdd_HHmmss"))

$SectionsCollected = New-Object System.Collections.ArrayList
$SectionsSkipped   = New-Object System.Collections.ArrayList
$SectionsFailed    = New-Object System.Collections.ArrayList
$SectionErrors     = New-Object System.Collections.ArrayList
$Result = [ordered]@{}

$AllSections = @(
    "system_info","updates","installed_software","network_config",
    "open_ports","active_connections","firewall","processes","services",
    "scheduled_tasks","user_accounts","security_policy","registry_hardening",
    "active_directory","certificates","shares","browser_chrome","browser_edge",
    "browser_firefox","server_software","remote_management","cloud_software",
    "event_logs","startup_items","bitlocker","windows_backup",
    "credential_exposure","privilege_escalation","defender_detailed","adcs",
    "persistence_mechanisms","powershell_config","laps_config","print_config",
    "dns_config","privacy_artifacts",
    "disk_storage","hardware_inventory"
)
$TotalSections = $AllSections.Count

function Write-Progress-Step {
    param([string]$Section, [int]$Index)
    if (-not $Quiet) {
        $pct = [math]::Round(($Index / $TotalSections) * 100)
        Write-Host ("[{0:HH:mm:ss}] [{1,3}%] Collecting: {2}" -f (Get-Date), $pct, $Section)
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) { return $item.$Name }
    } catch {}
    return $null
}

function Get-RegValues {
    param([string]$Path, [string[]]$Names)
    $out = [ordered]@{}
    foreach ($n in $Names) {
        $out[$n] = Get-RegValue -Path $Path -Name $n
    }
    return $out
}

function Safe-ToISO {
    param($dt)
    if ($null -eq $dt) { return $null }
    try { return ([datetime]$dt).ToString("o") } catch { return $dt.ToString() }
}

# ═══════════════════════════════════════════════════════════════
# Section 1: System Information
# ═══════════════════════════════════════════════════════════════
function Collect-SystemInfo {
    $data = [ordered]@{}
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

    $data["os_name"]         = $os.Caption
    $data["os_version"]      = $os.Version
    $data["os_build"]        = $os.BuildNumber
    $data["os_architecture"] = $os.OSArchitecture
    $data["os_install_date"] = Safe-ToISO $os.InstallDate
    $data["os_last_boot"]    = Safe-ToISO $os.LastBootUpTime
    $data["os_serial"]       = $os.SerialNumber
    $data["os_product_type"] = switch ($os.ProductType) { 1 {"Workstation"} 2 {"Domain Controller"} 3 {"Server"} default {$os.ProductType} }
    $data["os_suite_mask"]   = $os.SuiteMask

    $data["hostname"]         = $cs.Name
    $data["domain"]           = $cs.Domain
    $data["domain_role"]      = switch ($cs.DomainRole) { 0{"Standalone Workstation"} 1{"Member Workstation"} 2{"Standalone Server"} 3{"Member Server"} 4{"Backup DC"} 5{"Primary DC"} default{$cs.DomainRole} }
    $data["is_domain_joined"] = ($cs.PartOfDomain -eq $true)
    $data["manufacturer"]     = $cs.Manufacturer
    $data["model"]            = $cs.Model
    $data["total_ram_gb"]     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $data["number_of_processors"]      = $cs.NumberOfProcessors
    $data["number_of_logical_processors"] = $cs.NumberOfLogicalProcessors
    $data["current_user"]     = $env:USERNAME
    $data["system_directory"] = $os.SystemDirectory

    $data["bios_manufacturer"] = $bios.Manufacturer
    $data["bios_version"]      = $bios.SMBIOSBIOSVersion
    $data["bios_release_date"] = Safe-ToISO $bios.ReleaseDate
    $data["bios_serial"]       = $bios.SerialNumber

    $data["cpu_name"]  = $cpu.Name
    $data["cpu_cores"] = $cpu.NumberOfCores
    $data["cpu_logical"] = $cpu.NumberOfLogicalProcessors

    $now = Get-Date
    $uptime = $now - $os.LastBootUpTime
    $data["uptime_days"]    = [math]::Round($uptime.TotalDays, 2)
    $data["uptime_hours"]   = [math]::Round($uptime.TotalHours, 2)

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $data["tpm_present"]   = $tpm.TpmPresent
        $data["tpm_ready"]     = $tpm.TpmReady
        $data["tpm_enabled"]   = $tpm.TpmEnabled
        $data["tpm_activated"] = $tpm.TpmActivated
    } catch {
        $data["tpm_present"] = $null
        $data["tpm_error"]   = "Get-Tpm not available"
    }

    try {
        $tz = Get-TimeZone
        $data["timezone"]        = $tz.Id
        $data["timezone_offset"] = $tz.BaseUtcOffset.ToString()
    } catch {}

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 2: Windows Update
# ═══════════════════════════════════════════════════════════════
function Collect-WindowsUpdate {
    $data = [ordered]@{}

    # Update service status
    try {
        $svc = Get-Service wuauserv -ErrorAction SilentlyContinue
        $data["update_service_status"]   = if ($svc) { $svc.Status.ToString() } else { "Not Found" }
        $data["update_service_start_type"] = if ($svc) { $svc.StartType.ToString() } else { "N/A" }
    } catch {
        $data["update_service_status"] = "Error"
    }

    # WSUS configuration
    $wsusPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $data["wsus_server"]       = Get-RegValue $wsusPath "WUServer"
    $data["wsus_status_server"] = Get-RegValue $wsusPath "WUStatusServer"
    $data["wsus_use_policy"]   = Get-RegValue "$wsusPath\AU" "UseWUServer"
    $data["auto_update_option"] = Get-RegValue "$wsusPath\AU" "AUOptions"

    # Update history via COM
    $history = @()
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        $maxEntries = [math]::Min($count, 200)
        if ($maxEntries -gt 0) {
            $entries = $searcher.QueryHistory(0, $maxEntries)
            foreach ($entry in $entries) {
                $history += [ordered]@{
                    title       = $entry.Title
                    date        = Safe-ToISO $entry.Date
                    result_code = switch ($entry.ResultCode) { 0{"NotStarted"} 1{"InProgress"} 2{"Succeeded"} 3{"SucceededWithErrors"} 4{"Failed"} 5{"Aborted"} default{$entry.ResultCode} }
                    operation   = switch ($entry.Operation) { 1{"Installation"} 2{"Uninstallation"} default{$entry.Operation} }
                    kb          = if ($entry.Title -match 'KB(\d+)') { "KB$($Matches[1])" } else { "" }
                }
            }
        }
    } catch {
        $data["history_error"] = $_.Exception.Message
    }
    $data["update_history"] = $history
    $data["total_updates_installed"] = $history.Count

    # Last update date
    if ($history.Count -gt 0) {
        $successful = $history | Where-Object { $_.result_code -eq "Succeeded" } | Select-Object -First 1
        $data["last_successful_update"] = if ($successful) { $successful.date } else { $null }
    }

    # Pending updates
    $pending = @()
    try {
        $session2 = New-Object -ComObject Microsoft.Update.Session
        $searcher2 = $session2.CreateUpdateSearcher()
        $searchResult = $searcher2.Search("IsInstalled=0")
        foreach ($update in $searchResult.Updates) {
            $pending += [ordered]@{
                title        = $update.Title
                severity     = $update.MsrcSeverity
                is_mandatory = $update.IsMandatory
                kb           = if ($update.Title -match 'KB(\d+)') { "KB$($Matches[1])" } else { "" }
            }
        }
    } catch {
        $data["pending_error"] = $_.Exception.Message
    }
    $data["pending_updates"] = $pending
    $data["pending_count"]   = $pending.Count

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 3: Installed Software
# ═══════════════════════════════════════════════════════════════
function Collect-InstalledSoftware {
    $software = @()
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($path in $paths) {
        try {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" }
            foreach ($item in $items) {
                $software += [ordered]@{
                    name           = $item.DisplayName
                    version        = $item.DisplayVersion
                    publisher      = $item.Publisher
                    install_date   = $item.InstallDate
                    install_location = $item.InstallLocation
                    uninstall_string = $item.UninstallString
                    registry_path  = $path -replace '\\\*$',''
                }
            }
        } catch {}
    }
    # Deduplicate by name+version
    $seen = @{}
    $unique = @()
    foreach ($s in $software) {
        $key = "$($s.name)|$($s.version)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $unique += $s
        }
    }
    return $unique | Sort-Object { $_.name }
}

# ═══════════════════════════════════════════════════════════════
# Section 4: Network Configuration
# ═══════════════════════════════════════════════════════════════
function Collect-NetworkConfig {
    $data = [ordered]@{}

    # Adapters
    $adapters = @()
    try {
        $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
        foreach ($a in $netAdapters) {
            $adapters += [ordered]@{
                name            = $a.Name
                description     = $a.InterfaceDescription
                status          = $a.Status
                mac_address     = $a.MacAddress
                link_speed      = $a.LinkSpeed
                interface_index = $a.InterfaceIndex
                media_type      = $a.MediaType
            }
        }
    } catch {}
    $data["adapters"] = $adapters

    # IP addresses
    $ips = @()
    try {
        $addresses = Get-NetIPAddress -ErrorAction SilentlyContinue
        foreach ($ip in $addresses) {
            $ips += [ordered]@{
                ip_address      = $ip.IPAddress
                prefix_length   = $ip.PrefixLength
                address_family  = $ip.AddressFamily.ToString()
                interface_alias = $ip.InterfaceAlias
                type            = $ip.Type
            }
        }
    } catch {}
    $data["ip_addresses"] = $ips

    # DNS servers
    $dns = @()
    try {
        $dnsServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
                      Where-Object { $_.ServerAddresses.Count -gt 0 }
        foreach ($d in $dnsServers) {
            $dns += [ordered]@{
                interface_alias = $d.InterfaceAlias
                address_family  = $d.AddressFamily
                server_addresses = $d.ServerAddresses
            }
        }
    } catch {}
    $data["dns_servers"] = $dns

    # Routes
    $routes = @()
    try {
        $netRoutes = Get-NetRoute -ErrorAction SilentlyContinue |
                     Where-Object { $_.DestinationPrefix -ne "ff00::/8" }
        foreach ($r in $netRoutes) {
            $routes += [ordered]@{
                destination    = $r.DestinationPrefix
                next_hop       = $r.NextHop
                interface_alias = $r.InterfaceAlias
                route_metric   = $r.RouteMetric
            }
        }
    } catch {}
    $data["routes"] = $routes

    # ARP table
    $arp = @()
    try {
        $neighbors = Get-NetNeighbor -ErrorAction SilentlyContinue |
                     Where-Object { $_.State -ne "Unreachable" }
        foreach ($n in $neighbors) {
            $arp += [ordered]@{
                ip_address      = $n.IPAddress
                link_layer_addr = $n.LinkLayerAddress
                state           = $n.State.ToString()
                interface_alias = $n.InterfaceAlias
            }
        }
    } catch {}
    $data["arp_table"] = $arp

    # System proxy
    $proxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $data["proxy_enabled"] = Get-RegValue $proxyPath "ProxyEnable"
    $data["proxy_server"]  = Get-RegValue $proxyPath "ProxyServer"
    $data["proxy_override"] = Get-RegValue $proxyPath "ProxyOverride"
    $data["auto_config_url"] = Get-RegValue $proxyPath "AutoConfigURL"

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 5: Open Ports
# ═══════════════════════════════════════════════════════════════
function Collect-OpenPorts {
    $ports = @()

    # TCP listeners
    try {
        $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        $procCache = @{}
        foreach ($c in $tcpConns) {
            $pid = $c.OwningProcess
            if (-not $procCache.ContainsKey($pid)) {
                try {
                    $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    $procCache[$pid] = if ($p) { $p.ProcessName } else { "Unknown" }
                } catch { $procCache[$pid] = "Unknown" }
            }
            $ports += [ordered]@{
                protocol      = "TCP"
                local_address = $c.LocalAddress
                local_port    = $c.LocalPort
                state         = "Listen"
                process_id    = $pid
                process_name  = $procCache[$pid]
            }
        }
    } catch {}

    # UDP listeners
    try {
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        foreach ($u in $udpEndpoints) {
            $pid = $u.OwningProcess
            if (-not $procCache.ContainsKey($pid)) {
                try {
                    $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    $procCache[$pid] = if ($p) { $p.ProcessName } else { "Unknown" }
                } catch { $procCache[$pid] = "Unknown" }
            }
            $ports += [ordered]@{
                protocol      = "UDP"
                local_address = $u.LocalAddress
                local_port    = $u.LocalPort
                state         = "Listening"
                process_id    = $pid
                process_name  = $procCache[$pid]
            }
        }
    } catch {}

    return $ports
}

# ═══════════════════════════════════════════════════════════════
# Section 6: Active Connections
# ═══════════════════════════════════════════════════════════════
function Collect-ActiveConnections {
    $conns = @()
    try {
        $established = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $established) {
            $pName = "Unknown"
            try {
                $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                if ($p) { $pName = $p.ProcessName }
            } catch {}
            $conns += [ordered]@{
                local_address   = $c.LocalAddress
                local_port      = $c.LocalPort
                remote_address  = $c.RemoteAddress
                remote_port     = $c.RemotePort
                state           = "Established"
                process_id      = $c.OwningProcess
                process_name    = $pName
                creation_time   = Safe-ToISO $c.CreationTime
            }
        }
    } catch {}
    return $conns
}

# ═══════════════════════════════════════════════════════════════
# Section 7: Firewall
# ═══════════════════════════════════════════════════════════════
function Collect-Firewall {
    $data = [ordered]@{}

    # Profiles
    $profiles = @()
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($fp in $fwProfiles) {
            $profiles += [ordered]@{
                name                = $fp.Name
                enabled             = $fp.Enabled
                default_inbound     = $fp.DefaultInboundAction.ToString()
                default_outbound    = $fp.DefaultOutboundAction.ToString()
                allow_unicast_response = $fp.AllowUnicastResponseToMulticast
                log_allowed         = $fp.LogAllowed
                log_blocked         = $fp.LogBlocked
                log_file_name       = $fp.LogFileName
                log_max_size_kb     = $fp.LogMaxSizeKilobytes
            }
        }
    } catch {}
    $data["profiles"] = $profiles

    # Rules (all of them)
    $rules = @()
    try {
        $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        foreach ($r in $fwRules) {
            $portFilter = $null
            $addrFilter = $null
            $appFilter  = $null
            try { $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue } catch {}
            try { $addrFilter = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue } catch {}
            try { $appFilter  = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue } catch {}

            $rules += [ordered]@{
                name            = $r.DisplayName
                enabled         = $r.Enabled.ToString()
                direction       = $r.Direction.ToString()
                action          = $r.Action.ToString()
                profile         = $r.Profile.ToString()
                protocol        = if ($portFilter) { $portFilter.Protocol } else { "" }
                local_port      = if ($portFilter) { $portFilter.LocalPort } else { "" }
                remote_port     = if ($portFilter) { $portFilter.RemotePort } else { "" }
                remote_address  = if ($addrFilter) { $addrFilter.RemoteAddress -join "," } else { "" }
                local_address   = if ($addrFilter) { $addrFilter.LocalAddress -join "," } else { "" }
                program         = if ($appFilter) { $appFilter.Program } else { "" }
            }
        }
    } catch {}
    $data["rules"] = $rules
    $data["total_rules"] = $rules.Count

    # Recent firewall log entries (parse last 100 lines if log exists)
    $logEntries = @()
    foreach ($prof in $profiles) {
        $logFile = $prof.log_file_name
        if ($logFile -and (Test-Path $logFile -ErrorAction SilentlyContinue)) {
            try {
                $lines = Get-Content $logFile -Tail 100 -ErrorAction SilentlyContinue |
                         Where-Object { $_ -and $_ -notmatch '^#' }
                foreach ($line in $lines) {
                    $parts = $line -split '\s+'
                    if ($parts.Count -ge 8) {
                        $logEntries += [ordered]@{
                            date       = $parts[0]
                            time       = $parts[1]
                            action     = $parts[2]
                            protocol   = $parts[3]
                            src_ip     = $parts[4]
                            dst_ip     = $parts[5]
                            src_port   = $parts[6]
                            dst_port   = $parts[7]
                        }
                    }
                }
            } catch {}
        }
    }
    $data["recent_log_entries"] = $logEntries

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 8: Processes
# ═══════════════════════════════════════════════════════════════
function Collect-Processes {
    $procs = @()
    try {
        $wmiProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($wp in $wmiProcs) {
            $owner = $null
            try {
                $ownerInfo = Invoke-CimMethod -InputObject $wp -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($ownerInfo -and $ownerInfo.User) {
                    $owner = if ($ownerInfo.Domain) { "$($ownerInfo.Domain)\$($ownerInfo.User)" } else { $ownerInfo.User }
                }
            } catch {}

            $hash = $null
            if (-not $NoHash -and $wp.ExecutablePath -and (Test-Path $wp.ExecutablePath -ErrorAction SilentlyContinue)) {
                try {
                    $hash = (Get-FileHash -Path $wp.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                } catch {}
            }

            $procs += [ordered]@{
                pid             = $wp.ProcessId
                name            = $wp.Name
                path            = $wp.ExecutablePath
                command_line    = $wp.CommandLine
                parent_pid      = $wp.ParentProcessId
                owner           = $owner
                creation_date   = Safe-ToISO $wp.CreationDate
                working_set_kb  = [math]::Round($wp.WorkingSetSize / 1KB, 0)
                sha256          = $hash
            }
        }
    } catch {}
    return $procs
}

# ═══════════════════════════════════════════════════════════════
# Section 9: Services
# ═══════════════════════════════════════════════════════════════
function Collect-Services {
    $svcs = @()
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($s in $services) {
            $svcs += [ordered]@{
                name          = $s.Name
                display_name  = $s.DisplayName
                state         = $s.State
                start_mode    = $s.StartMode
                service_type  = $s.ServiceType
                start_name    = $s.StartName
                path_name     = $s.PathName
                description   = $s.Description
                process_id    = $s.ProcessId
            }
        }
    } catch {}
    return $svcs
}

# ═══════════════════════════════════════════════════════════════
# Section 10: Scheduled Tasks
# ═══════════════════════════════════════════════════════════════
function Collect-ScheduledTasks {
    $tasks = @()
    try {
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                    Where-Object { $_.TaskPath -notmatch '\\Microsoft\\Windows\\' -or $_.State -eq 'Ready' -or $_.State -eq 'Running' }
        foreach ($t in $allTasks) {
            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue } catch {}

            $actions = @()
            foreach ($a in $t.Actions) {
                $actions += [ordered]@{
                    type      = $a.CimClass.CimClassName
                    execute   = $a.Execute
                    arguments = $a.Arguments
                    working_dir = $a.WorkingDirectory
                }
            }
            $triggers = @()
            foreach ($tr in $t.Triggers) {
                $triggers += [ordered]@{
                    type     = $tr.CimClass.CimClassName
                    enabled  = $tr.Enabled
                }
            }
            $tasks += [ordered]@{
                task_name     = $t.TaskName
                task_path     = $t.TaskPath
                state         = $t.State.ToString()
                actions       = $actions
                triggers      = $triggers
                principal_user = $t.Principal.UserId
                run_level     = $t.Principal.RunLevel.ToString()
                last_run_time = if ($info) { Safe-ToISO $info.LastRunTime } else { $null }
                next_run_time = if ($info) { Safe-ToISO $info.NextRunTime } else { $null }
                last_result   = if ($info) { $info.LastTaskResult } else { $null }
            }
        }
    } catch {}
    return $tasks
}

# ═══════════════════════════════════════════════════════════════
# Section 11: User Accounts
# ═══════════════════════════════════════════════════════════════
function Collect-UserAccounts {
    $data = [ordered]@{}

    # Local users
    $users = @()
    try {
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($u in $localUsers) {
            $users += [ordered]@{
                name                  = $u.Name
                enabled               = $u.Enabled
                description           = $u.Description
                full_name             = $u.FullName
                password_changeable   = $u.PasswordChangeableDate
                password_expires      = Safe-ToISO $u.PasswordExpires
                password_last_set     = Safe-ToISO $u.PasswordLastSet
                last_logon            = Safe-ToISO $u.LastLogon
                user_may_change_password = $u.UserMayChangePassword
                password_required     = $u.PasswordRequired
                password_never_expires = ($null -eq $u.PasswordExpires)
                account_source        = $u.PrincipalSource.ToString()
                sid                   = $u.SID.Value
            }
        }
    } catch {}
    $data["local_users"] = $users

    # Local groups
    $groups = @()
    try {
        $localGroups = Get-LocalGroup -ErrorAction SilentlyContinue
        foreach ($g in $localGroups) {
            $members = @()
            try {
                $grpMembers = Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue
                foreach ($m in $grpMembers) {
                    $members += [ordered]@{
                        name            = $m.Name
                        object_class    = $m.ObjectClass
                        principal_source = $m.PrincipalSource.ToString()
                        sid             = $m.SID.Value
                    }
                }
            } catch {}
            $groups += [ordered]@{
                name        = $g.Name
                description = $g.Description
                sid         = $g.SID.Value
                members     = $members
            }
        }
    } catch {}
    $data["local_groups"] = $groups

    # Password policy via net accounts
    try {
        $netAccounts = net accounts 2>&1
        $policy = [ordered]@{}
        foreach ($line in $netAccounts) {
            if ($line -match '^\s*(.+?):\s+(.+)$') {
                $key = $Matches[1].Trim() -replace '\s+','_' -replace '[^a-zA-Z0-9_]',''
                $policy[$key.ToLower()] = $Matches[2].Trim()
            }
        }
        $data["password_policy"] = $policy
    } catch {
        $data["password_policy"] = @{}
    }

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 12: Security Policy
# ═══════════════════════════════════════════════════════════════
function Collect-SecurityPolicy {
    $data = [ordered]@{}

    # Audit policy
    $auditPolicy = @()
    try {
        $auditOutput = auditpol /get /category:* 2>&1
        $currentCategory = ""
        foreach ($line in $auditOutput) {
            if ($line -match '^\s{2}(\S.+)$' -and $line -notmatch 'Setting') {
                $currentCategory = $Matches[1].Trim()
            }
            elseif ($line -match '^\s{4}(.+?)\s{2,}(.+)$') {
                $auditPolicy += [ordered]@{
                    category    = $currentCategory
                    subcategory = $Matches[1].Trim()
                    setting     = $Matches[2].Trim()
                }
            }
        }
    } catch {}
    $data["audit_policy"] = $auditPolicy

    # Security options via secedit export
    $securityOptions = [ordered]@{}
    $tempInf = Join-Path $env:TEMP "dredge_secedit_$((Get-Date).Ticks).inf"
    try {
        $null = secedit /export /cfg $tempInf /quiet 2>&1
        if (Test-Path $tempInf) {
            $content = Get-Content $tempInf -ErrorAction SilentlyContinue
            $section = ""
            foreach ($line in $content) {
                if ($line -match '^\[(.+)\]$') {
                    $section = $Matches[1]
                }
                elseif ($line -match '^(.+?)\s*=\s*(.+)$' -and $section) {
                    $key = "$section`_$($Matches[1].Trim())" -replace '\s+','_'
                    $securityOptions[$key] = $Matches[2].Trim()
                }
            }
            Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
        }
    } catch {
        $data["secedit_error"] = $_.Exception.Message
    }
    $data["security_options"] = $securityOptions

    # User rights assignments (from the secedit export)
    $userRights = [ordered]@{}
    foreach ($key in $securityOptions.Keys) {
        if ($key -match '^Privilege_Rights_') {
            $rightName = $key -replace '^Privilege_Rights_',''
            $userRights[$rightName] = $securityOptions[$key]
        }
    }
    $data["user_rights_assignments"] = $userRights

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 13: Registry Hardening
# ═══════════════════════════════════════════════════════════════
function Collect-RegistryHardening {
    $data = [ordered]@{}

    # UAC
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $data["uac"] = Get-RegValues $uacPath @(
        "EnableLUA","ConsentPromptBehaviorAdmin","ConsentPromptBehaviorUser",
        "EnableInstallerDetection","EnableSecureUIAPaths","EnableVirtualization",
        "PromptOnSecureDesktop","FilterAdministratorToken"
    )

    # SMB
    $smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $data["smb_server"] = Get-RegValues $smbServerPath @(
        "SMB1","RequireSecuritySignature","EnableSecuritySignature",
        "AutoShareServer","AutoShareWks","NullSessionPipes","NullSessionShares",
        "RestrictNullSessAccess"
    )
    $smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $data["smb_client"] = Get-RegValues $smbClientPath @(
        "RequireSecuritySignature","EnableSecuritySignature","EnablePlainTextPassword"
    )
    # SMBv1 via feature
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $data["smb1_feature_state"] = if ($smb1Feature) { $smb1Feature.State.ToString() } else { "Unknown" }
    } catch {
        $data["smb1_feature_state"] = "Check unavailable"
    }

    # NTLM / LM
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Lsa"
    $data["lsa"] = Get-RegValues $lsaPath @(
        "LmCompatibilityLevel","NoLMHash","RestrictAnonymous",
        "RestrictAnonymousSAM","EveryoneIncludesAnonymous","ForceGuest",
        "RunAsPPL","DisableDomainCreds"
    )
    $lsaControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $data["lsa_control"] = Get-RegValues $lsaControlPath @(
        "LmCompatibilityLevel","NoLMHash","RunAsPPL",
        "DisableDomainCreds","RestrictAnonymous","RestrictAnonymousSAM"
    )

    # WDigest
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $data["wdigest_uselogoncredential"] = Get-RegValue $wdigestPath "UseLogonCredential"

    # Credential Guard / Device Guard
    $dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $data["device_guard"] = Get-RegValues $dgPath @(
        "EnableVirtualizationBasedSecurity","RequirePlatformSecurityFeatures",
        "Locked","ConfigureSystemGuardLaunch"
    )
    $lsaCfg = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
    $data["credential_guard_config"] = Get-RegValue $lsaCfg "LsaCfgFlags"

    # AutoRun
    $explorerPolicies = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $data["autorun"] = [ordered]@{
        NoDriveTypeAutoRun = Get-RegValue $explorerPolicies "NoDriveTypeAutoRun"
        NoAutorun          = Get-RegValue $explorerPolicies "NoAutorun"
    }

    # PowerShell logging
    $psLogBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    $data["powershell_logging"] = [ordered]@{
        script_block_logging   = Get-RegValue "$psLogBase\ScriptBlockLogging" "EnableScriptBlockLogging"
        script_block_invocation = Get-RegValue "$psLogBase\ScriptBlockLogging" "EnableScriptBlockInvocationLogging"
        module_logging         = Get-RegValue "$psLogBase\ModuleLogging" "EnableModuleLogging"
        transcription          = Get-RegValue "$psLogBase\Transcription" "EnableTranscripting"
        transcription_dir      = Get-RegValue "$psLogBase\Transcription" "OutputDirectory"
    }
    # PowerShell v2 engine
    try {
        $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
        $data["powershell_v2_state"] = if ($psv2) { $psv2.State.ToString() } else { "Unknown" }
    } catch {
        $data["powershell_v2_state"] = "Check unavailable"
    }

    # LLMNR
    $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    $data["llmnr_enabled"] = Get-RegValue $dnsClientPath "EnableMulticast"

    # NetBIOS
    $netbiosEntries = @()
    try {
        $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
        foreach ($nic in $nics) {
            $netbiosEntries += [ordered]@{
                description   = $nic.Description
                tcpip_netbios = switch ($nic.TcpipNetbiosOptions) { 0{"Default"} 1{"Enabled"} 2{"Disabled"} default{$nic.TcpipNetbiosOptions} }
            }
        }
    } catch {}
    $data["netbios_settings"] = $netbiosEntries

    # WPAD
    $data["wpad_service_start"] = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" "Start"

    # DEP
    try {
        $depOutput = bcdedit /enum "{current}" 2>&1
        $nxLine = $depOutput | Select-String "nx\s+"
        $data["dep_nx_policy"] = if ($nxLine) { ($nxLine -replace '.*nx\s+','').Trim() } else { "Unknown" }
    } catch {
        $data["dep_nx_policy"] = "Error reading bcdedit"
    }

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        $data["secure_boot_enabled"] = $sb
    } catch {
        $data["secure_boot_enabled"] = $null
        $data["secure_boot_note"]    = "Confirm-SecureBootUEFI not available or not UEFI"
    }

    # ASLR / DEP system-wide
    $memMgmt = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $data["memory_management"] = Get-RegValues $memMgmt @(
        "MoveImages","FeatureSettingsOverride","FeatureSettingsOverrideMask"
    )

    # Windows Defender
    $data["defender"] = [ordered]@{}
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $data["defender"]["antivirus_enabled"]        = $mpStatus.AntivirusEnabled
        $data["defender"]["real_time_protection"]      = $mpStatus.RealTimeProtectionEnabled
        $data["defender"]["behavior_monitor"]          = $mpStatus.BehaviorMonitorEnabled
        $data["defender"]["ioav_protection"]            = $mpStatus.IoavProtectionEnabled
        $data["defender"]["antispyware_enabled"]        = $mpStatus.AntispywareEnabled
        $data["defender"]["tamper_protection"]          = $mpStatus.IsTamperProtected
        $data["defender"]["signature_version"]          = $mpStatus.AntivirusSignatureVersion
        $data["defender"]["signature_last_updated"]     = Safe-ToISO $mpStatus.AntivirusSignatureLastUpdated
        $data["defender"]["full_scan_age_days"]         = $mpStatus.FullScanAge
        $data["defender"]["quick_scan_age_days"]        = $mpStatus.QuickScanAge
        $data["defender"]["nis_enabled"]                = $mpStatus.NISEnabled

        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mpPref) {
            $data["defender"]["exclusion_paths"]      = @($mpPref.ExclusionPath)
            $data["defender"]["exclusion_extensions"] = @($mpPref.ExclusionExtension)
            $data["defender"]["exclusion_processes"]  = @($mpPref.ExclusionProcess)
            $data["defender"]["disable_realtime"]     = $mpPref.DisableRealtimeMonitoring
            $data["defender"]["disable_behavior"]     = $mpPref.DisableBehaviorMonitoring
            $data["defender"]["disable_ioav"]         = $mpPref.DisableIOAVProtection
            $data["defender"]["disable_script_scan"]  = $mpPref.DisableScriptScanning
            $data["defender"]["pua_protection"]       = $mpPref.PUAProtection
        }
    } catch {
        $data["defender"]["error"] = "Windows Defender not available: $($_.Exception.Message)"
    }

    # RDP NLA
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $data["rdp_user_authentication"] = Get-RegValue $rdpPath "UserAuthentication"
    $data["rdp_security_layer"]      = Get-RegValue $rdpPath "SecurityLayer"
    $data["rdp_min_encryption"]      = Get-RegValue $rdpPath "MinEncryptionLevel"

    # Remote Desktop enabled
    $tsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $data["rdp_deny_ts_connections"] = Get-RegValue $tsPath "fDenyTSConnections"

    # Speculative execution mitigations
    $data["speculation_control"] = Get-RegValues $memMgmt @(
        "FeatureSettingsOverride","FeatureSettingsOverrideMask"
    )

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 14: Active Directory
# ═══════════════════════════════════════════════════════════════
function Collect-ActiveDirectory {
    $data = [ordered]@{}

    # Check if domain-joined
    if (-not $env:USERDNSDOMAIN -and -not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        $data["status"] = "Not domain-joined"
        return $data
    }
    $data["status"] = "Domain-joined"
    $data["dns_domain"] = $env:USERDNSDOMAIN
    $data["logon_server"] = $env:LOGONSERVER

    # Domain info via .NET
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $data["domain_name"]  = $domain.Name
        $data["domain_mode"]  = $domain.DomainMode.ToString()
        $data["pdc_emulator"] = $domain.PdcRoleOwner.Name

        $dcs = @()
        foreach ($dc in $domain.DomainControllers) {
            $dcs += [ordered]@{
                name      = $dc.Name
                ip        = $dc.IPAddress
                os        = $dc.OSVersion
                site_name = $dc.SiteName
                roles     = @($dc.Roles | ForEach-Object { $_.ToString() })
            }
        }
        $data["domain_controllers"] = $dcs
    } catch {
        $data["domain_error"] = $_.Exception.Message
    }

    # Forest info
    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $data["forest_name"]   = $forest.Name
        $data["forest_mode"]   = $forest.ForestMode.ToString()
        $data["forest_domains"] = @($forest.Domains | ForEach-Object { $_.Name })
        $data["global_catalogs"] = @($forest.GlobalCatalogs | ForEach-Object { $_.Name })
    } catch {
        $data["forest_error"] = $_.Exception.Message
    }

    # Trust relationships
    $trusts = @()
    try {
        $domainTrusts = $domain.GetAllTrustRelationships()
        foreach ($t in $domainTrusts) {
            $trusts += [ordered]@{
                target_name    = $t.TargetName
                trust_type     = $t.TrustType.ToString()
                trust_direction = $t.TrustDirection.ToString()
            }
        }
    } catch {}
    $data["trusts"] = $trusts

    # ADSI searcher helper
    $rootDSE = $null
    $domainDN = $null
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $domainDN = $rootDSE.defaultNamingContext.ToString()
    } catch {
        $data["ldap_error"] = $_.Exception.Message
        return $data
    }

    # Domain password policy
    try {
        $domObj = [ADSI]"LDAP://$domainDN"
        $data["domain_password_policy"] = [ordered]@{
            min_password_length    = $domObj.minPwdLength.Value
            password_history_count = $domObj.pwdHistoryLength.Value
            lockout_threshold      = $domObj.lockoutThreshold.Value
            lockout_duration_min   = if ($domObj.lockoutDuration.Value) { [math]::Abs([long]$domObj.lockoutDuration.Value / 600000000) } else { $null }
            lockout_window_min     = if ($domObj.lockoutObservationWindow.Value) { [math]::Abs([long]$domObj.lockoutObservationWindow.Value / 600000000) } else { $null }
            max_password_age_days  = if ($domObj.maxPwdAge.Value) { [math]::Abs([long]$domObj.maxPwdAge.Value / 864000000000) } else { $null }
            min_password_age_days  = if ($domObj.minPwdAge.Value) { [math]::Abs([long]$domObj.minPwdAge.Value / 864000000000) } else { $null }
            password_complexity    = $domObj.pwdProperties.Value
        }
    } catch {
        $data["password_policy_error"] = $_.Exception.Message
    }

    # Fine-grained password policies
    $fgpps = @()
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://CN=Password Settings Container,CN=System,$domainDN"
        $searcher.Filter = "(objectClass=msDS-PasswordSettings)"
        $searcher.PropertiesToLoad.AddRange(@("cn","msDS-PasswordSettingsPrecedence","msDS-MinimumPasswordLength","msDS-PasswordHistoryLength","msDS-LockoutThreshold","msDS-PSOAppliesTo"))
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $fgpps += [ordered]@{
                name           = $r.Properties["cn"][0]
                precedence     = $r.Properties["msds-passwordsettingsprecedence"][0]
                min_length     = $r.Properties["msds-minimumpasswordlength"][0]
                history_count  = $r.Properties["msds-passwordhistorylength"][0]
                lockout_threshold = $r.Properties["msds-lockoutthreshold"][0]
                applies_to     = @($r.Properties["msds-psoappliesTo"])
            }
        }
    } catch {}
    $data["fine_grained_password_policies"] = $fgpps

    # User enumeration (security-relevant attributes)
    $adUsers = @()
    try {
        $userSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $userSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $userSearcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        $userSearcher.PropertiesToLoad.AddRange(@(
            "sAMAccountName","userAccountControl","adminCount",
            "servicePrincipalName","lastLogonTimestamp","pwdLastSet",
            "memberOf","msDS-AllowedToDelegateTo","userPrincipalName",
            "whenCreated","description"
        ))
        $userSearcher.PageSize = 1000
        $userSearcher.SizeLimit = 5000
        $userResults = $userSearcher.FindAll()
        foreach ($ur in $userResults) {
            $props = $ur.Properties
            $uac = [int]$props["useraccountcontrol"][0]
            $enabled = -not ($uac -band 0x2)
            $pwdNeverExpires = [bool]($uac -band 0x10000)
            $noPreAuth = [bool]($uac -band 0x400000)
            $trustedForDeleg = [bool]($uac -band 0x80000)

            $lastLogon = $null
            if ($props["lastlogontimestamp"].Count -gt 0) {
                try { $lastLogon = [datetime]::FromFileTime([long]$props["lastlogontimestamp"][0]).ToString("o") } catch {}
            }
            $pwdLastSet = $null
            if ($props["pwdlastset"].Count -gt 0 -and [long]$props["pwdlastset"][0] -gt 0) {
                try { $pwdLastSet = [datetime]::FromFileTime([long]$props["pwdlastset"][0]).ToString("o") } catch {}
            }

            $spns = @($props["serviceprincipalname"])
            $delegateTo = @($props["msds-allowedtodelegateto"])

            $adUsers += [ordered]@{
                username              = "$($props['samaccountname'][0])"
                enabled               = $enabled
                admin_count           = if ($props["admincount"].Count -gt 0) { $props["admincount"][0] } else { 0 }
                password_never_expires = $pwdNeverExpires
                no_preauth_required   = $noPreAuth
                trusted_for_delegation = $trustedForDeleg
                last_logon            = $lastLogon
                pwd_last_set          = $pwdLastSet
                spn_count             = $spns.Count
                spns                  = if ($spns.Count -le 10) { $spns } else { $spns[0..9] + @("... and $($spns.Count - 10) more") }
                constrained_delegation = $delegateTo
                description           = "$($props['description'])"
                when_created          = "$($props['whencreated'])"
            }
        }
    } catch {
        $data["user_enum_error"] = $_.Exception.Message
    }
    $data["users"] = $adUsers
    $data["total_users"] = $adUsers.Count

    # Kerberoastable accounts (have SPNs, are not machine accounts)
    $kerberoastable = $adUsers | Where-Object { $_.spn_count -gt 0 -and $_.enabled }
    $data["kerberoastable_accounts"] = @($kerberoastable | ForEach-Object { $_.username })
    $data["kerberoastable_count"]    = $kerberoastable.Count

    # AS-REP roastable
    $asrep = $adUsers | Where-Object { $_.no_preauth_required -and $_.enabled }
    $data["asrep_roastable_accounts"] = @($asrep | ForEach-Object { $_.username })
    $data["asrep_roastable_count"]    = $asrep.Count

    # Unconstrained delegation
    $unconstrained = $adUsers | Where-Object { $_.trusted_for_delegation -and $_.enabled }
    $data["unconstrained_delegation_accounts"] = @($unconstrained | ForEach-Object { $_.username })

    # Key group memberships
    $keyGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators")
    $groupMembers = [ordered]@{}
    foreach ($gName in $keyGroups) {
        try {
            $gSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $gSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
            $gSearcher.Filter = "(&(objectClass=group)(cn=$gName))"
            $gSearcher.PropertiesToLoad.Add("member") | Out-Null
            $gResult = $gSearcher.FindOne()
            if ($gResult) {
                $members = @($gResult.Properties["member"] | ForEach-Object {
                    ($_ -split ',')[0] -replace '^CN=',''
                })
                $groupMembers[$gName] = $members
            }
        } catch {}
    }
    $data["privileged_group_members"] = $groupMembers

    # GPO listing
    $gpos = @()
    try {
        $gpoSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $gpoSearcher.SearchRoot = [ADSI]"LDAP://CN=Policies,CN=System,$domainDN"
        $gpoSearcher.Filter = "(objectClass=groupPolicyContainer)"
        $gpoSearcher.PropertiesToLoad.AddRange(@("displayName","cn","gPCFileSysPath","versionNumber","whenChanged"))
        $gpoSearcher.PageSize = 500
        $gpoResults = $gpoSearcher.FindAll()
        foreach ($g in $gpoResults) {
            $gpos += [ordered]@{
                name         = "$($g.Properties['displayname'])"
                guid         = "$($g.Properties['cn'])"
                path         = "$($g.Properties['gpcfilesyspath'])"
                version      = $g.Properties['versionnumber'][0]
                when_changed = "$($g.Properties['whenchanged'])"
            }
        }
    } catch {}
    $data["gpos"] = $gpos

    # LDAP signing requirement on this machine (relevant if DC)
    $data["ldap_server_integrity"] = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
    $data["ldap_client_integrity"] = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" "LDAPClientIntegrity"

    # LDAP channel binding
    $data["ldap_enforce_channel_binding"] = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding"

    # Kerberos encryption types
    $data["kerberos_supported_encryption"] = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"

    # Print spooler on DC
    try {
        $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
        $data["print_spooler_status"] = if ($spooler) { $spooler.Status.ToString() } else { "Not Found" }
        $data["print_spooler_start_type"] = if ($spooler) { $spooler.StartType.ToString() } else { "N/A" }
    } catch {}

    # OU structure
    $ous = @()
    try {
        $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ouSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $ouSearcher.Filter = "(objectClass=organizationalUnit)"
        $ouSearcher.PropertiesToLoad.AddRange(@("ou","distinguishedName","description"))
        $ouSearcher.PageSize = 1000
        $ouResults = $ouSearcher.FindAll()
        foreach ($o in $ouResults) {
            $ous += [ordered]@{
                name = "$($o.Properties['ou'])"
                dn   = "$($o.Properties['distinguishedname'])"
                description = "$($o.Properties['description'])"
            }
        }
    } catch {}
    $data["organizational_units"] = $ous

    # RBCD (resource-based constrained delegation)
    $rbcdAccounts = @()
    try {
        $rbcdSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $rbcdSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $rbcdSearcher.Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        $rbcdSearcher.PropertiesToLoad.AddRange(@("sAMAccountName","msDS-AllowedToActOnBehalfOfOtherIdentity"))
        $rbcdSearcher.PageSize = 1000
        $rbcdResults = $rbcdSearcher.FindAll()
        foreach ($r in $rbcdResults) {
            $rbcdAccounts += "$($r.Properties['samaccountname'])"
        }
    } catch {}
    $data["rbcd_configured_accounts"] = $rbcdAccounts

    # AdminSDHolder
    $adminSDHolderModified = @()
    try {
        $sdSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $sdSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $sdSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
        $sdSearcher.PropertiesToLoad.AddRange(@("sAMAccountName","memberOf"))
        $sdSearcher.PageSize = 1000
        $sdResults = $sdSearcher.FindAll()
        foreach ($s in $sdResults) {
            $adminSDHolderModified += "$($s.Properties['samaccountname'])"
        }
    } catch {}
    $data["admin_sd_holder_protected_users"] = $adminSDHolderModified

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 15: Certificates
# ═══════════════════════════════════════════════════════════════
function Collect-Certificates {
    $certs = @()
    $stores = @("Cert:\LocalMachine\My","Cert:\LocalMachine\Root","Cert:\LocalMachine\CA",
                "Cert:\CurrentUser\My","Cert:\CurrentUser\Root","Cert:\CurrentUser\CA")
    $now = Get-Date
    foreach ($store in $stores) {
        try {
            $items = Get-ChildItem $store -ErrorAction SilentlyContinue
            foreach ($cert in $items) {
                $isExpired  = $cert.NotAfter -lt $now
                $isExpiring = (-not $isExpired) -and ($cert.NotAfter -lt $now.AddDays(90))
                $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
                $isWeakAlgo   = $cert.SignatureAlgorithm.FriendlyName -match 'SHA1|MD5|MD2'
                $keySize = 0
                try { $keySize = $cert.PublicKey.Key.KeySize } catch {}

                $certs += [ordered]@{
                    store           = $store
                    subject         = $cert.Subject
                    issuer          = $cert.Issuer
                    thumbprint      = $cert.Thumbprint
                    not_before      = Safe-ToISO $cert.NotBefore
                    not_after       = Safe-ToISO $cert.NotAfter
                    serial_number   = $cert.SerialNumber
                    signature_algo  = $cert.SignatureAlgorithm.FriendlyName
                    key_size        = $keySize
                    is_expired      = $isExpired
                    is_expiring_90d = $isExpiring
                    is_self_signed  = $isSelfSigned
                    is_weak_algo    = $isWeakAlgo
                    is_weak_key     = ($keySize -gt 0 -and $keySize -lt 2048)
                    has_private_key = $cert.HasPrivateKey
                }
            }
        } catch {}
    }
    return $certs
}

# ═══════════════════════════════════════════════════════════════
# Section 16: Shares
# ═══════════════════════════════════════════════════════════════
function Collect-Shares {
    $shares = @()
    try {
        $smbShares = Get-SmbShare -ErrorAction SilentlyContinue
        foreach ($s in $smbShares) {
            $access = @()
            try {
                $acl = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
                foreach ($a in $acl) {
                    $access += [ordered]@{
                        account_name  = $a.AccountName
                        access_right  = $a.AccessRight.ToString()
                        access_type   = $a.AccessControlType.ToString()
                    }
                }
            } catch {}
            $shares += [ordered]@{
                name        = $s.Name
                path        = $s.Path
                description = $s.Description
                share_type  = $s.ShareType.ToString()
                special     = $s.Special
                access      = $access
            }
        }
    } catch {}
    return $shares
}

# ═══════════════════════════════════════════════════════════════
# Section 17: Browser — Chrome
# ═══════════════════════════════════════════════════════════════
function Collect-BrowserChrome {
    $data = [ordered]@{}
    $userDirs = @()
    # Check all user profile directories
    $usersRoot = Split-Path $env:USERPROFILE
    try {
        $userFolders = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue
        foreach ($uf in $userFolders) {
            $chromePath = Join-Path $uf.FullName "AppData\Local\Google\Chrome\User Data"
            if (Test-Path $chromePath) { $userDirs += @{user=$uf.Name; path=$chromePath} }
        }
    } catch {}
    # Fallback to current user
    if ($userDirs.Count -eq 0) {
        $cp = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
        if (Test-Path $cp) { $userDirs += @{user=$env:USERNAME; path=$cp} }
    }

    $allExtensions = @()
    $allBookmarks  = @()
    $proxySettings = @()

    foreach ($ud in $userDirs) {
        $basePath = $ud.path
        # Find profiles (Default, Profile 1, etc.)
        $profiles = @("Default") + @(Get-ChildItem $basePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        foreach ($profile in $profiles) {
            $profilePath = Join-Path $basePath $profile
            if (-not (Test-Path $profilePath)) { continue }

            # Extensions
            $extPath = Join-Path $profilePath "Extensions"
            if (Test-Path $extPath) {
                $extDirs = Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue
                foreach ($extDir in $extDirs) {
                    $verDirs = Get-ChildItem $extDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                    if ($verDirs) {
                        $manifest = Join-Path $verDirs.FullName "manifest.json"
                        if (Test-Path $manifest) {
                            try {
                                $mData = Get-Content $manifest -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                                $allExtensions += [ordered]@{
                                    user         = $ud.user
                                    profile      = $profile
                                    browser      = "Chrome"
                                    extension_id = $extDir.Name
                                    name         = $mData.name
                                    version      = $mData.version
                                    description  = $mData.description
                                    permissions  = @($mData.permissions)
                                }
                            } catch {}
                        }
                    }
                }
            }

            # Bookmarks
            $bmFile = Join-Path $profilePath "Bookmarks"
            if (Test-Path $bmFile) {
                try {
                    $bmData = Get-Content $bmFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                    $bmBar = $bmData.roots.bookmark_bar
                    $bmOther = $bmData.roots.other
                    foreach ($root in @($bmBar, $bmOther)) {
                        if ($root -and $root.children) {
                            foreach ($bm in $root.children) {
                                if ($bm.type -eq "url") {
                                    $allBookmarks += [ordered]@{
                                        user    = $ud.user
                                        profile = $profile
                                        browser = "Chrome"
                                        name    = $bm.name
                                        url     = $bm.url
                                    }
                                }
                            }
                        }
                    }
                } catch {}
            }

            # Proxy from Preferences
            $prefsFile = Join-Path $profilePath "Preferences"
            if (Test-Path $prefsFile) {
                try {
                    $prefs = Get-Content $prefsFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                    if ($prefs.proxy) {
                        $proxySettings += [ordered]@{
                            user    = $ud.user
                            profile = $profile
                            browser = "Chrome"
                            mode    = $prefs.proxy.mode
                            server  = $prefs.proxy.server
                            pac_url = $prefs.proxy.pac_url
                        }
                    }
                } catch {}
            }
        }
    }

    $data["extensions"]     = $allExtensions
    $data["bookmarks"]      = $allBookmarks
    $data["proxy_settings"] = $proxySettings
    $data["installed"]      = ($userDirs.Count -gt 0)

    # Chrome version
    try {
        $chromeExe = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
        if (-not (Test-Path $chromeExe)) { $chromeExe = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" }
        if (Test-Path $chromeExe) {
            $data["version"] = (Get-Item $chromeExe).VersionInfo.ProductVersion
        }
    } catch {}

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 18: Browser — Edge
# ═══════════════════════════════════════════════════════════════
function Collect-BrowserEdge {
    $data = [ordered]@{}
    $userDirs = @()
    $usersRoot = Split-Path $env:USERPROFILE
    try {
        $userFolders = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue
        foreach ($uf in $userFolders) {
            $edgePath = Join-Path $uf.FullName "AppData\Local\Microsoft\Edge\User Data"
            if (Test-Path $edgePath) { $userDirs += @{user=$uf.Name; path=$edgePath} }
        }
    } catch {}
    if ($userDirs.Count -eq 0) {
        $ep = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
        if (Test-Path $ep) { $userDirs += @{user=$env:USERNAME; path=$ep} }
    }

    $allExtensions = @()
    $allBookmarks  = @()
    $proxySettings = @()

    foreach ($ud in $userDirs) {
        $basePath = $ud.path
        $profiles = @("Default") + @(Get-ChildItem $basePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        foreach ($profile in $profiles) {
            $profilePath = Join-Path $basePath $profile
            if (-not (Test-Path $profilePath)) { continue }

            $extPath = Join-Path $profilePath "Extensions"
            if (Test-Path $extPath) {
                $extDirs = Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue
                foreach ($extDir in $extDirs) {
                    $verDirs = Get-ChildItem $extDir.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
                    if ($verDirs) {
                        $manifest = Join-Path $verDirs.FullName "manifest.json"
                        if (Test-Path $manifest) {
                            try {
                                $mData = Get-Content $manifest -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                                $allExtensions += [ordered]@{
                                    user=$ud.user; profile=$profile; browser="Edge"
                                    extension_id=$extDir.Name; name=$mData.name
                                    version=$mData.version; description=$mData.description
                                    permissions=@($mData.permissions)
                                }
                            } catch {}
                        }
                    }
                }
            }

            $bmFile = Join-Path $profilePath "Bookmarks"
            if (Test-Path $bmFile) {
                try {
                    $bmData = Get-Content $bmFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                    foreach ($root in @($bmData.roots.bookmark_bar, $bmData.roots.other)) {
                        if ($root -and $root.children) {
                            foreach ($bm in $root.children) {
                                if ($bm.type -eq "url") {
                                    $allBookmarks += [ordered]@{ user=$ud.user; profile=$profile; browser="Edge"; name=$bm.name; url=$bm.url }
                                }
                            }
                        }
                    }
                } catch {}
            }

            $prefsFile = Join-Path $profilePath "Preferences"
            if (Test-Path $prefsFile) {
                try {
                    $prefs = Get-Content $prefsFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                    if ($prefs.proxy) {
                        $proxySettings += [ordered]@{ user=$ud.user; profile=$profile; browser="Edge"; mode=$prefs.proxy.mode; server=$prefs.proxy.server }
                    }
                } catch {}
            }
        }
    }

    $data["extensions"]     = $allExtensions
    $data["bookmarks"]      = $allBookmarks
    $data["proxy_settings"] = $proxySettings
    $data["installed"]      = ($userDirs.Count -gt 0)

    try {
        $edgeExe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        if (-not (Test-Path $edgeExe)) { $edgeExe = "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe" }
        if (Test-Path $edgeExe) { $data["version"] = (Get-Item $edgeExe).VersionInfo.ProductVersion }
    } catch {}

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 19: Browser — Firefox
# ═══════════════════════════════════════════════════════════════
function Collect-BrowserFirefox {
    $data = [ordered]@{}
    $allExtensions = @()
    $allBookmarks  = @()
    $proxySettings = @()

    $usersRoot = Split-Path $env:USERPROFILE
    $userFolders = @()
    try { $userFolders = Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue } catch {}
    if ($userFolders.Count -eq 0) { $userFolders = @(Get-Item $env:USERPROFILE) }

    foreach ($uf in $userFolders) {
        $ffRoot = Join-Path $uf.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (-not (Test-Path $ffRoot)) { continue }
        $ffProfiles = Get-ChildItem $ffRoot -Directory -ErrorAction SilentlyContinue
        foreach ($fp in $ffProfiles) {
            # Extensions
            $extFile = Join-Path $fp.FullName "extensions.json"
            if (Test-Path $extFile) {
                try {
                    $extData = Get-Content $extFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                    foreach ($addon in $extData.addons) {
                        if ($addon.type -eq "extension") {
                            $allExtensions += [ordered]@{
                                user=$uf.Name; profile=$fp.Name; browser="Firefox"
                                extension_id=$addon.id; name=$addon.defaultLocale.name
                                version=$addon.version; description=$addon.defaultLocale.description
                                permissions=@()
                            }
                        }
                    }
                } catch {}
            }

            # Proxy from prefs.js
            $prefsJs = Join-Path $fp.FullName "prefs.js"
            if (Test-Path $prefsJs) {
                try {
                    $prefsContent = Get-Content $prefsJs -ErrorAction SilentlyContinue
                    $proxyType = ($prefsContent | Select-String 'user_pref\("network\.proxy\.type",\s*(\d+)\)').Matches | ForEach-Object { $_.Groups[1].Value }
                    $proxyHttp = ($prefsContent | Select-String 'user_pref\("network\.proxy\.http",\s*"(.+?)"\)').Matches | ForEach-Object { $_.Groups[1].Value }
                    $proxyPort = ($prefsContent | Select-String 'user_pref\("network\.proxy\.http_port",\s*(\d+)\)').Matches | ForEach-Object { $_.Groups[1].Value }
                    $pacUrl    = ($prefsContent | Select-String 'user_pref\("network\.proxy\.autoconfig_url",\s*"(.+?)"\)').Matches | ForEach-Object { $_.Groups[1].Value }
                    if ($proxyType) {
                        $proxySettings += [ordered]@{
                            user=$uf.Name; profile=$fp.Name; browser="Firefox"
                            proxy_type=$proxyType; http_proxy=$proxyHttp; http_port=$proxyPort; pac_url=$pacUrl
                        }
                    }
                } catch {}
            }

            # Bookmarks from backup JSON
            $bmBackupDir = Join-Path $fp.FullName "bookmarkbackups"
            if (Test-Path $bmBackupDir) {
                $latestBm = Get-ChildItem $bmBackupDir -Filter "*.jsonlz4" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                # jsonlz4 requires special decompression; try plain JSON fallback
                $plainBm = Get-ChildItem $bmBackupDir -Filter "*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($plainBm) {
                    try {
                        $bmJson = Get-Content $plainBm.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        function Extract-FFBookmarks($node) {
                            if ($node.type -eq "text/x-moz-place" -and $node.uri) {
                                $allBookmarks += [ordered]@{ user=$uf.Name; profile=$fp.Name; browser="Firefox"; name=$node.title; url=$node.uri }
                            }
                            if ($node.children) { foreach ($c in $node.children) { Extract-FFBookmarks $c } }
                        }
                        Extract-FFBookmarks $bmJson
                    } catch {}
                }
            }
        }
    }

    $data["extensions"]     = $allExtensions
    $data["bookmarks"]      = $allBookmarks
    $data["proxy_settings"] = $proxySettings

    # Firefox version
    try {
        $ffExe = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
        if (-not (Test-Path $ffExe)) { $ffExe = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe" }
        if (Test-Path $ffExe) { $data["version"] = (Get-Item $ffExe).VersionInfo.ProductVersion }
        $data["installed"] = (Test-Path $ffExe)
    } catch { $data["installed"] = $false }

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 20: Server Software
# ═══════════════════════════════════════════════════════════════
function Collect-ServerSoftware {
    $data = [ordered]@{}

    # IIS
    $data["iis"] = [ordered]@{ installed = $false }
    try {
        $w3svc = Get-Service W3SVC -ErrorAction SilentlyContinue
        if ($w3svc) {
            $data["iis"]["installed"] = $true
            $data["iis"]["status"]    = $w3svc.Status.ToString()
            # Try Get-Website if WebAdministration module available
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $sites = Get-Website -ErrorAction SilentlyContinue
                $data["iis"]["sites"] = @($sites | ForEach-Object {
                    [ordered]@{
                        name=$_.Name; state=$_.State; physical_path=$_.physicalPath
                        bindings=@($_.Bindings.Collection | ForEach-Object { "$($_.protocol)/$($_.bindingInformation)" })
                    }
                })
                $pools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
                $data["iis"]["app_pools"] = @($pools | ForEach-Object {
                    [ordered]@{ name=$_.Name; state=$_.State; runtime_version=$_.managedRuntimeVersion; identity=$_.processModel.identityType }
                })
            } catch {
                $data["iis"]["webadmin_unavailable"] = $true
            }
        }
    } catch {}

    # SQL Server
    $data["sql_server"] = [ordered]@{ installed = $false }
    try {
        $sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue
        if ($sqlServices) {
            $data["sql_server"]["installed"] = $true
            $data["sql_server"]["instances"] = @($sqlServices | ForEach-Object {
                [ordered]@{ name=$_.Name; display_name=$_.DisplayName; status=$_.Status.ToString(); start_type=$_.StartType.ToString() }
            })
            # Auth mode from registry
            $sqlInstances = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue
            if ($sqlInstances) {
                foreach ($prop in $sqlInstances.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS') {
                        $loginMode = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($prop.Value)\MSSQLServer" "LoginMode"
                        $data["sql_server"]["login_mode_$($prop.Name)"] = switch ($loginMode) { 1{"Windows"} 2{"Mixed"} default{$loginMode} }
                    }
                }
            }
        }
    } catch {}

    # Exchange
    $data["exchange"] = [ordered]@{ installed = $false }
    try {
        $exchSvc = Get-Service MSExchangeTransport -ErrorAction SilentlyContinue
        if ($exchSvc) {
            $data["exchange"]["installed"] = $true
            $data["exchange"]["transport_status"] = $exchSvc.Status.ToString()
            $exchVersion = Get-RegValue "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup" "MsiProductMajor"
            $data["exchange"]["version_major"] = $exchVersion
        }
    } catch {}

    # Windows Server roles (if Get-WindowsFeature available)
    $roles = @()
    try {
        $features = Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed }
        foreach ($f in $features) {
            $roles += [ordered]@{ name=$f.Name; display_name=$f.DisplayName; feature_type=$f.FeatureType }
        }
    } catch {}
    $data["installed_roles"] = $roles

    # DHCP
    try {
        $dhcp = Get-Service DHCPServer -ErrorAction SilentlyContinue
        $data["dhcp_server"] = if ($dhcp) { [ordered]@{ installed=$true; status=$dhcp.Status.ToString() } } else { [ordered]@{ installed=$false } }
    } catch { $data["dhcp_server"] = [ordered]@{ installed=$false } }

    # DNS
    try {
        $dnsSvc = Get-Service DNS -ErrorAction SilentlyContinue
        $data["dns_server"] = if ($dnsSvc) { [ordered]@{ installed=$true; status=$dnsSvc.Status.ToString() } } else { [ordered]@{ installed=$false } }
    } catch { $data["dns_server"] = [ordered]@{ installed=$false } }

    # Hyper-V
    try {
        $hyperv = Get-Service vmms -ErrorAction SilentlyContinue
        $data["hyperv"] = if ($hyperv) { [ordered]@{ installed=$true; status=$hyperv.Status.ToString() } } else { [ordered]@{ installed=$false } }
    } catch { $data["hyperv"] = [ordered]@{ installed=$false } }

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 21: Remote Management
# ═══════════════════════════════════════════════════════════════
function Collect-RemoteManagement {
    $data = [ordered]@{}

    # RDP
    $tsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $data["rdp"] = [ordered]@{
        enabled            = ((Get-RegValue $tsPath "fDenyTSConnections") -ne 1)
        nla_required       = ((Get-RegValue $rdpTcpPath "UserAuthentication") -eq 1)
        port               = (Get-RegValue $rdpTcpPath "PortNumber")
        security_layer     = Get-RegValue $rdpTcpPath "SecurityLayer"
        min_encryption     = Get-RegValue $rdpTcpPath "MinEncryptionLevel"
    }
    try {
        $termSvc = Get-Service TermService -ErrorAction SilentlyContinue
        $data["rdp"]["service_status"] = if ($termSvc) { $termSvc.Status.ToString() } else { "Not Found" }
    } catch {}

    # WinRM
    $data["winrm"] = [ordered]@{}
    try {
        $winrmSvc = Get-Service WinRM -ErrorAction SilentlyContinue
        $data["winrm"]["service_status"] = if ($winrmSvc) { $winrmSvc.Status.ToString() } else { "Not Found" }
        $data["winrm"]["service_start_type"] = if ($winrmSvc) { $winrmSvc.StartType.ToString() } else { "N/A" }
        if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
            try {
                $winrmConfig = winrm get winrm/config 2>&1
                $data["winrm"]["config_output"] = ($winrmConfig | Out-String).Trim()
            } catch {}
        }
    } catch {}

    # SSH Server
    try {
        $sshd = Get-Service sshd -ErrorAction SilentlyContinue
        $data["ssh_server"] = if ($sshd) { [ordered]@{ installed=$true; status=$sshd.Status.ToString(); start_type=$sshd.StartType.ToString() } }
                              else { [ordered]@{ installed=$false } }
    } catch { $data["ssh_server"] = [ordered]@{ installed=$false } }

    # Remote management tools detection
    $rmtTools = @(
        @{name="TeamViewer";     svc=@("TeamViewer"); proc=@("TeamViewer","TeamViewer_Service")},
        @{name="AnyDesk";        svc=@("AnyDesk");    proc=@("AnyDesk")},
        @{name="LogMeIn";        svc=@("LogMeIn");    proc=@("LogMeIn","LMIGuardianSvc")},
        @{name="ConnectWise";    svc=@("ScreenConnect Client*"); proc=@("ScreenConnect.ClientService","ScreenConnect.WindowsClient")},
        @{name="Splashtop";      svc=@("SplashtopRemoteService"); proc=@("SRService","SRManager")},
        @{name="GoToMyPC";       svc=@("GoToMyPC");   proc=@("g2svc","g2comm")},
        @{name="BeyondTrust";    svc=@("bomaboremote*","BeyondTrust*"); proc=@("bomba","sdcust")},
        @{name="VNC";            svc=@("*vnc*","*VNC*"); proc=@("winvnc","tvnserver","vncserver")},
        @{name="RustDesk";       svc=@("RustDesk");   proc=@("rustdesk")},
        @{name="RemotePC";       svc=@("RPCService"); proc=@("RemotePC","RPCSuite")}
    )

    $detectedRmt = @()
    foreach ($rmt in $rmtTools) {
        $found = $false
        $svcStatus = $null
        $procRunning = $false

        foreach ($svcPattern in $rmt.svc) {
            try {
                $svc = Get-Service -Name $svcPattern -ErrorAction SilentlyContinue
                if ($svc) { $found = $true; $svcStatus = $svc.Status.ToString() }
            } catch {}
        }
        foreach ($procName in $rmt.proc) {
            try {
                $p = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($p) { $found = $true; $procRunning = $true }
            } catch {}
        }

        if ($found) {
            $detectedRmt += [ordered]@{
                name            = $rmt.name
                service_status  = $svcStatus
                process_running = $procRunning
            }
        }
    }
    $data["detected_rmt_tools"] = $detectedRmt

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 22: Cloud Software
# ═══════════════════════════════════════════════════════════════
function Collect-CloudSoftware {
    $data = [ordered]@{}

    $cloudApps = @(
        @{name="OneDrive";           proc=@("OneDrive"); svc=@()},
        @{name="Dropbox";            proc=@("Dropbox");  svc=@("DbxSvc")},
        @{name="Google Drive";       proc=@("GoogleDriveFS"); svc=@()},
        @{name="Box";                proc=@("Box","BoxUI"); svc=@("Box*")},
        @{name="SharePoint Sync";    proc=@("groove");   svc=@()},
        @{name="Azure AD Connect";   proc=@();           svc=@("ADSync")},
        @{name="Azure Arc Agent";    proc=@("himds");    svc=@("himds")},
        @{name="AWS SSM Agent";      proc=@("amazon-ssm-agent"); svc=@("AmazonSSMAgent")},
        @{name="GCP Guest Agent";    proc=@("GCEWindowsAgent"); svc=@("GCEAgent")}
    )

    $detected = @()
    foreach ($app in $cloudApps) {
        $found = $false
        $svcStatus = $null
        $procRunning = $false

        foreach ($svcName in $app.svc) {
            try {
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($svc) { $found = $true; $svcStatus = $svc.Status.ToString() }
            } catch {}
        }
        foreach ($procName in $app.proc) {
            try {
                $p = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($p) { $found = $true; $procRunning = $true }
            } catch {}
        }

        if ($found) {
            $detected += [ordered]@{
                name            = $app.name
                service_status  = $svcStatus
                process_running = $procRunning
            }
        }
    }
    $data["detected_cloud_software"] = $detected

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 23: Event Logs
# ═══════════════════════════════════════════════════════════════
function Collect-EventLogs {
    $data = [ordered]@{}
    $cutoff = (Get-Date).AddDays(-7)

    # Security events
    $securityEvents = [ordered]@{}

    # Failed logins (4625)
    $failedLogins = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$cutoff} -MaxEvents 500 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $evData = $xml.Event.EventData.Data
            $failedLogins += [ordered]@{
                time        = $e.TimeCreated.ToString("o")
                target_user = ($evData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                source_ip   = ($evData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                logon_type  = ($evData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                status      = ($evData | Where-Object { $_.Name -eq 'Status' }).'#text'
                sub_status  = ($evData | Where-Object { $_.Name -eq 'SubStatus' }).'#text'
                workstation = ($evData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
            }
        }
    } catch {}
    $securityEvents["failed_logins"] = $failedLogins
    $securityEvents["failed_login_count"] = $failedLogins.Count

    # Account lockouts (4740)
    $lockouts = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$cutoff} -MaxEvents 200 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $evData = $xml.Event.EventData.Data
            $lockouts += [ordered]@{
                time     = $e.TimeCreated.ToString("o")
                user     = ($evData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                caller   = ($evData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
            }
        }
    } catch {}
    $securityEvents["lockouts"] = $lockouts

    # Special privileges (4672) — just count, too noisy
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$cutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        $securityEvents["special_privilege_logon_count"] = if ($events) { (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$cutoff} -ErrorAction SilentlyContinue).Count } else { 0 }
    } catch { $securityEvents["special_privilege_logon_count"] = 0 }

    # Log cleared (1102)
    $logCleared = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102; StartTime=$cutoff} -MaxEvents 50 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $logCleared += [ordered]@{ time=$e.TimeCreated.ToString("o"); message=$e.Message.Substring(0, [math]::Min(200, $e.Message.Length)) }
        }
    } catch {}
    $securityEvents["log_cleared_events"] = $logCleared

    # User created (4720)
    $userCreated = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; StartTime=$cutoff} -MaxEvents 100 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $evData = $xml.Event.EventData.Data
            $userCreated += [ordered]@{
                time = $e.TimeCreated.ToString("o")
                new_user = ($evData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                created_by = ($evData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            }
        }
    } catch {}
    $securityEvents["user_created_events"] = $userCreated

    # Member added to security-enabled group (4732)
    $memberAdded = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732; StartTime=$cutoff} -MaxEvents 100 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $evData = $xml.Event.EventData.Data
            $memberAdded += [ordered]@{
                time   = $e.TimeCreated.ToString("o")
                member = ($evData | Where-Object { $_.Name -eq 'MemberName' }).'#text'
                group  = ($evData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                by     = ($evData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            }
        }
    } catch {}
    $securityEvents["member_added_to_group"] = $memberAdded

    $data["security"] = $securityEvents

    # System events
    $systemEvents = [ordered]@{}

    # New service installed (7045)
    $newServices = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$cutoff} -MaxEvents 200 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $newServices += [ordered]@{
                time    = $e.TimeCreated.ToString("o")
                service = $e.Properties[0].Value
                path    = $e.Properties[1].Value
                type    = $e.Properties[2].Value
                start   = $e.Properties[3].Value
                account = $e.Properties[4].Value
            }
        }
    } catch {}
    $systemEvents["new_service_installs"] = $newServices

    # System crashes (1001)
    $crashes = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=$cutoff} -MaxEvents 50 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $crashes += [ordered]@{ time=$e.TimeCreated.ToString("o"); message=$e.Message.Substring(0, [math]::Min(300, $e.Message.Length)) }
        }
    } catch {}
    $systemEvents["crashes"] = $crashes

    # Unexpected shutdown (41)
    $shutdowns = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=41; StartTime=$cutoff} -MaxEvents 50 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $shutdowns += [ordered]@{ time=$e.TimeCreated.ToString("o"); message=$e.Message.Substring(0, [math]::Min(200, $e.Message.Length)) }
        }
    } catch {}
    $systemEvents["unexpected_shutdowns"] = $shutdowns

    $data["system"] = $systemEvents

    # PowerShell events (4104 — script block logging)
    $psEvents = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$cutoff} -MaxEvents 500 -ErrorAction SilentlyContinue
        $suspiciousKeywords = @('Invoke-Mimikatz','Invoke-Expression','IEX','DownloadString','DownloadFile',
            'Net.WebClient','Start-Process','Invoke-WebRequest','certutil','bitsadmin','FromBase64String',
            'EncodedCommand','bypass','AMSI','Reflection.Assembly','GetProcAddress','VirtualAlloc',
            'WriteProcessMemory','CreateRemoteThread','Invoke-Shellcode','Invoke-DllInjection',
            'Add-MpPreference','Set-MpPreference','Disable-','Invoke-Command','Invoke-WmiMethod')
        foreach ($e in $events) {
            $scriptBlock = $e.Properties[2].Value
            $isSuspicious = $false
            foreach ($kw in $suspiciousKeywords) {
                if ($scriptBlock -match [regex]::Escape($kw)) { $isSuspicious = $true; break }
            }
            if ($isSuspicious) {
                $psEvents += [ordered]@{
                    time         = $e.TimeCreated.ToString("o")
                    script_block = $scriptBlock.Substring(0, [math]::Min(1000, $scriptBlock.Length))
                    suspicious   = $true
                }
            }
        }
    } catch {}
    $data["powershell_suspicious"] = $psEvents

    # Application errors (last 7 days, Error level)
    $appErrors = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=$cutoff} -MaxEvents 200 -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $appErrors += [ordered]@{
                time     = $e.TimeCreated.ToString("o")
                source   = $e.ProviderName
                event_id = $e.Id
                message  = $e.Message.Substring(0, [math]::Min(300, $e.Message.Length))
            }
        }
    } catch {}
    $data["application_errors"] = $appErrors

    return $data
}

# ═══════════════════════════════════════════════════════════════
# Section 24: Startup Items
# ═══════════════════════════════════════════════════════════════
function Collect-StartupItems {
    $items = @()

    # Registry Run keys
    $runPaths = @(
        @{path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; scope="Machine"; type="Run"},
        @{path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; scope="Machine"; type="RunOnce"},
        @{path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; scope="User"; type="Run"},
        @{path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; scope="User"; type="RunOnce"},
        @{path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"; scope="Machine (32-bit)"; type="Run"}
    )
    foreach ($rp in $runPaths) {
        try {
            $props = Get-ItemProperty $rp.path -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -notmatch '^PS') {
                        $items += [ordered]@{
                            name    = $p.Name
                            value   = $p.Value
                            source  = $rp.path
                            scope   = $rp.scope
                            type    = $rp.type
                        }
                    }
                }
            }
        } catch {}
    }

    # Startup folders
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($sf in $startupFolders) {
        if (Test-Path $sf) {
            try {
                $files = Get-ChildItem $sf -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    $items += [ordered]@{
                        name   = $f.Name
                        value  = $f.FullName
                        source = $sf
                        scope  = if ($sf -match 'ProgramData') { "All Users" } else { "Current User" }
                        type   = "Startup Folder"
                    }
                }
            } catch {}
        }
    }

    # Boot execute
    $bootExec = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "BootExecute"
    if ($bootExec) {
        foreach ($be in $bootExec) {
            $items += [ordered]@{ name="BootExecute"; value=$be; source="Session Manager"; scope="Machine"; type="BootExecute" }
        }
    }

    return $items
}

# ═══════════════════════════════════════════════════════════════
# Section 25: BitLocker
# ═══════════════════════════════════════════════════════════════
function Collect-BitLocker {
    $volumes = @()
    try {
        $blVolumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($v in $blVolumes) {
            $protectors = @()
            foreach ($kp in $v.KeyProtector) {
                $protectors += [ordered]@{
                    type = $kp.KeyProtectorType.ToString()
                    id   = $kp.KeyProtectorId
                }
            }
            $volumes += [ordered]@{
                mount_point           = $v.MountPoint
                volume_status         = $v.VolumeStatus.ToString()
                encryption_percentage = $v.EncryptionPercentage
                protection_status     = $v.ProtectionStatus.ToString()
                encryption_method     = $v.EncryptionMethod.ToString()
                volume_type           = $v.VolumeType.ToString()
                lock_status           = $v.LockStatus.ToString()
                key_protectors        = $protectors
            }
        }
    } catch {
        return [ordered]@{ available=$false; error=$_.Exception.Message }
    }
    return [ordered]@{ available=$true; volumes=$volumes }
}

# ═══════════════════════════════════════════════════════════════
# Section 26: Windows Backup
# ═══════════════════════════════════════════════════════════════
function Collect-WindowsBackup {
    $data = [ordered]@{}

    # Check Windows Server Backup feature
    try {
        $wbFeature = Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue
        $data["wsb_installed"] = if ($wbFeature) { $wbFeature.Installed } else { $null }
    } catch {
        $data["wsb_installed"] = $null
    }

    # wbadmin status
    try {
        $wbStatus = wbadmin get status 2>&1
        $data["wbadmin_status"] = ($wbStatus | Out-String).Trim()
    } catch {
        $data["wbadmin_status"] = "Not available"
    }

    # wbadmin policy
    try {
        $wbPolicy = wbadmin get policy 2>&1
        $data["wbadmin_policy"] = ($wbPolicy | Out-String).Trim()
    } catch {
        $data["wbadmin_policy"] = "Not available"
    }

    # Windows Backup via WMI (for client OS)
    try {
        $backupStatus = Get-WmiObject -Namespace "root\cimv2" -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
        if ($backupStatus) {
            $data["shadow_copies"] = @($backupStatus | ForEach-Object {
                [ordered]@{ id=$_.ID; volume=$_.VolumeName; date=Safe-ToISO $_.InstallDate }
            })
        }
    } catch {}

    # File History (client OS)
    $fhPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory"
    $data["file_history_enabled"] = Get-RegValue $fhPath "ProtectedUpToTime"

    # System restore
    try {
        $srConfig = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -First 5
        $data["restore_points"] = @($srConfig | ForEach-Object {
            [ordered]@{ sequence=$_.SequenceNumber; description=$_.Description; type=$_.RestorePointType; date=Safe-ToISO $_.CreationTime }
        })
    } catch {
        $data["restore_points"] = @()
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 27: Credential Exposure
# ═══════════════════════════════════════════════════════════════
function Collect-CredentialExposure {
    $data = [ordered]@{}

    # WiFi profiles with cleartext keys
    try {
        $profiles = @()
        $raw = netsh wlan show profiles 2>$null
        if ($raw) {
            $profileNames = $raw | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
            foreach ($pn in $profileNames) {
                $detail = netsh wlan show profile name="$pn" key=clear 2>$null
                $auth = ($detail | Select-String "Authentication\s*:\s*(.+)" | Select-Object -First 1)
                $cipher = ($detail | Select-String "Cipher\s*:\s*(.+)" | Select-Object -First 1)
                $keyContent = ($detail | Select-String "Key Content\s*:\s*(.+)" | Select-Object -First 1)
                $profiles += [ordered]@{
                    name           = $pn
                    authentication = if ($auth) { $auth.Matches[0].Groups[1].Value.Trim() } else { $null }
                    cipher         = if ($cipher) { $cipher.Matches[0].Groups[1].Value.Trim() } else { $null }
                    key_present    = ($null -ne $keyContent)
                }
            }
        }
        $data["wifi_profiles"] = $profiles
    } catch {
        $data["wifi_profiles"] = @()
    }

    # PuTTY saved sessions
    try {
        $putty = @()
        $sessions = Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $props = Get-ItemProperty $s.PSPath -ErrorAction SilentlyContinue
            $putty += [ordered]@{
                name          = $s.PSChildName
                hostname      = $props.HostName
                username      = $props.UserName
                public_key    = $props.PublicKeyFile
            }
        }
        $data["putty_sessions"] = $putty
    } catch {
        $data["putty_sessions"] = @()
    }

    # WinSCP saved sessions
    try {
        $winscp = @()
        $sessions = Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $props = Get-ItemProperty $s.PSPath -ErrorAction SilentlyContinue
            $winscp += [ordered]@{
                name          = $s.PSChildName
                hostname      = $props.HostName
                username      = $props.UserName
                password_stored = ($null -ne $props.Password -and $props.Password -ne "")
            }
        }
        $data["winscp_sessions"] = $winscp
    } catch {
        $data["winscp_sessions"] = @()
    }

    # FileZilla saved sessions
    try {
        $fzPath = Join-Path $env:APPDATA "FileZilla\sitemanager.xml"
        if (Test-Path $fzPath) {
            [xml]$fzXml = Get-Content $fzPath -ErrorAction SilentlyContinue
            $fzSites = @()
            $fzXml.SelectNodes("//Server") | ForEach-Object {
                $fzSites += [ordered]@{
                    host          = $_.Host
                    user          = $_.User
                    password_stored = ($null -ne $_.Pass -and $_.Pass -ne "")
                }
            }
            $data["filezilla_sessions"] = $fzSites
        } else {
            $data["filezilla_sessions"] = @()
        }
    } catch {
        $data["filezilla_sessions"] = @()
    }

    # RDP saved connections
    try {
        $rdp = @()
        $servers = Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
        foreach ($s in $servers) {
            $props = Get-ItemProperty $s.PSPath -ErrorAction SilentlyContinue
            $rdp += [ordered]@{
                hostname      = $s.PSChildName
                username_hint = $props.UsernameHint
            }
        }
        $data["rdp_saved_connections"] = $rdp
    } catch {
        $data["rdp_saved_connections"] = @()
    }

    # Credential files on disk
    try {
        $credFiles = @()
        $paths = @(
            "C:\Windows\Panther\unattend.xml",
            "C:\Windows\Panther\Unattend\unattend.xml",
            "C:\Windows\System32\Sysprep\sysprep.xml",
            "C:\Windows\System32\Sysprep\unattend.xml",
            "C:\inetpub\wwwroot\web.config",
            "C:\Windows\System32\inetsrv\config\applicationHost.config",
            "C:\ProgramData\McAfee\Common Framework\SiteList.xml"
        )
        foreach ($p in $paths) {
            if (Test-Path $p) {
                $credFiles += [ordered]@{ path=$p; found=$true }
            }
        }
        # GPP Groups.xml with cpassword
        $sysvolPaths = @()
        try {
            $domain = (Get-CimInstance Win32_ComputerSystem).Domain
            if ($domain -and $domain -ne "WORKGROUP") {
                $gppBase = "\\$domain\SYSVOL\$domain\Policies"
                if (Test-Path $gppBase) {
                    $sysvolPaths = Get-ChildItem $gppBase -Recurse -Filter "Groups.xml" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
                }
            }
        } catch {}
        foreach ($gpp in $sysvolPaths) {
            $credFiles += [ordered]@{ path=$gpp; found=$true; type="gpp_groups_xml" }
        }
        $data["credential_files"] = $credFiles
    } catch {
        $data["credential_files"] = @()
    }

    # Cloud credential files
    try {
        $cloudCreds = [ordered]@{
            aws_credentials   = Test-Path (Join-Path $env:USERPROFILE ".aws\credentials")
            aws_config        = Test-Path (Join-Path $env:USERPROFILE ".aws\config")
            azure_directory   = Test-Path (Join-Path $env:USERPROFILE ".azure")
            gcloud_directory  = Test-Path (Join-Path $env:USERPROFILE ".config\gcloud")
        }
        $data["cloud_credentials"] = $cloudCreds
    } catch {
        $data["cloud_credentials"] = [ordered]@{}
    }

    # Windows Vault
    try {
        $vaultRaw = vaultcmd /list 2>$null
        $data["windows_vault"] = if ($vaultRaw) { @($vaultRaw) } else { @() }
    } catch {
        $data["windows_vault"] = @()
    }

    # SSH private keys
    try {
        $sshKeys = @()
        $sshDir = Join-Path $env:USERPROFILE ".ssh"
        if (Test-Path $sshDir) {
            $keyFiles = Get-ChildItem $sshDir -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match "^id_(rsa|ed25519|ecdsa|dsa)$"
            }
            foreach ($kf in $keyFiles) {
                $sshKeys += [ordered]@{ name=$kf.Name; path=$kf.FullName; size=$kf.Length }
            }
        }
        $data["ssh_private_keys"] = $sshKeys
    } catch {
        $data["ssh_private_keys"] = @()
    }

    # KeePass database files
    try {
        $kdbx = @()
        $searchPaths = @($env:USERPROFILE, $env:APPDATA, "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop")
        foreach ($sp in $searchPaths) {
            if (Test-Path $sp) {
                Get-ChildItem $sp -Recurse -Filter "*.kdbx" -ErrorAction SilentlyContinue -Depth 3 | ForEach-Object {
                    $kdbx += [ordered]@{ path=$_.FullName; size=$_.Length; modified=Safe-ToISO $_.LastWriteTime }
                }
            }
        }
        $data["keepass_databases"] = $kdbx
    } catch {
        $data["keepass_databases"] = @()
    }

    # DPAPI master keys
    try {
        $protectDir = Join-Path $env:APPDATA "Microsoft\Protect"
        $dpapi = [ordered]@{ protect_dir_exists = (Test-Path $protectDir); sids = @() }
        if ($dpapi.protect_dir_exists) {
            $dpapi["sids"] = @(Get-ChildItem $protectDir -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        }
        $data["dpapi"] = $dpapi
    } catch {
        $data["dpapi"] = [ordered]@{ protect_dir_exists=$false; sids=@() }
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 28: Privilege Escalation
# ═══════════════════════════════════════════════════════════════
function Collect-PrivilegeEscalation {
    $data = [ordered]@{}

    # AlwaysInstallElevated
    try {
        $data["always_install_elevated"] = [ordered]@{
            hklm = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
            hkcu = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
        }
    } catch {
        $data["always_install_elevated"] = [ordered]@{ hklm=$null; hkcu=$null }
    }

    # Modifiable service binaries
    try {
        $modifiable = @()
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.State -eq "Running" }
        foreach ($svc in $services) {
            $binPath = $svc.PathName
            # Extract the actual executable path (handle quotes and arguments)
            if ($binPath -match '^"([^"]+)"') {
                $exePath = $Matches[1]
            } elseif ($binPath -match '^(\S+)') {
                $exePath = $Matches[1]
            } else { continue }

            if (-not (Test-Path $exePath)) { continue }
            try {
                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                $writable = $false
                foreach ($ace in $acl.Access) {
                    if ($ace.FileSystemRights -match "Modify|FullControl|Write" -and
                        $ace.AccessControlType -eq "Allow" -and
                        $ace.IdentityReference.Value -notmatch "^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT SERVICE\\)") {
                        $writable = $true
                        break
                    }
                }
                if ($writable) {
                    $modifiable += [ordered]@{
                        name=$svc.Name; display_name=$svc.DisplayName;
                        path=$exePath; start_mode=$svc.StartMode
                    }
                }
            } catch {}
        }
        $data["modifiable_service_binaries"] = $modifiable
    } catch {
        $data["modifiable_service_binaries"] = @()
    }

    # Unquoted service paths
    try {
        $unquoted = @()
        $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '^\s*"' }
        foreach ($svc in $services) {
            $p = $svc.PathName
            if ($p -match " " -and $p -notmatch "^\\\\") {
                $parts = $p.Split(" ")
                $checkPaths = @()
                for ($i = 0; $i -lt ($parts.Count - 1); $i++) {
                    $candidate = ($parts[0..$i] -join " ") + ".exe"
                    $parentDir = Split-Path $candidate -Parent -ErrorAction SilentlyContinue
                    if ($parentDir -and (Test-Path $parentDir)) {
                        $checkPaths += $candidate
                    }
                }
                if ($checkPaths.Count -gt 0) {
                    $unquoted += [ordered]@{
                        name=$svc.Name; display_name=$svc.DisplayName;
                        path=$p; hijack_candidates=@($checkPaths)
                    }
                }
            }
        }
        $data["unquoted_service_paths"] = $unquoted
    } catch {
        $data["unquoted_service_paths"] = @()
    }

    # Token privileges
    try {
        $privRaw = whoami /priv 2>$null
        $dangerousPrivs = @(
            "SeImpersonatePrivilege","SeAssignPrimaryTokenPrivilege",
            "SeBackupPrivilege","SeRestorePrivilege","SeDebugPrivilege",
            "SeTcbPrivilege","SeLoadDriverPrivilege","SeTakeOwnershipPrivilege"
        )
        $privs = @()
        if ($privRaw) {
            foreach ($line in $privRaw) {
                foreach ($dp in $dangerousPrivs) {
                    if ($line -match $dp) {
                        $enabled = $line -match "Enabled"
                        $privs += [ordered]@{ privilege=$dp; enabled=$enabled }
                    }
                }
            }
        }
        $data["dangerous_privileges"] = $privs
    } catch {
        $data["dangerous_privileges"] = @()
    }

    # DLL search order hijacking — writable directories in PATH
    try {
        $writablePath = @()
        $pathDirs = $env:PATH -split ";"
        foreach ($dir in $pathDirs) {
            if (-not $dir -or -not (Test-Path $dir)) { continue }
            try {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    if ($ace.FileSystemRights -match "Modify|FullControl|Write" -and
                        $ace.AccessControlType -eq "Allow" -and
                        $ace.IdentityReference.Value -notmatch "^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|NT SERVICE\\)") {
                        $writablePath += [ordered]@{ directory=$dir; identity=$ace.IdentityReference.Value; rights=$ace.FileSystemRights.ToString() }
                        break
                    }
                }
            } catch {}
        }
        $data["writable_path_directories"] = $writablePath
    } catch {
        $data["writable_path_directories"] = @()
    }

    # Named pipes
    try {
        $pipes = @()
        $pipeFiles = [System.IO.Directory]::GetFiles("\\.\pipe\") 2>$null
        if ($pipeFiles) {
            $attackPipes = @("spoolss","epmapper","samr","lsarpc","netlogon","wkssvc","browser","atsvc","srvsvc","winreg")
            foreach ($pipe in $pipeFiles) {
                $pipeName = [System.IO.Path]::GetFileName($pipe)
                if ($attackPipes -contains $pipeName.ToLower()) {
                    $pipes += $pipeName
                }
            }
        }
        $data["attack_relevant_pipes"] = $pipes
    } catch {
        $data["attack_relevant_pipes"] = @()
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 29: Defender Detailed
# ═══════════════════════════════════════════════════════════════
function Collect-DefenderDetailed {
    $data = [ordered]@{}

    # ASR rules
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $asrIds = $pref.AttackSurfaceReductionRules_Ids
        $asrActions = $pref.AttackSurfaceReductionRules_Actions
        $asrRules = @()
        if ($asrIds) {
            for ($i = 0; $i -lt $asrIds.Count; $i++) {
                $asrRules += [ordered]@{
                    rule_id = $asrIds[$i]
                    action  = if ($asrActions -and $i -lt $asrActions.Count) { $asrActions[$i] } else { $null }
                }
            }
        }
        $data["asr_rules"] = $asrRules
    } catch {
        $data["asr_rules"] = @()
    }

    # Controlled folder access
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $data["controlled_folder_access"] = [ordered]@{
            enabled               = $pref.EnableControlledFolderAccess
            allowed_applications  = @($pref.ControlledFolderAccessAllowedApplications)
            protected_folders     = @($pref.ControlledFolderAccessProtectedFolders)
        }
    } catch {
        $data["controlled_folder_access"] = [ordered]@{ enabled=$null }
    }

    # Network protection
    try {
        $data["network_protection"] = (Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection
    } catch {
        $data["network_protection"] = $null
    }

    # Exploit protection
    try {
        $ep = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if ($ep) {
            $data["exploit_protection"] = [ordered]@{
                dep                  = $ep.DEP.Enable
                aslr_bottom_up       = $ep.ASLR.BottomUp
                aslr_force_relocate  = $ep.ASLR.ForceRelocateImages
                aslr_high_entropy    = $ep.ASLR.HighEntropy
                cfg                  = $ep.CFG.Enable
                sehop                = $ep.SEHOP.Enable
                heap_terminate       = $ep.Heap.TerminateOnError
            }
        } else {
            $data["exploit_protection"] = $null
        }
    } catch {
        $data["exploit_protection"] = $null
    }

    # All AV products
    try {
        $avProducts = @()
        $avList = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        foreach ($av in $avList) {
            $avProducts += [ordered]@{
                display_name    = $av.displayName
                product_state   = $av.productState
                exe_path        = $av.pathToSignedProductExe
                reporting_path  = $av.pathToSignedReportingExe
            }
        }
        $data["av_products"] = $avProducts
    } catch {
        $data["av_products"] = @()
    }

    # Definition age
    try {
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($status -and $status.AntivirusSignatureLastUpdated) {
            $age = (New-TimeSpan -Start $status.AntivirusSignatureLastUpdated -End (Get-Date)).Days
            $data["definition_age_days"] = $age
            $data["signature_last_updated"] = Safe-ToISO $status.AntivirusSignatureLastUpdated
        } else {
            $data["definition_age_days"] = $null
            $data["signature_last_updated"] = $null
        }
    } catch {
        $data["definition_age_days"] = $null
        $data["signature_last_updated"] = $null
    }

    # Cloud protection
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $data["cloud_protection"] = [ordered]@{
            maps_reporting        = $pref.MAPSReporting
            submit_samples        = $pref.SubmitSamplesConsent
            cloud_block_level     = $pref.CloudBlockLevel
            cloud_extended_timeout = $pref.CloudExtendedTimeout
        }
    } catch {
        $data["cloud_protection"] = [ordered]@{}
    }

    # Tamper protection
    try {
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $data["tamper_protection"] = $status.IsTamperProtected
    } catch {
        $data["tamper_protection"] = $null
    }

    # Real-time protection
    try {
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $data["realtime_protection"] = [ordered]@{
            realtime_enabled     = $status.RealTimeProtectionEnabled
            ioav_enabled         = $status.IoavProtectionEnabled
            on_access_enabled    = $status.OnAccessProtectionEnabled
            behavior_monitor     = $status.BehaviorMonitorEnabled
        }
    } catch {
        $data["realtime_protection"] = [ordered]@{}
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 30: AD Certificate Services
# ═══════════════════════════════════════════════════════════════
function Collect-ADCS {
    $data = [ordered]@{}

    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        $data["domain_required"] = $true
        $data["available"] = $false
        return $data
    }
    $data["available"] = $true

    # CA enumeration
    try {
        $caRaw = certutil -config - -ping 2>&1
        $cas = @()
        foreach ($line in $caRaw) {
            if ($line -match '^\s*\d+\.\s+`(.+)\\(.+)`') {
                $cas += [ordered]@{ host=$Matches[1]; ca_name=$Matches[2] }
            } elseif ($line -match 'Config string:\s*`(.+)`') {
                $cas += [ordered]@{ config_string=$Matches[1] }
            }
        }
        $data["certificate_authorities"] = $cas
    } catch {
        $data["certificate_authorities"] = @()
    }

    # Certificate templates
    try {
        $templateRaw = certutil -v -template 2>&1
        $templates = @()
        $current = $null
        foreach ($line in $templateRaw) {
            if ($line -match "^Template\[\d+\]:$") {
                if ($current) { $templates += $current }
                $current = [ordered]@{
                    name=$null; schema_version=$null;
                    name_flag=$null; enrollment_flag=$null;
                    ekus=@(); ra_signature=$null;
                    esc_indicators=@()
                }
            }
            if ($null -eq $current) { continue }
            if ($line -match "TemplatePropCommonName\s*=\s*(.+)") { $current.name = $Matches[1].Trim() }
            if ($line -match "Schema Version\s*=\s*(\d+)") { $current.schema_version = [int]$Matches[1] }
            if ($line -match "msPKI-Certificate-Name-Flag\s*=\s*(\S+)") { $current.name_flag = $Matches[1].Trim() }
            if ($line -match "msPKI-Enrollment-Flag\s*=\s*(\S+)") { $current.enrollment_flag = $Matches[1].Trim() }
            if ($line -match "pKIExtendedKeyUsage\s*=\s*(.+)") { $current.ekus = @($Matches[1].Trim() -split ",\s*") }
            if ($line -match "msPKI-RA-Signature\s*=\s*(\d+)") { $current.ra_signature = [int]$Matches[1] }

            # ESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU
            if ($current.name_flag -match "ENROLLEE_SUPPLIES_SUBJECT" -and ($current.ekus -contains "1.3.6.1.5.5.7.3.2")) {
                if ("ESC1" -notin $current.esc_indicators) { $current.esc_indicators += "ESC1" }
            }
            # ESC2: Any Purpose (2.5.29.37.0) or no EKU
            if ($current.ekus -contains "2.5.29.37.0" -or $current.ekus.Count -eq 0) {
                if ("ESC2" -notin $current.esc_indicators) { $current.esc_indicators += "ESC2" }
            }
            # ESC3: Certificate Request Agent (1.3.6.1.4.1.311.20.2.1) with no RA sig
            if ($current.ekus -contains "1.3.6.1.4.1.311.20.2.1" -and ($current.ra_signature -eq 0 -or $null -eq $current.ra_signature)) {
                if ("ESC3" -notin $current.esc_indicators) { $current.esc_indicators += "ESC3" }
            }
        }
        if ($current) { $templates += $current }
        $data["templates"] = $templates
    } catch {
        $data["templates"] = @()
    }

    # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
    try {
        $editFlagRaw = certutil -getreg policy\EditFlags 2>&1
        $esc6 = $false
        foreach ($line in $editFlagRaw) {
            if ($line -match "EDITF_ATTRIBUTESUBJECTALTNAME2") { $esc6 = $true; break }
        }
        $data["esc6_editf_flag"] = $esc6
    } catch {
        $data["esc6_editf_flag"] = $null
    }

    # ESC8: HTTP enrollment endpoints
    try {
        $httpEnroll = @()
        foreach ($ca in $data["certificate_authorities"]) {
            if ($ca.host) {
                $url = "http://$($ca.host)/certsrv/"
                try {
                    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
                    $httpEnroll += [ordered]@{ ca_host=$ca.host; url=$url; accessible=$true; status_code=$resp.StatusCode }
                } catch {
                    $httpEnroll += [ordered]@{ ca_host=$ca.host; url=$url; accessible=$false }
                }
            }
        }
        $data["http_enrollment_endpoints"] = $httpEnroll
    } catch {
        $data["http_enrollment_endpoints"] = @()
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 31: Persistence Mechanisms
# ═══════════════════════════════════════════════════════════════
function Collect-PersistenceMechanisms {
    $data = [ordered]@{}

    # WMI event subscriptions
    try {
        $filters = @()
        Get-WmiObject -Namespace root/subscription -Class __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
            $filters += [ordered]@{ name=$_.Name; query=$_.Query; query_language=$_.QueryLanguage }
        }
        $consumers = @()
        Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
            $consumers += [ordered]@{ name=$_.Name; command=$_.CommandLineTemplate; executable=$_.ExecutablePath }
        }
        Get-WmiObject -Namespace root/subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
            $consumers += [ordered]@{ name=$_.Name; scripting_engine=$_.ScriptingEngine; script_text=$_.ScriptText }
        }
        $bindings = @()
        Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
            $bindings += [ordered]@{ filter=$_.Filter; consumer=$_.Consumer }
        }
        $data["wmi_subscriptions"] = [ordered]@{
            filters=$filters; consumers=$consumers; bindings=$bindings
        }
    } catch {
        $data["wmi_subscriptions"] = [ordered]@{ filters=@(); consumers=@(); bindings=@() }
    }

    # COM hijacking — user CLSID overrides
    try {
        $comHijacks = @()
        $clsids = Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue
        foreach ($c in $clsids) {
            $server = Get-ItemProperty "$($c.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
            if ($server -and $server.'(default)') {
                $comHijacks += [ordered]@{ clsid=$c.PSChildName; dll=$server.'(default)' }
            }
            $localServer = Get-ItemProperty "$($c.PSPath)\LocalServer32" -ErrorAction SilentlyContinue
            if ($localServer -and $localServer.'(default)') {
                $comHijacks += [ordered]@{ clsid=$c.PSChildName; exe=$localServer.'(default)' }
            }
        }
        $data["com_hijacks"] = $comHijacks
    } catch {
        $data["com_hijacks"] = @()
    }

    # AppInit_DLLs
    try {
        $data["appinit_dlls"] = [ordered]@{
            dlls        = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "AppInit_DLLs"
            load_enabled = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs"
        }
    } catch {
        $data["appinit_dlls"] = [ordered]@{}
    }

    # IFEO debugger keys
    try {
        $ifeo = @()
        $keys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue
        foreach ($k in $keys) {
            $debugger = Get-RegValue $k.PSPath "Debugger"
            if ($debugger) {
                $ifeo += [ordered]@{ target=$k.PSChildName; debugger=$debugger }
            }
        }
        $data["ifeo_debuggers"] = $ifeo
    } catch {
        $data["ifeo_debuggers"] = @()
    }

    # Accessibility feature replacement
    try {
        $accFeatures = @()
        $osInstall = (Get-CimInstance Win32_OperatingSystem).InstallDate
        $targets = @("sethc.exe","utilman.exe","osk.exe","narrator.exe","magnify.exe")
        foreach ($t in $targets) {
            $fpath = Join-Path $env:SystemRoot "System32\$t"
            if (Test-Path $fpath) {
                $fi = Get-Item $fpath
                $modified = $fi.LastWriteTime -gt $osInstall
                $accFeatures += [ordered]@{
                    file=$t; last_modified=Safe-ToISO $fi.LastWriteTime;
                    os_install=Safe-ToISO $osInstall; modified_after_install=$modified
                }
            }
        }
        $data["accessibility_features"] = $accFeatures
    } catch {
        $data["accessibility_features"] = @()
    }

    # Print monitor DLLs
    try {
        $monitors = @()
        $monKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ErrorAction SilentlyContinue
        foreach ($mk in $monKeys) {
            $driver = Get-RegValue $mk.PSPath "Driver"
            $monitors += [ordered]@{ name=$mk.PSChildName; driver=$driver }
        }
        $data["print_monitors"] = $monitors
    } catch {
        $data["print_monitors"] = @()
    }

    # Sysmon
    try {
        $sysmonInstalled = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"
        $sysmonConfig = $null
        if ($sysmonInstalled) {
            $raw = sysmon64 -c 2>&1
            if (-not $raw -or $LASTEXITCODE -ne 0) { $raw = sysmon -c 2>&1 }
            $sysmonConfig = @($raw)
        }
        $data["sysmon"] = [ordered]@{ installed=$sysmonInstalled; config=$sysmonConfig }
    } catch {
        $data["sysmon"] = [ordered]@{ installed=$false; config=$null }
    }

    # LSA packages
    try {
        $data["lsa_packages"] = [ordered]@{
            authentication_packages = @(Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "Authentication Packages")
            notification_packages   = @(Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "Notification Packages")
            security_packages       = @(Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "Security Packages")
        }
    } catch {
        $data["lsa_packages"] = [ordered]@{}
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 32: PowerShell Configuration
# ═══════════════════════════════════════════════════════════════
function Collect-PowerShellConfig {
    $data = [ordered]@{}

    # .NET CLR versions
    try {
        $netVersions = @()
        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse -ErrorAction SilentlyContinue |
            Get-ItemProperty -Name Version -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Version) {
                    $netVersions += [ordered]@{ path=$_.PSPath -replace ".*\\NDP\\","NDP\\"; version=$_.Version }
                }
            }
        $data["dotnet_versions"] = $netVersions
    } catch {
        $data["dotnet_versions"] = @()
    }

    # Language mode
    try {
        $data["language_mode"] = $ExecutionContext.SessionState.LanguageMode.ToString()
    } catch {
        $data["language_mode"] = $null
    }

    # AMSI providers
    try {
        $amsiProviders = @()
        $providers = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue
        foreach ($p in $providers) {
            $amsiProviders += $p.PSChildName
        }
        $data["amsi_providers"] = $amsiProviders
    } catch {
        $data["amsi_providers"] = @()
    }

    # Execution policy
    try {
        $policies = @()
        Get-ExecutionPolicy -List | ForEach-Object {
            $policies += [ordered]@{ scope=$_.Scope.ToString(); policy=$_.ExecutionPolicy.ToString() }
        }
        $data["execution_policy"] = $policies
    } catch {
        $data["execution_policy"] = @()
    }

    # PowerShell v2 engine
    try {
        $v2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
        if ($v2Feature) {
            $data["powershell_v2"] = [ordered]@{ state=$v2Feature.State.ToString() }
        } else {
            $v2Reg = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" "PowerShellVersion"
            $data["powershell_v2"] = [ordered]@{ registry_version=$v2Reg }
        }
    } catch {
        $data["powershell_v2"] = [ordered]@{}
    }

    # Console history presence
    try {
        $histPath = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        $data["console_history"] = [ordered]@{
            exists = Test-Path $histPath
            line_count = if (Test-Path $histPath) { (Get-Content $histPath -ErrorAction SilentlyContinue | Measure-Object -Line).Lines } else { 0 }
        }
    } catch {
        $data["console_history"] = [ordered]@{ exists=$false; line_count=0 }
    }

    # Transcription
    try {
        $data["transcription"] = [ordered]@{
            enabled     = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
            output_dir  = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "OutputDirectory"
            invocation  = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableInvocationHeader"
        }
    } catch {
        $data["transcription"] = [ordered]@{}
    }

    # Script block logging
    try {
        $data["script_block_logging"] = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    } catch {
        $data["script_block_logging"] = $null
    }

    # Module logging
    try {
        $data["module_logging"] = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
    } catch {
        $data["module_logging"] = $null
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 33: LAPS Configuration
# ═══════════════════════════════════════════════════════════════
function Collect-LAPSConfig {
    $data = [ordered]@{}

    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        $data["domain_required"] = $true
        $data["available"] = $false
        return $data
    }
    $data["available"] = $true

    # Legacy LAPS DLL
    try {
        $data["legacy_laps_dll"] = Test-Path (Join-Path $env:ProgramFiles "LAPS\CSE\AdmPwd.dll")
    } catch {
        $data["legacy_laps_dll"] = $false
    }

    # Windows LAPS (new)
    try {
        $lapsState = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State" -ErrorAction SilentlyContinue
        $data["windows_laps_state"] = if ($lapsState) { [ordered]@{ present=$true } } else { [ordered]@{ present=$false } }
    } catch {
        $data["windows_laps_state"] = [ordered]@{ present=$false }
    }

    # LAPS policy
    try {
        $data["laps_policy"] = Get-RegValues "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" @(
            "AdmPwdEnabled","PwdExpirationProtectionEnabled",
            "PasswordComplexity","PasswordLength","PasswordAgeDays"
        )
    } catch {
        $data["laps_policy"] = [ordered]@{}
    }

    # ms-Mcs-AdmPwd attribute accessibility
    try {
        $searcher = [adsisearcher]"(&(objectClass=computer)(name=$env:COMPUTERNAME))"
        $result = $searcher.FindOne()
        $admpwd = $result.Properties["ms-mcs-admpwd"]
        $data["admpwd_readable"] = ($null -ne $admpwd -and $admpwd.Count -gt 0)
    } catch {
        $data["admpwd_readable"] = $null
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 34: Print Configuration
# ═══════════════════════════════════════════════════════════════
function Collect-PrintConfig {
    $data = [ordered]@{}

    # Print spooler status
    try {
        $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
        $data["spooler_service"] = [ordered]@{
            status     = $spooler.Status.ToString()
            start_type = $spooler.StartType.ToString()
        }
    } catch {
        $data["spooler_service"] = [ordered]@{ status="Unknown"; start_type="Unknown" }
    }

    # Printer drivers
    try {
        $drivers = @()
        if (Get-Command Get-PrinterDriver -ErrorAction SilentlyContinue) {
            Get-PrinterDriver -ErrorAction SilentlyContinue | ForEach-Object {
                $drivers += [ordered]@{
                    name=$_.Name; environment=$_.PrinterEnvironment; provider=$_.Provider
                }
            }
        }
        $data["printer_drivers"] = $drivers
    } catch {
        $data["printer_drivers"] = @()
    }

    # Point-and-Print restrictions
    try {
        $data["point_and_print"] = Get-RegValues "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" @(
            "RestrictDriverInstallationToAdministrators",
            "NoWarningNoElevationOnInstall",
            "UpdatePromptSettings",
            "TrustedServers",
            "ServerList"
        )
    } catch {
        $data["point_and_print"] = [ordered]@{}
    }

    # PrintNightmare mitigation
    try {
        $restrict = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators"
        $data["printnightmare_mitigated"] = ($restrict -eq 1)
        $data["restrict_driver_install"] = $restrict
    } catch {
        $data["printnightmare_mitigated"] = $null
        $data["restrict_driver_install"] = $null
    }

    # RPC configuration
    try {
        $data["rpc_config"] = Get-RegValues "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" @(
            "RpcUseNamedPipeProtocol",
            "RpcAuthentication",
            "RpcProtocols"
        )
    } catch {
        $data["rpc_config"] = [ordered]@{}
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 35: DNS Configuration
# ═══════════════════════════════════════════════════════════════
function Collect-DnsConfig {
    $data = [ordered]@{}

    # Check if DNS service exists
    $dnsService = Get-Service DNS -ErrorAction SilentlyContinue
    if (-not $dnsService) {
        $data["dns_role_installed"] = $false
        return $data
    }
    $data["dns_role_installed"] = $true
    $data["dns_service_status"] = $dnsService.Status.ToString()
    $data["dns_service_start_type"] = $dnsService.StartType.ToString()

    # Zone transfer settings
    try {
        $zones = @()
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            Get-DnsServerZone -ErrorAction SilentlyContinue | ForEach-Object {
                $zones += [ordered]@{
                    name=$_.ZoneName; type=$_.ZoneType;
                    secure_secondaries=$_.SecureSecondaries;
                    secondary_servers=@($_.SecondaryServers)
                }
            }
        }
        $data["zones"] = $zones
    } catch {
        $data["zones"] = @()
    }

    # DNSSEC
    try {
        if (Get-Command Get-DnsServerDsSetting -ErrorAction SilentlyContinue) {
            $dsSetting = Get-DnsServerDsSetting -ErrorAction SilentlyContinue
            $data["dnssec"] = [ordered]@{
                ds_polling_interval = $dsSetting.PollingInterval
                tombstone_interval  = $dsSetting.TombstoneInterval
            }
        } else {
            $data["dnssec"] = $null
        }
    } catch {
        $data["dnssec"] = $null
    }

    # Debug logging
    try {
        if (Get-Command Get-DnsServerDiagnostics -ErrorAction SilentlyContinue) {
            $diag = Get-DnsServerDiagnostics -ErrorAction SilentlyContinue
            $data["debug_logging"] = [ordered]@{
                queries=$diag.Queries; answers=$diag.Answers;
                notifications=$diag.Notifications; updates=$diag.Update;
                log_file_path=$diag.LogFilePath; max_size=$diag.MaxMBFileSize
            }
        } else {
            $data["debug_logging"] = $null
        }
    } catch {
        $data["debug_logging"] = $null
    }

    # Cache poisoning mitigations
    try {
        $dnscmdRaw = dnscmd /info 2>&1
        $socketPool = $null
        $cacheLocking = $null
        foreach ($line in $dnscmdRaw) {
            if ($line -match "SocketPoolSize\s*=\s*(\d+)") { $socketPool = [int]$Matches[1] }
            if ($line -match "CacheLockingPercent\s*=\s*(\d+)") { $cacheLocking = [int]$Matches[1] }
        }
        $data["cache_poisoning_mitigations"] = [ordered]@{
            socket_pool_size    = $socketPool
            cache_locking_pct   = $cacheLocking
        }
    } catch {
        $data["cache_poisoning_mitigations"] = [ordered]@{}
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section 36: Privacy Artifacts
# ═══════════════════════════════════════════════════════════════
function Collect-PrivacyArtifacts {
    $data = [ordered]@{}

    # Recent documents (MRU)
    try {
        $recentDocs = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue
        $mruCount = 0
        if ($recentDocs) {
            $mruCount = ($recentDocs.PSObject.Properties | Where-Object { $_.Name -match "^\d+$" }).Count
        }
        $data["recent_docs_count"] = $mruCount
    } catch {
        $data["recent_docs_count"] = 0
    }

    # TypedPaths
    try {
        $typedPaths = @()
        $tp = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -ErrorAction SilentlyContinue
        if ($tp) {
            $tp.PSObject.Properties | Where-Object { $_.Name -match "^url\d+$" } | ForEach-Object {
                $typedPaths += $_.Value
            }
        }
        $data["typed_paths"] = $typedPaths
    } catch {
        $data["typed_paths"] = @()
    }

    # Mapped network drives
    try {
        $mapped = @()
        $psDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.DisplayRoot -like "\\*" }
        foreach ($d in $psDrives) {
            $mapped += [ordered]@{ drive=$d.Name; unc=$d.DisplayRoot }
        }
        $regDrives = Get-ChildItem "HKCU:\Network" -ErrorAction SilentlyContinue
        foreach ($rd in $regDrives) {
            $props = Get-ItemProperty $rd.PSPath -ErrorAction SilentlyContinue
            $mapped += [ordered]@{ drive=$rd.PSChildName; unc=$props.RemotePath; source="registry" }
        }
        $data["mapped_drives"] = $mapped
    } catch {
        $data["mapped_drives"] = @()
    }

    # UserAssist
    try {
        $userAssist = @()
        $uaKeys = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -ErrorAction SilentlyContinue
        foreach ($uak in $uaKeys) {
            $countKey = Get-ChildItem "$($uak.PSPath)\Count" -ErrorAction SilentlyContinue
            $entryCount = 0
            if ($countKey) {
                $entryCount = (Get-ItemProperty $countKey.PSPath -ErrorAction SilentlyContinue).PSObject.Properties.Count
            } else {
                $cp = Get-ItemProperty "$($uak.PSPath)\Count" -ErrorAction SilentlyContinue
                if ($cp) { $entryCount = $cp.PSObject.Properties.Count }
            }
            $userAssist += [ordered]@{ guid=$uak.PSChildName; entry_count=$entryCount }
        }
        $data["user_assist"] = $userAssist
    } catch {
        $data["user_assist"] = @()
    }

    # BAM/DAM
    try {
        $bam = @()
        $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        if (Test-Path $bamPath) {
            $sids = Get-ChildItem $bamPath -ErrorAction SilentlyContinue
            foreach ($sid in $sids) {
                $props = Get-ItemProperty $sid.PSPath -ErrorAction SilentlyContinue
                $exes = @()
                $props.PSObject.Properties | Where-Object { $_.Name -match "\\" } | ForEach-Object {
                    $exes += $_.Name
                }
                $bam += [ordered]@{ sid=$sid.PSChildName; executable_count=$exes.Count; executables=$exes }
            }
        }
        $data["bam_entries"] = $bam
    } catch {
        $data["bam_entries"] = @()
    }

    # Recently accessed files count
    try {
        $recentDir = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
        $data["recent_files_count"] = if (Test-Path $recentDir) { (Get-ChildItem $recentDir -ErrorAction SilentlyContinue).Count } else { 0 }
    } catch {
        $data["recent_files_count"] = 0
    }

    # Jump lists
    try {
        $autoDir = Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations"
        $customDir = Join-Path $env:APPDATA "Microsoft\Windows\Recent\CustomDestinations"
        $data["jump_lists"] = [ordered]@{
            automatic_count = if (Test-Path $autoDir) { (Get-ChildItem $autoDir -ErrorAction SilentlyContinue).Count } else { 0 }
            custom_count    = if (Test-Path $customDir) { (Get-ChildItem $customDir -ErrorAction SilentlyContinue).Count } else { 0 }
        }
    } catch {
        $data["jump_lists"] = [ordered]@{ automatic_count=0; custom_count=0 }
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section: Disk & Storage
# ═══════════════════════════════════════════════════════════════
function Collect-DiskStorage {
    $data = [ordered]@{}

    # 1. Physical disks (WMI — works on all Windows versions)
    try {
        $phys = @()
        Get-CimInstance Win32_DiskDrive -ErrorAction Stop | ForEach-Object {
            $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
            $phys += [ordered]@{
                device_id        = $_.DeviceID
                model            = $_.Model
                size_gb          = $sizeGB
                interface_type   = $_.InterfaceType
                media_type       = $_.MediaType
                status           = $_.Status
                serial_number    = $_.SerialNumber
                partitions       = $_.Partitions
                firmware_revision = $_.FirmwareRevision
                scsi_bus         = $_.SCSIBus
                scsi_target      = $_.SCSITargetId
                scsi_lun         = $_.SCSILogicalUnit
            }
        }
        $data["physical_disks"] = $phys
    } catch {
        $data["physical_disks"] = @()
    }

    # 2. Logical disks (WMI — works on all Windows versions)
    try {
        $logical = @()
        Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | ForEach-Object {
            $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
            $freeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }
            $pctFree = if ($_.Size -and $_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
            $driveTypeName = switch ($_.DriveType) {
                0 {"Unknown"} 1 {"No Root Directory"} 2 {"Removable"} 3 {"Local Fixed"}
                4 {"Network"} 5 {"CD-ROM"} 6 {"RAM Disk"} default {"Unknown"}
            }
            $logical += [ordered]@{
                device_id   = $_.DeviceID
                file_system = $_.FileSystem
                size_gb     = $sizeGB
                free_gb     = $freeGB
                percent_free = $pctFree
                volume_name = $_.VolumeName
                drive_type  = $driveTypeName
            }
        }
        $data["logical_disks"] = $logical
    } catch {
        $data["logical_disks"] = @()
    }

    # 3. Disk partitions (WMI — works on all Windows versions)
    try {
        $parts = @()
        Get-CimInstance Win32_DiskPartition -ErrorAction Stop | ForEach-Object {
            $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
            $parts += [ordered]@{
                name              = $_.Name
                size_gb           = $sizeGB
                type              = $_.Type
                bootable          = $_.Bootable
                primary_partition = $_.PrimaryPartition
                disk_index        = $_.DiskIndex
            }
        }
        $data["partitions"] = $parts
    } catch {
        $data["partitions"] = @()
    }

    # 4. Storage module physical disks (Server 2012+ Storage module)
    try {
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            $spd = @()
            Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
                $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
                $spd += [ordered]@{
                    friendly_name      = $_.FriendlyName
                    serial_number      = $_.SerialNumber
                    media_type         = "$($_.MediaType)"
                    size_gb            = $sizeGB
                    health_status      = "$($_.HealthStatus)"
                    operational_status = "$($_.OperationalStatus)"
                    usage              = "$($_.Usage)"
                    bus_type           = "$($_.BusType)"
                    firmware_version   = $_.FirmwareVersion
                    unique_id          = $_.UniqueId
                    can_pool           = $_.CanPool
                }
            }
            $data["storage_physical_disks"] = $spd
        } else {
            $data["storage_physical_disks"] = @()
        }
    } catch {
        $data["storage_physical_disks"] = @()
    }

    # 5. Storage pools (Server 2012+ Storage Spaces — exclude Primordial)
    try {
        if (Get-Command Get-StoragePool -ErrorAction SilentlyContinue) {
            $pools = @()
            Get-StoragePool -ErrorAction Stop | Where-Object { -not $_.IsPrimordial } | ForEach-Object {
                $pool = $_
                $sizeGB = if ($pool.Size) { [math]::Round($pool.Size / 1GB, 2) } else { 0 }
                $allocGB = if ($pool.AllocatedSize) { [math]::Round($pool.AllocatedSize / 1GB, 2) } else { 0 }

                $poolDisks = @()
                try {
                    Get-PhysicalDisk -StoragePool $pool -ErrorAction Stop | ForEach-Object {
                        $pdSizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
                        $poolDisks += [ordered]@{
                            friendly_name      = $_.FriendlyName
                            health_status      = "$($_.HealthStatus)"
                            operational_status = "$($_.OperationalStatus)"
                            usage              = "$($_.Usage)"
                            media_type         = "$($_.MediaType)"
                            size_gb            = $pdSizeGB
                        }
                    }
                } catch {}

                $pools += [ordered]@{
                    friendly_name                  = $pool.FriendlyName
                    health_status                  = "$($pool.HealthStatus)"
                    operational_status             = "$($pool.OperationalStatus)"
                    size_gb                        = $sizeGB
                    allocated_size_gb              = $allocGB
                    is_read_only                   = $pool.IsReadOnly
                    is_power_protected             = $pool.IsPowerProtected
                    retire_missing_physical_disks  = "$($pool.RetireMissingPhysicalDisks)"
                    physical_disks                 = $poolDisks
                }
            }
            $data["storage_pools"] = $pools
        } else {
            $data["storage_pools"] = @()
        }
    } catch {
        $data["storage_pools"] = @()
    }

    # 6. Virtual disks (Server 2012+ Storage Spaces — RAID/parity info)
    try {
        if (Get-Command Get-VirtualDisk -ErrorAction SilentlyContinue) {
            $vds = @()
            Get-VirtualDisk -ErrorAction Stop | ForEach-Object {
                $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
                $vds += [ordered]@{
                    friendly_name              = $_.FriendlyName
                    health_status              = "$($_.HealthStatus)"
                    operational_status         = "$($_.OperationalStatus)"
                    size_gb                    = $sizeGB
                    resiliency_setting         = "$($_.ResiliencySettingName)"
                    number_of_columns          = $_.NumberOfColumns
                    interleave_bytes           = $_.Interleave
                    physical_disk_redundancy   = $_.PhysicalDiskRedundancy
                    number_of_data_copies      = $_.NumberOfDataCopies
                    is_deduplication_enabled   = $_.IsDeduplicationEnabled
                }
            }
            $data["virtual_disks"] = $vds
        } else {
            $data["virtual_disks"] = @()
        }
    } catch {
        $data["virtual_disks"] = @()
    }

    # 7. Storage subsystems (Server 2012+)
    try {
        if (Get-Command Get-StorageSubSystem -ErrorAction SilentlyContinue) {
            $subs = @()
            Get-StorageSubSystem -ErrorAction Stop | ForEach-Object {
                $subs += [ordered]@{
                    friendly_name      = $_.FriendlyName
                    model              = $_.Model
                    manufacturer       = $_.Manufacturer
                    health_status      = "$($_.HealthStatus)"
                    operational_status = "$($_.OperationalStatus)"
                }
            }
            $data["storage_subsystems"] = $subs
        } else {
            $data["storage_subsystems"] = @()
        }
    } catch {
        $data["storage_subsystems"] = @()
    }

    # 8. Disks via Get-Disk (Server 2012+)
    try {
        if (Get-Command Get-Disk -ErrorAction SilentlyContinue) {
            $disks = @()
            Get-Disk -ErrorAction Stop | ForEach-Object {
                $sizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
                $disks += [ordered]@{
                    number             = $_.Number
                    friendly_name      = $_.FriendlyName
                    partition_style    = "$($_.PartitionStyle)"
                    operational_status = "$($_.OperationalStatus)"
                    health_status      = "$($_.HealthStatus)"
                    size_gb            = $sizeGB
                    is_boot            = $_.IsBoot
                    is_system          = $_.IsSystem
                    is_offline         = $_.IsOffline
                }
            }
            $data["disks"] = $disks
        } else {
            $data["disks"] = @()
        }
    } catch {
        $data["disks"] = @()
    }

    # 9. RAID / storage controllers (WMI — works on all Windows versions)
    try {
        $ctrls = @()
        Get-CimInstance Win32_SCSIController -ErrorAction Stop | ForEach-Object {
            $ctrls += [ordered]@{
                name         = $_.Name
                manufacturer = $_.Manufacturer
                driver_name  = $_.DriverName
                status       = $_.Status
            }
        }
        $data["raid_controllers"] = $ctrls
    } catch {
        $data["raid_controllers"] = @()
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Section: Hardware Inventory
# ═══════════════════════════════════════════════════════════════
function Collect-HardwareInventory {
    $data = [ordered]@{}

    # 1. Motherboard / Baseboard
    try {
        $bb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
        $data["baseboard"] = [ordered]@{
            manufacturer  = $bb.Manufacturer
            product       = $bb.Product
            serial_number = $bb.SerialNumber
            version       = $bb.Version
            status        = $bb.Status
        }
    } catch {
        $data["baseboard"] = $null
    }

    # 2. Memory modules (DIMMs)
    try {
        $dimms = @()
        Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | ForEach-Object {
            $sizeGB = if ($_.Capacity) { [math]::Round($_.Capacity / 1GB, 2) } else { 0 }
            $memType = switch ($_.SMBIOSMemoryType) {
                20 {"DDR"} 21 {"DDR2"} 22 {"DDR2 FB-DIMM"} 24 {"DDR3"} 26 {"DDR4"} 34 {"DDR5"} default {"Type $($_.SMBIOSMemoryType)"}
            }
            $dimms += [ordered]@{
                bank_label     = $_.BankLabel
                device_locator = $_.DeviceLocator
                capacity_gb    = $sizeGB
                speed_mhz      = $_.Speed
                configured_speed_mhz = $_.ConfiguredClockSpeed
                memory_type    = $memType
                form_factor    = "$($_.FormFactor)"
                manufacturer   = $_.Manufacturer
                part_number    = ($_.PartNumber -replace '\s+$','')
                serial_number  = $_.SerialNumber
                data_width     = $_.DataWidth
                total_width    = $_.TotalWidth
            }
        }
        $data["memory_modules"] = $dimms
        $data["memory_total_gb"] = ($dimms | Measure-Object -Property capacity_gb -Sum).Sum
        $data["memory_slot_count"] = $dimms.Count
        # Check for ECC (TotalWidth > DataWidth indicates ECC)
        $data["memory_ecc"] = ($dimms | Where-Object { $_.total_width -gt $_.data_width }).Count -gt 0
    } catch {
        $data["memory_modules"] = @()
        $data["memory_total_gb"] = 0
        $data["memory_slot_count"] = 0
        $data["memory_ecc"] = $null
    }

    # 3. GPU / Video adapters
    try {
        $gpus = @()
        Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object {
            $vramGB = if ($_.AdapterRAM -and $_.AdapterRAM -gt 0) { [math]::Round($_.AdapterRAM / 1GB, 2) } else { 0 }
            $gpus += [ordered]@{
                name            = $_.Name
                adapter_ram_gb  = $vramGB
                driver_version  = $_.DriverVersion
                driver_date     = if ($_.DriverDate) { $_.DriverDate.ToString("o") } else { $null }
                video_processor = $_.VideoProcessor
                status          = $_.Status
                pnp_device_id   = $_.PNPDeviceID
                current_resolution = "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)"
            }
        }
        $data["gpu_adapters"] = $gpus
    } catch {
        $data["gpu_adapters"] = @()
    }

    # 4. USB devices (connected)
    try {
        $usb = @()
        Get-CimInstance Win32_USBControllerDevice -ErrorAction Stop | ForEach-Object {
            $dep = $_.Dependent
            if ($dep -match 'DeviceID="(.+)"') {
                $devId = $Matches[1] -replace '\\\\','\\'
                $devInfo = Get-CimInstance Win32_PnPEntity -Filter "DeviceID='$($devId -replace "'","''")'" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($devInfo) {
                    $usb += [ordered]@{
                        name       = $devInfo.Name
                        device_id  = $devInfo.DeviceID
                        status     = $devInfo.Status
                        class      = $devInfo.PNPClass
                        manufacturer = $devInfo.Manufacturer
                    }
                }
            }
        }
        $data["usb_devices"] = $usb
    } catch {
        $data["usb_devices"] = @()
    }

    # 5. PCI devices
    try {
        $pci = @()
        Get-CimInstance Win32_PnPEntity -Filter "PNPClass='System' OR PNPClass='Display' OR PNPClass='Net' OR PNPClass='SCSIAdapter' OR PNPClass='HDC'" -ErrorAction Stop | ForEach-Object {
            if ($_.DeviceID -and $_.DeviceID -match "^PCI\\") {
                $pci += [ordered]@{
                    name       = $_.Name
                    device_id  = $_.DeviceID
                    class      = $_.PNPClass
                    status     = $_.Status
                    manufacturer = $_.Manufacturer
                }
            }
        }
        $data["pci_devices"] = $pci
    } catch {
        $data["pci_devices"] = @()
    }

    # 6. Network adapters (physical only, with MAC and speed)
    try {
        $nics = @()
        Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" -ErrorAction Stop | ForEach-Object {
            $speedMbps = if ($_.Speed) { [math]::Round($_.Speed / 1000000, 0) } else { $null }
            $nics += [ordered]@{
                name            = $_.Name
                mac_address     = $_.MACAddress
                speed_mbps      = $speedMbps
                adapter_type    = $_.AdapterType
                manufacturer    = $_.Manufacturer
                net_connection_status = "$($_.NetConnectionStatus)"
                pnp_device_id   = $_.PNPDeviceID
            }
        }
        $data["network_adapters"] = $nics
    } catch {
        $data["network_adapters"] = @()
    }

    # 7. Battery / UPS (relevant for laptops and rackmounts with UPS)
    try {
        $batteries = @()
        Get-CimInstance Win32_Battery -ErrorAction Stop | ForEach-Object {
            $batteries += [ordered]@{
                name               = $_.Name
                status             = $_.Status
                estimated_charge   = $_.EstimatedChargeRemaining
                battery_status     = switch ($_.BatteryStatus) { 1 {"Discharging"} 2 {"AC Power"} 3 {"Fully Charged"} 4 {"Low"} 5 {"Critical"} default {"$($_.BatteryStatus)"} }
                chemistry          = switch ($_.Chemistry) { 1 {"Other"} 2 {"Unknown"} 3 {"Lead Acid"} 4 {"Nickel Cadmium"} 5 {"Nickel Metal Hydride"} 6 {"Lithium-ion"} 7 {"Zinc Air"} 8 {"Lithium Polymer"} default {"$($_.Chemistry)"} }
                design_voltage     = $_.DesignVoltage
            }
        }
        $data["batteries"] = $batteries
    } catch {
        $data["batteries"] = @()
    }

    # 8. Processor details (extended beyond system_info)
    try {
        $cpus = @()
        Get-CimInstance Win32_Processor -ErrorAction Stop | ForEach-Object {
            $cpus += [ordered]@{
                name                  = $_.Name
                device_id             = $_.DeviceID
                cores                 = $_.NumberOfCores
                logical_processors    = $_.NumberOfLogicalProcessors
                max_clock_speed_mhz   = $_.MaxClockSpeed
                current_clock_speed_mhz = $_.CurrentClockSpeed
                l2_cache_kb           = $_.L2CacheSize
                l3_cache_kb           = $_.L3CacheSize
                architecture          = switch ($_.Architecture) { 0 {"x86"} 5 {"ARM"} 9 {"x64"} 12 {"ARM64"} default {"$($_.Architecture)"} }
                status                = $_.Status
                manufacturer          = $_.Manufacturer
                socket                = $_.SocketDesignation
                virtualization_enabled = $_.VirtualizationFirmwareEnabled
            }
        }
        $data["processors"] = $cpus
    } catch {
        $data["processors"] = @()
    }

    # 9. Power plan
    try {
        if (Get-Command powercfg -ErrorAction SilentlyContinue) {
            $active = & powercfg /getactivescheme 2>$null
            $data["active_power_plan"] = if ($active) { ($active -replace '^.*:\s*','').Trim() } else { $null }
        } else {
            $data["active_power_plan"] = $null
        }
    } catch {
        $data["active_power_plan"] = $null
    }

    return $data
}


# ═══════════════════════════════════════════════════════════════
# Main execution
# ═══════════════════════════════════════════════════════════════

if (-not $Quiet) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗"
    Write-Host "║         Dredge Collection Script v$DredgeVersion           ║"
    Write-Host "║     Windows Endpoint Security Auditor               ║"
    Write-Host "╚══════════════════════════════════════════════════════╝"
    Write-Host ""
    Write-Host "  Hostname : $Hostname"
    Write-Host "  Output   : $OutputFile"
    Write-Host "  Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    if ($Skip.Count -gt 0) { Write-Host "  Skipping : $($Skip -join ', ')" }
    if ($NoHash) { Write-Host "  Hashing  : Disabled" }
    Write-Host ""
}

# Section dispatcher
$SectionMap = [ordered]@{
    "system_info"         = { Collect-SystemInfo }
    "updates"             = { Collect-WindowsUpdate }
    "installed_software"  = { Collect-InstalledSoftware }
    "network_config"      = { Collect-NetworkConfig }
    "open_ports"          = { Collect-OpenPorts }
    "active_connections"  = { Collect-ActiveConnections }
    "firewall"            = { Collect-Firewall }
    "processes"           = { Collect-Processes }
    "services"            = { Collect-Services }
    "scheduled_tasks"     = { Collect-ScheduledTasks }
    "user_accounts"       = { Collect-UserAccounts }
    "security_policy"     = { Collect-SecurityPolicy }
    "registry_hardening"  = { Collect-RegistryHardening }
    "active_directory"    = { Collect-ActiveDirectory }
    "certificates"        = { Collect-Certificates }
    "shares"              = { Collect-Shares }
    "browser_chrome"      = { Collect-BrowserChrome }
    "browser_edge"        = { Collect-BrowserEdge }
    "browser_firefox"     = { Collect-BrowserFirefox }
    "server_software"     = { Collect-ServerSoftware }
    "remote_management"   = { Collect-RemoteManagement }
    "cloud_software"      = { Collect-CloudSoftware }
    "event_logs"          = { Collect-EventLogs }
    "startup_items"       = { Collect-StartupItems }
    "bitlocker"           = { Collect-BitLocker }
    "windows_backup"      = { Collect-WindowsBackup }
    "credential_exposure"   = { Collect-CredentialExposure }
    "privilege_escalation"  = { Collect-PrivilegeEscalation }
    "defender_detailed"     = { Collect-DefenderDetailed }
    "adcs"                  = { Collect-ADCS }
    "persistence_mechanisms" = { Collect-PersistenceMechanisms }
    "powershell_config"     = { Collect-PowerShellConfig }
    "laps_config"           = { Collect-LAPSConfig }
    "print_config"          = { Collect-PrintConfig }
    "dns_config"            = { Collect-DnsConfig }
    "privacy_artifacts"     = { Collect-PrivacyArtifacts }
    "disk_storage"          = { Collect-DiskStorage }
    "hardware_inventory"    = { Collect-HardwareInventory }
}

$idx = 0
foreach ($section in $SectionMap.Keys) {
    $idx++
    if ($Skip -contains $section) {
        [void]$SectionsSkipped.Add($section)
        continue
    }

    Write-Progress-Step $section $idx

    try {
        $sectionData = & $SectionMap[$section]
        $Result[$section] = $sectionData
        [void]$SectionsCollected.Add($section)
    } catch {
        [void]$SectionsFailed.Add($section)
        [void]$SectionErrors.Add([ordered]@{
            section   = $section
            error     = $_.Exception.Message
            line      = $_.InvocationInfo.ScriptLineNumber
        })
        $Result[$section] = [ordered]@{ error = $_.Exception.Message }
    }
}

# Build final output
$EndTime = Get-Date
$Duration = ($EndTime - $StartTime).TotalSeconds

$Output = [ordered]@{
    dredge_version             = $DredgeVersion
    collection_timestamp       = $StartTime.ToString("o")
    collection_completed       = $EndTime.ToString("o")
    collection_duration_seconds = [math]::Round($Duration, 2)
    hostname                   = $Hostname
    fqdn                       = try { [System.Net.Dns]::GetHostEntry($Hostname).HostName } catch { $Hostname }
    collector_user             = "$env:USERDOMAIN\$env:USERNAME"
    collector_is_admin         = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    sections_collected         = @($SectionsCollected)
    sections_skipped           = @($SectionsSkipped)
    sections_failed            = @($SectionsFailed)
    section_errors             = @($SectionErrors)
}

# Merge section data
foreach ($key in $Result.Keys) {
    $Output[$key] = $Result[$key]
}

# Write JSON
try {
    $json = $Output | ConvertTo-Json -Depth 10 -Compress:$false
    [System.IO.File]::WriteAllText($OutputFile, $json, [System.Text.Encoding]::UTF8)
} catch {
    # Fallback: try with less depth if object is too complex
    try {
        $json = $Output | ConvertTo-Json -Depth 6 -Compress:$false
        [System.IO.File]::WriteAllText($OutputFile, $json, [System.Text.Encoding]::UTF8)
    } catch {
        Write-Error "Failed to write output: $($_.Exception.Message)"
        exit 1
    }
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗"
    Write-Host "║  Collection Complete                                ║"
    Write-Host "╠══════════════════════════════════════════════════════╣"
    Write-Host "║  Sections collected : $($SectionsCollected.Count.ToString().PadLeft(3))                            ║"
    Write-Host "║  Sections skipped   : $($SectionsSkipped.Count.ToString().PadLeft(3))                            ║"
    Write-Host "║  Sections failed    : $($SectionsFailed.Count.ToString().PadLeft(3))                            ║"
    Write-Host "║  Duration           : $([math]::Round($Duration,1).ToString().PadLeft(6))s                       ║"
    Write-Host "╠══════════════════════════════════════════════════════╣"
    Write-Host "║  Output: $($OutputFile.PadRight(42).Substring(0,42)) ║"
    Write-Host "╚══════════════════════════════════════════════════════╝"
    Write-Host ""
    if ($SectionsFailed.Count -gt 0) {
        Write-Host "  Failed sections:" -ForegroundColor Yellow
        foreach ($err in $SectionErrors) {
            Write-Host "    - $($err.section): $($err.error)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

# Return output path for programmatic callers
Write-Output $OutputFile
