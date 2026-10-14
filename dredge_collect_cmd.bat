@echo off
setlocal enabledelayedexpansion
REM ═══════════════════════════════════════════════════════════════
REM  Dredge CMD Collector — Pure CMD backup for PS-blocked systems
REM  Version: 1.8.0
REM  Works on: Windows Server 2012+ / Windows 7+ (cmd.exe only)
REM  Usage: dredge_collect_cmd.bat [OutputPath]
REM ═══════════════════════════════════════════════════════════════

set "DREDGE_VERSION=1.8.0"
set "HOSTNAME=%COMPUTERNAME%"

REM --- Build timestamp ---
for /f "tokens=1-6 delims=/:. " %%a in ("%DATE% %TIME%") do (
    set "DT_RAW=%%a%%b%%c_%%d%%e%%f"
)
REM Fallback: use wmic for locale-independent timestamp
for /f "skip=1 tokens=1" %%t in ('wmic os get localdatetime 2^>nul') do (
    if not "%%t"=="" (
        set "WMIC_DT=%%t"
        goto :got_ts
    )
)
:got_ts
if defined WMIC_DT (
    set "TS=%WMIC_DT:~0,4%%WMIC_DT:~4,2%%WMIC_DT:~6,2%_%WMIC_DT:~8,2%%WMIC_DT:~10,2%%WMIC_DT:~12,2%"
    set "TS_DISPLAY=%WMIC_DT:~0,4%-%WMIC_DT:~4,2%-%WMIC_DT:~6,2% %WMIC_DT:~8,2%:%WMIC_DT:~10,2%:%WMIC_DT:~12,2%"
) else (
    set "TS=%DT_RAW%"
    set "TS_DISPLAY=%DATE% %TIME%"
)

REM --- Output directory ---
set "BASE_DIR=%~1"
if "%BASE_DIR%"=="" set "BASE_DIR=."
set "OUT_DIR=%BASE_DIR%\dredge_cmd_%HOSTNAME%_%TS%"
mkdir "%OUT_DIR%" 2>nul
if errorlevel 1 (
    echo ERROR: Cannot create output directory: %OUT_DIR%
    exit /b 1
)

set "SECTIONS_FILE=%OUT_DIR%\_sections.txt"
set "META_FILE=%OUT_DIR%\meta.txt"
set "COLLECTOR_LOG=%OUT_DIR%\collector.log"
set "SECT_COUNT=0"
set "SECT_FAIL=0"
set "TOTAL_SECTIONS=39"

echo.
echo ===================================================================
echo   Dredge CMD Collector v%DREDGE_VERSION%
echo   Windows Endpoint Security Auditor (CMD Backup)
echo ===================================================================
echo.
echo   Hostname : %HOSTNAME%
echo   Output   : %OUT_DIR%
echo   Started  : %TS_DISPLAY%
echo   User     : %USERDOMAIN%\%USERNAME%
echo.

REM --- Initialize collector log ---
echo Dredge CMD Collector v%DREDGE_VERSION%> "%COLLECTOR_LOG%"
echo Hostname: %HOSTNAME%>> "%COLLECTOR_LOG%"
echo User: %USERDOMAIN%\%USERNAME%>> "%COLLECTOR_LOG%"
echo Started: %TS_DISPLAY%>> "%COLLECTOR_LOG%"
echo Output: %OUT_DIR%>> "%COLLECTOR_LOG%"
echo ===================================================================>> "%COLLECTOR_LOG%"

REM --- Write meta ---
echo Dredge CMD Collector> "%META_FILE%"
echo version=%DREDGE_VERSION%>> "%META_FILE%"
echo hostname=%HOSTNAME%>> "%META_FILE%"
echo collector_user=%USERDOMAIN%\%USERNAME%>> "%META_FILE%"
echo started=%TS_DISPLAY%>> "%META_FILE%"
echo mode=cmd_backup>> "%META_FILE%"

REM --- Start time (seconds since midnight for elapsed calc) ---
for /f "tokens=1-3 delims=:." %%a in ("%TIME: =0%") do (
    set /a "START_SEC=(%%a * 3600) + (%%b * 60) + %%c"
)

REM ═══════════════════════════════════════════════════════════════
REM  Section 1: System Information
REM ═══════════════════════════════════════════════════════════════
call :section_start "system_info" 1
mkdir "%OUT_DIR%\system_info" 2>nul
systeminfo > "%OUT_DIR%\system_info\systeminfo.txt" 2>&1
wmic os list full /format:list > "%OUT_DIR%\system_info\wmic_os.txt" 2>&1
wmic computersystem list full /format:list > "%OUT_DIR%\system_info\wmic_computersystem.txt" 2>&1
wmic bios list full /format:list > "%OUT_DIR%\system_info\wmic_bios.txt" 2>&1
wmic cpu list full /format:list > "%OUT_DIR%\system_info\wmic_cpu.txt" 2>&1
wmic timezone list full /format:list > "%OUT_DIR%\system_info\wmic_timezone.txt" 2>&1
bcdedit /enum "{current}" > "%OUT_DIR%\system_info\bcdedit.txt" 2>&1
call :section_end "system_info"

REM ═══════════════════════════════════════════════════════════════
REM  Section 2: Windows Update
REM ═══════════════════════════════════════════════════════════════
call :section_start "updates" 2
mkdir "%OUT_DIR%\updates" 2>nul
wmic qfe list full /format:csv > "%OUT_DIR%\updates\qfe_list.csv" 2>&1
sc query wuauserv > "%OUT_DIR%\updates\wuauserv_status.txt" 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /s > "%OUT_DIR%\updates\wsus_policy.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /s > "%OUT_DIR%\updates\au_policy.txt" 2>nul
call :section_end "updates"

REM ═══════════════════════════════════════════════════════════════
REM  Section 3: Installed Software
REM ═══════════════════════════════════════════════════════════════
call :section_start "installed_software" 3
mkdir "%OUT_DIR%\installed_software" 2>nul
wmic product list full /format:csv > "%OUT_DIR%\installed_software\wmic_product.csv" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%OUT_DIR%\installed_software\uninstall_hklm.txt" 2>nul
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%OUT_DIR%\installed_software\uninstall_hklm_wow64.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s > "%OUT_DIR%\installed_software\uninstall_hkcu.txt" 2>nul
call :section_end "installed_software"

REM ═══════════════════════════════════════════════════════════════
REM  Section 4: Network Configuration
REM ═══════════════════════════════════════════════════════════════
call :section_start "network_config" 4
mkdir "%OUT_DIR%\network_config" 2>nul
ipconfig /all > "%OUT_DIR%\network_config\ipconfig.txt" 2>&1
route print > "%OUT_DIR%\network_config\route_print.txt" 2>&1
arp -a > "%OUT_DIR%\network_config\arp_table.txt" 2>&1
nbtstat -n > "%OUT_DIR%\network_config\nbtstat_n.txt" 2>&1
netsh interface show interface > "%OUT_DIR%\network_config\interfaces.txt" 2>&1
netsh interface ip show config > "%OUT_DIR%\network_config\ip_config.txt" 2>&1
netsh interface ip show dns > "%OUT_DIR%\network_config\dns_servers.txt" 2>&1
wmic nicconfig where "IPEnabled=True" list full /format:list > "%OUT_DIR%\network_config\wmic_nicconfig.txt" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable > "%OUT_DIR%\network_config\proxy_settings.txt" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer >> "%OUT_DIR%\network_config\proxy_settings.txt" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL >> "%OUT_DIR%\network_config\proxy_settings.txt" 2>nul
call :section_end "network_config"

REM ═══════════════════════════════════════════════════════════════
REM  Section 5: Open Ports
REM ═══════════════════════════════════════════════════════════════
call :section_start "open_ports" 5
mkdir "%OUT_DIR%\open_ports" 2>nul
netstat -ano > "%OUT_DIR%\open_ports\netstat_ano.txt" 2>&1
netstat -anob > "%OUT_DIR%\open_ports\netstat_anob.txt" 2>&1
call :section_end "open_ports"

REM ═══════════════════════════════════════════════════════════════
REM  Section 6: Active Connections
REM ═══════════════════════════════════════════════════════════════
call :section_start "active_connections" 6
mkdir "%OUT_DIR%\active_connections" 2>nul
netstat -ano -p tcp > "%OUT_DIR%\active_connections\tcp_connections.txt" 2>&1
netstat -ano -p udp > "%OUT_DIR%\active_connections\udp_connections.txt" 2>&1
netstat -anob -p tcp > "%OUT_DIR%\active_connections\tcp_connections_named.txt" 2>&1
call :section_end "active_connections"

REM ═══════════════════════════════════════════════════════════════
REM  Section 7: Firewall
REM ═══════════════════════════════════════════════════════════════
call :section_start "firewall" 7
mkdir "%OUT_DIR%\firewall" 2>nul
netsh advfirewall show allprofiles > "%OUT_DIR%\firewall\profiles.txt" 2>&1
netsh advfirewall firewall show rule name=all > "%OUT_DIR%\firewall\rules_all.txt" 2>&1
netsh advfirewall show allprofiles state > "%OUT_DIR%\firewall\state.txt" 2>&1
netsh advfirewall export "%OUT_DIR%\firewall\firewall_export.wfw" > nul 2>&1
call :section_end "firewall"

REM ═══════════════════════════════════════════════════════════════
REM  Section 8: Processes
REM ═══════════════════════════════════════════════════════════════
call :section_start "processes" 8
mkdir "%OUT_DIR%\processes" 2>nul
tasklist /v /fo csv > "%OUT_DIR%\processes\tasklist_verbose.csv" 2>&1
wmic process list full /format:csv > "%OUT_DIR%\processes\wmic_process.csv" 2>&1
wmic process get Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine /format:csv > "%OUT_DIR%\processes\process_detail.csv" 2>&1
call :section_end "processes"

REM ═══════════════════════════════════════════════════════════════
REM  Section 9: Services
REM ═══════════════════════════════════════════════════════════════
call :section_start "services" 9
mkdir "%OUT_DIR%\services" 2>nul
wmic service list full /format:csv > "%OUT_DIR%\services\wmic_service.csv" 2>&1
sc query state= all > "%OUT_DIR%\services\sc_query_all.txt" 2>&1
wmic service get Name,DisplayName,State,StartMode,StartName,PathName /format:csv > "%OUT_DIR%\services\service_summary.csv" 2>&1
call :section_end "services"

REM ═══════════════════════════════════════════════════════════════
REM  Section 10: Scheduled Tasks
REM ═══════════════════════════════════════════════════════════════
call :section_start "scheduled_tasks" 10
mkdir "%OUT_DIR%\scheduled_tasks" 2>nul
schtasks /query /fo csv /v > "%OUT_DIR%\scheduled_tasks\schtasks_verbose.csv" 2>&1
schtasks /query /fo list /v > "%OUT_DIR%\scheduled_tasks\schtasks_list.txt" 2>&1
call :section_end "scheduled_tasks"

REM ═══════════════════════════════════════════════════════════════
REM  Section 11: User Accounts
REM ═══════════════════════════════════════════════════════════════
call :section_start "user_accounts" 11
mkdir "%OUT_DIR%\user_accounts" 2>nul
net user > "%OUT_DIR%\user_accounts\net_user.txt" 2>&1
net localgroup > "%OUT_DIR%\user_accounts\net_localgroup.txt" 2>&1
net localgroup Administrators > "%OUT_DIR%\user_accounts\local_admins.txt" 2>&1
net localgroup "Remote Desktop Users" > "%OUT_DIR%\user_accounts\rdp_users.txt" 2>&1
net localgroup "Backup Operators" > "%OUT_DIR%\user_accounts\backup_operators.txt" 2>&1
wmic useraccount list full /format:csv > "%OUT_DIR%\user_accounts\wmic_useraccount.csv" 2>&1
wmic group list full /format:csv > "%OUT_DIR%\user_accounts\wmic_group.csv" 2>&1
whoami /all > "%OUT_DIR%\user_accounts\whoami_all.txt" 2>&1
net accounts > "%OUT_DIR%\user_accounts\net_accounts.txt" 2>&1
call :section_end "user_accounts"

REM ═══════════════════════════════════════════════════════════════
REM  Section 12: Security Policy
REM ═══════════════════════════════════════════════════════════════
call :section_start "security_policy" 12
mkdir "%OUT_DIR%\security_policy" 2>nul
auditpol /get /category:* > "%OUT_DIR%\security_policy\auditpol.txt" 2>&1
set "SECEDIT_INF=%TEMP%\dredge_secedit_%RANDOM%.inf"
secedit /export /cfg "%SECEDIT_INF%" /quiet > nul 2>&1
if exist "%SECEDIT_INF%" (
    copy "%SECEDIT_INF%" "%OUT_DIR%\security_policy\secedit_export.inf" > nul 2>&1
    del "%SECEDIT_INF%" 2>nul
)
net accounts > "%OUT_DIR%\security_policy\net_accounts.txt" 2>&1
net accounts /domain > "%OUT_DIR%\security_policy\net_accounts_domain.txt" 2>&1
call :section_end "security_policy"

REM ═══════════════════════════════════════════════════════════════
REM  Section 13: Registry Hardening
REM ═══════════════════════════════════════════════════════════════
call :section_start "registry_hardening" 13
mkdir "%OUT_DIR%\registry_hardening" 2>nul

REM UAC
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" > "%OUT_DIR%\registry_hardening\uac.txt" 2>nul

REM LSA
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" > "%OUT_DIR%\registry_hardening\lsa.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Lsa" > "%OUT_DIR%\registry_hardening\lsa_services.txt" 2>nul

REM SMB Server
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" > "%OUT_DIR%\registry_hardening\smb_server.txt" 2>nul

REM SMB Client
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" > "%OUT_DIR%\registry_hardening\smb_client.txt" 2>nul

REM WDigest
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" > "%OUT_DIR%\registry_hardening\wdigest.txt" 2>nul

REM Credential Guard / Device Guard
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /s > "%OUT_DIR%\registry_hardening\device_guard.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags > "%OUT_DIR%\registry_hardening\credential_guard.txt" 2>nul

REM AutoRun
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" > "%OUT_DIR%\registry_hardening\autorun.txt" 2>nul

REM PowerShell logging
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /s > "%OUT_DIR%\registry_hardening\powershell_logging.txt" 2>nul

REM LLMNR
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast > "%OUT_DIR%\registry_hardening\llmnr.txt" 2>nul

REM WPAD
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v Start > "%OUT_DIR%\registry_hardening\wpad.txt" 2>nul

REM DEP / ASLR / Memory
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" > "%OUT_DIR%\registry_hardening\memory_mgmt.txt" 2>nul

REM RDP / Terminal Server
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" > "%OUT_DIR%\registry_hardening\rdp_ts.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" > "%OUT_DIR%\registry_hardening\rdp_tcp.txt" 2>nul

REM Windows Defender policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /s > "%OUT_DIR%\registry_hardening\defender_policy.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /s > "%OUT_DIR%\registry_hardening\defender_config.txt" 2>nul

REM Spectre / Meltdown mitigations
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride > "%OUT_DIR%\registry_hardening\spectre_mitigations.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask >> "%OUT_DIR%\registry_hardening\spectre_mitigations.txt" 2>nul

call :section_end "registry_hardening"

REM ═══════════════════════════════════════════════════════════════
REM  Section 14: Active Directory
REM ═══════════════════════════════════════════════════════════════
call :section_start "active_directory" 14
mkdir "%OUT_DIR%\active_directory" 2>nul
nltest /dclist: > "%OUT_DIR%\active_directory\dclist.txt" 2>&1
nltest /domain_trusts > "%OUT_DIR%\active_directory\domain_trusts.txt" 2>&1
nltest /dsgetsite > "%OUT_DIR%\active_directory\site.txt" 2>&1
net group /domain > "%OUT_DIR%\active_directory\domain_groups.txt" 2>&1
net group "Domain Admins" /domain > "%OUT_DIR%\active_directory\domain_admins.txt" 2>&1
net group "Enterprise Admins" /domain > "%OUT_DIR%\active_directory\enterprise_admins.txt" 2>&1
net group "Schema Admins" /domain > "%OUT_DIR%\active_directory\schema_admins.txt" 2>&1
net group "Account Operators" /domain > "%OUT_DIR%\active_directory\account_operators.txt" 2>&1
net group "Backup Operators" /domain > "%OUT_DIR%\active_directory\backup_operators_domain.txt" 2>&1
net group "Server Operators" /domain > "%OUT_DIR%\active_directory\server_operators.txt" 2>&1
net group "Domain Controllers" /domain > "%OUT_DIR%\active_directory\domain_controllers.txt" 2>&1
gpresult /r > "%OUT_DIR%\active_directory\gpresult.txt" 2>&1
gpresult /z > "%OUT_DIR%\active_directory\gpresult_verbose.txt" 2>&1

REM LDAP signing
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity > "%OUT_DIR%\active_directory\ldap_signing_server.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ldap" /v LDAPClientIntegrity > "%OUT_DIR%\active_directory\ldap_signing_client.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding > "%OUT_DIR%\active_directory\ldap_channel_binding.txt" 2>nul

REM Kerberos
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" > "%OUT_DIR%\active_directory\kerberos_params.txt" 2>nul

REM dsquery if available
where dsquery >nul 2>&1
if not errorlevel 1 (
    dsquery user -limit 0 > "%OUT_DIR%\active_directory\dsquery_users.txt" 2>&1
    dsquery computer -limit 0 > "%OUT_DIR%\active_directory\dsquery_computers.txt" 2>&1
    dsquery group -limit 0 > "%OUT_DIR%\active_directory\dsquery_groups.txt" 2>&1
    dsquery ou -limit 0 > "%OUT_DIR%\active_directory\dsquery_ous.txt" 2>&1
)

call :section_end "active_directory"

REM ═══════════════════════════════════════════════════════════════
REM  Section 15: Certificates
REM ═══════════════════════════════════════════════════════════════
call :section_start "certificates" 15
mkdir "%OUT_DIR%\certificates" 2>nul
certutil -store My > "%OUT_DIR%\certificates\store_my.txt" 2>&1
certutil -store Root > "%OUT_DIR%\certificates\store_root.txt" 2>&1
certutil -store CA > "%OUT_DIR%\certificates\store_ca.txt" 2>&1
certutil -store -user My > "%OUT_DIR%\certificates\store_user_my.txt" 2>&1
certutil -store -user Root > "%OUT_DIR%\certificates\store_user_root.txt" 2>&1
certutil -store -user CA > "%OUT_DIR%\certificates\store_user_ca.txt" 2>&1
call :section_end "certificates"

REM ═══════════════════════════════════════════════════════════════
REM  Section 16: Shares
REM ═══════════════════════════════════════════════════════════════
call :section_start "shares" 16
mkdir "%OUT_DIR%\shares" 2>nul
net share > "%OUT_DIR%\shares\net_share.txt" 2>&1
wmic share list full /format:csv > "%OUT_DIR%\shares\wmic_share.csv" 2>&1
call :section_end "shares"

REM ═══════════════════════════════════════════════════════════════
REM  Section 17: Browser — Chrome
REM ═══════════════════════════════════════════════════════════════
call :section_start "browser_chrome" 17
mkdir "%OUT_DIR%\browser_chrome" 2>nul
reg query "HKLM\SOFTWARE\Google\Chrome" /s > "%OUT_DIR%\browser_chrome\chrome_hklm.txt" 2>nul
reg query "HKCU\SOFTWARE\Google\Chrome" /s > "%OUT_DIR%\browser_chrome\chrome_hkcu.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Google\Chrome" /s > "%OUT_DIR%\browser_chrome\chrome_policy.txt" 2>nul
if exist "%LOCALAPPDATA%\Google\Chrome\User Data" (
    dir /s /b "%LOCALAPPDATA%\Google\Chrome\User Data\*Preferences*" > "%OUT_DIR%\browser_chrome\chrome_profiles.txt" 2>nul
    dir /s /b "%LOCALAPPDATA%\Google\Chrome\User Data\*Extensions*" >> "%OUT_DIR%\browser_chrome\chrome_profiles.txt" 2>nul
)
call :section_end "browser_chrome"

REM ═══════════════════════════════════════════════════════════════
REM  Section 18: Browser — Edge
REM ═══════════════════════════════════════════════════════════════
call :section_start "browser_edge" 18
mkdir "%OUT_DIR%\browser_edge" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Edge" /s > "%OUT_DIR%\browser_edge\edge_hklm.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /s > "%OUT_DIR%\browser_edge\edge_policy.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Edge" /s > "%OUT_DIR%\browser_edge\edge_hkcu.txt" 2>nul
if exist "%LOCALAPPDATA%\Microsoft\Edge\User Data" (
    dir /s /b "%LOCALAPPDATA%\Microsoft\Edge\User Data\*Preferences*" > "%OUT_DIR%\browser_edge\edge_profiles.txt" 2>nul
)
call :section_end "browser_edge"

REM ═══════════════════════════════════════════════════════════════
REM  Section 19: Browser — Firefox
REM ═══════════════════════════════════════════════════════════════
call :section_start "browser_firefox" 19
mkdir "%OUT_DIR%\browser_firefox" 2>nul
reg query "HKLM\SOFTWARE\Mozilla\Mozilla Firefox" /s > "%OUT_DIR%\browser_firefox\firefox_hklm.txt" 2>nul
if exist "%APPDATA%\Mozilla\Firefox\Profiles" (
    dir /s /b "%APPDATA%\Mozilla\Firefox\Profiles" > "%OUT_DIR%\browser_firefox\firefox_profiles.txt" 2>nul
)
reg query "HKLM\SOFTWARE\Policies\Mozilla\Firefox" /s > "%OUT_DIR%\browser_firefox\firefox_policy.txt" 2>nul
call :section_end "browser_firefox"

REM ═══════════════════════════════════════════════════════════════
REM  Section 20: Server Software
REM ═══════════════════════════════════════════════════════════════
call :section_start "server_software" 20
mkdir "%OUT_DIR%\server_software" 2>nul

REM IIS
reg query "HKLM\SOFTWARE\Microsoft\InetStp" > "%OUT_DIR%\server_software\iis.txt" 2>nul
where appcmd >nul 2>&1
if not errorlevel 1 (
    appcmd list site > "%OUT_DIR%\server_software\iis_sites.txt" 2>&1
    appcmd list app > "%OUT_DIR%\server_software\iis_apps.txt" 2>&1
    appcmd list apppool > "%OUT_DIR%\server_software\iis_apppools.txt" 2>&1
)

REM SQL Server
reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server" /s > "%OUT_DIR%\server_software\sql_server.txt" 2>nul

REM Apache (common install locations)
if exist "C:\Apache24" dir /s /b "C:\Apache24\conf\httpd.conf" > "%OUT_DIR%\server_software\apache.txt" 2>nul
if exist "C:\xampp\apache" dir /s /b "C:\xampp\apache\conf\httpd.conf" >> "%OUT_DIR%\server_software\apache.txt" 2>nul

REM DHCP / DNS Server roles
sc query DHCPServer > "%OUT_DIR%\server_software\dhcp_server.txt" 2>&1
sc query DNS > "%OUT_DIR%\server_software\dns_server.txt" 2>&1
sc query NTDS > "%OUT_DIR%\server_software\ad_ds.txt" 2>&1
sc query CertSvc > "%OUT_DIR%\server_software\cert_svc.txt" 2>&1

call :section_end "server_software"

REM ═══════════════════════════════════════════════════════════════
REM  Section 21: Remote Management
REM ═══════════════════════════════════════════════════════════════
call :section_start "remote_management" 21
mkdir "%OUT_DIR%\remote_management" 2>nul

REM WinRM
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM" /s > "%OUT_DIR%\remote_management\winrm_policy.txt" 2>nul
sc query WinRM > "%OUT_DIR%\remote_management\winrm_service.txt" 2>&1
winrm get winrm/config > "%OUT_DIR%\remote_management\winrm_config.txt" 2>&1

REM RDP
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" > "%OUT_DIR%\remote_management\rdp_config.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" > "%OUT_DIR%\remote_management\rdp_tcp_config.txt" 2>nul

REM SSH
sc query sshd > "%OUT_DIR%\remote_management\sshd_service.txt" 2>&1
reg query "HKLM\SOFTWARE\OpenSSH" > "%OUT_DIR%\remote_management\openssh.txt" 2>nul

REM VNC
reg query "HKLM\SOFTWARE\RealVNC" /s > "%OUT_DIR%\remote_management\vnc.txt" 2>nul
reg query "HKLM\SOFTWARE\TightVNC" /s >> "%OUT_DIR%\remote_management\vnc.txt" 2>nul

REM TeamViewer
reg query "HKLM\SOFTWARE\TeamViewer" /s > "%OUT_DIR%\remote_management\teamviewer.txt" 2>nul
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer" /s >> "%OUT_DIR%\remote_management\teamviewer.txt" 2>nul

call :section_end "remote_management"

REM ═══════════════════════════════════════════════════════════════
REM  Section 22: Cloud Software
REM ═══════════════════════════════════════════════════════════════
call :section_start "cloud_software" 22
mkdir "%OUT_DIR%\cloud_software" 2>nul
where az >nul 2>&1 && az --version > "%OUT_DIR%\cloud_software\az_cli.txt" 2>&1
where aws >nul 2>&1 && aws --version > "%OUT_DIR%\cloud_software\aws_cli.txt" 2>&1
where gcloud >nul 2>&1 && gcloud --version > "%OUT_DIR%\cloud_software\gcloud.txt" 2>&1
if exist "%USERPROFILE%\.aws\credentials" echo FOUND: %%USERPROFILE%%\.aws\credentials > "%OUT_DIR%\cloud_software\cloud_cred_locations.txt"
if exist "%USERPROFILE%\.azure\accessTokens.json" echo FOUND: %%USERPROFILE%%\.azure\accessTokens.json >> "%OUT_DIR%\cloud_software\cloud_cred_locations.txt"
if exist "%APPDATA%\gcloud\credentials.db" echo FOUND: %%APPDATA%%\gcloud\credentials.db >> "%OUT_DIR%\cloud_software\cloud_cred_locations.txt"
call :section_end "cloud_software"

REM ═══════════════════════════════════════════════════════════════
REM  Section 23: Event Logs
REM ═══════════════════════════════════════════════════════════════
call :section_start "event_logs" 23
mkdir "%OUT_DIR%\event_logs" 2>nul
wevtutil qe Security /c:200 /f:text /rd:true > "%OUT_DIR%\event_logs\security_recent.txt" 2>&1
wevtutil qe System /c:200 /f:text /rd:true > "%OUT_DIR%\event_logs\system_recent.txt" 2>&1
wevtutil qe Application /c:200 /f:text /rd:true > "%OUT_DIR%\event_logs\application_recent.txt" 2>&1
wevtutil qe "Microsoft-Windows-PowerShell/Operational" /c:200 /f:text /rd:true > "%OUT_DIR%\event_logs\powershell_operational.txt" 2>&1
wevtutil qe "Windows PowerShell" /c:200 /f:text /rd:true > "%OUT_DIR%\event_logs\powershell_classic.txt" 2>&1

REM Failed logons (Event ID 4625)
wevtutil qe Security /q:"*[System[EventID=4625]]" /c:100 /f:text /rd:true > "%OUT_DIR%\event_logs\failed_logons.txt" 2>&1

REM Successful logons (Event ID 4624)
wevtutil qe Security /q:"*[System[EventID=4624]]" /c:100 /f:text /rd:true > "%OUT_DIR%\event_logs\successful_logons.txt" 2>&1

REM Account management events (4720,4722,4723,4724,4725,4726,4738,4740)
wevtutil qe Security /q:"*[System[EventID=4720 or EventID=4722 or EventID=4726 or EventID=4740]]" /c:100 /f:text /rd:true > "%OUT_DIR%\event_logs\account_mgmt.txt" 2>&1

REM Log sizes
wevtutil el > "%OUT_DIR%\event_logs\log_list.txt" 2>&1
for %%L in (Security System Application) do (
    wevtutil gli %%L > "%OUT_DIR%\event_logs\%%L_info.txt" 2>&1
)

call :section_end "event_logs"

REM ═══════════════════════════════════════════════════════════════
REM  Section 24: Startup Items
REM ═══════════════════════════════════════════════════════════════
call :section_start "startup_items" 24
mkdir "%OUT_DIR%\startup_items" 2>nul
wmic startup list full /format:csv > "%OUT_DIR%\startup_items\wmic_startup.csv" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%OUT_DIR%\startup_items\run_hklm.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%OUT_DIR%\startup_items\run_hkcu.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" > "%OUT_DIR%\startup_items\runonce_hklm.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" > "%OUT_DIR%\startup_items\runonce_hkcu.txt" 2>nul
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" > "%OUT_DIR%\startup_items\run_hklm_wow64.txt" 2>nul
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" (
    dir /b "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" > "%OUT_DIR%\startup_items\user_startup_folder.txt" 2>nul
)
if exist "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup" (
    dir /b "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup" > "%OUT_DIR%\startup_items\common_startup_folder.txt" 2>nul
)
call :section_end "startup_items"

REM ═══════════════════════════════════════════════════════════════
REM  Section 25: BitLocker
REM ═══════════════════════════════════════════════════════════════
call :section_start "bitlocker" 25
mkdir "%OUT_DIR%\bitlocker" 2>nul
manage-bde -status > "%OUT_DIR%\bitlocker\status.txt" 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\FVE" /s > "%OUT_DIR%\bitlocker\policy.txt" 2>nul
call :section_end "bitlocker"

REM ═══════════════════════════════════════════════════════════════
REM  Section 26: Windows Backup
REM ═══════════════════════════════════════════════════════════════
call :section_start "windows_backup" 26
mkdir "%OUT_DIR%\windows_backup" 2>nul
wbadmin get versions > "%OUT_DIR%\windows_backup\versions.txt" 2>&1
wbadmin get status > "%OUT_DIR%\windows_backup\status.txt" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsBackup" /s > "%OUT_DIR%\windows_backup\backup_config.txt" 2>nul
sc query wbengine > "%OUT_DIR%\windows_backup\wbengine_service.txt" 2>&1
call :section_end "windows_backup"

REM ═══════════════════════════════════════════════════════════════
REM  Section 27: Credential Exposure
REM ═══════════════════════════════════════════════════════════════
call :section_start "credential_exposure" 27
mkdir "%OUT_DIR%\credential_exposure" 2>nul

REM WDigest plaintext creds
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential > "%OUT_DIR%\credential_exposure\wdigest.txt" 2>nul

REM Cached logon count
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount > "%OUT_DIR%\credential_exposure\cached_logons.txt" 2>nul

REM LSA protection
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL > "%OUT_DIR%\credential_exposure\lsa_protection.txt" 2>nul

REM AutoLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName > "%OUT_DIR%\credential_exposure\autologon.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword >> "%OUT_DIR%\credential_exposure\autologon.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon >> "%OUT_DIR%\credential_exposure\autologon.txt" 2>nul

REM Unattend / sysprep files
echo --- Searching for unattend/sysprep files --- > "%OUT_DIR%\credential_exposure\sensitive_files.txt"
if exist "C:\unattend.xml" echo FOUND: C:\unattend.xml >> "%OUT_DIR%\credential_exposure\sensitive_files.txt"
if exist "C:\Windows\Panther\unattend.xml" echo FOUND: C:\Windows\Panther\unattend.xml >> "%OUT_DIR%\credential_exposure\sensitive_files.txt"
if exist "C:\Windows\Panther\Unattend\unattend.xml" echo FOUND: C:\Windows\Panther\Unattend\unattend.xml >> "%OUT_DIR%\credential_exposure\sensitive_files.txt"
if exist "C:\Windows\system32\sysprep\unattend.xml" echo FOUND: C:\Windows\system32\sysprep\unattend.xml >> "%OUT_DIR%\credential_exposure\sensitive_files.txt"
if exist "C:\Windows\system32\sysprep\Panther\unattend.xml" echo FOUND: C:\Windows\system32\sysprep\Panther\unattend.xml >> "%OUT_DIR%\credential_exposure\sensitive_files.txt"
echo --- Searching for web.config files --- >> "%OUT_DIR%\credential_exposure\sensitive_files.txt"
dir /s /b "C:\inetpub\web.config" >> "%OUT_DIR%\credential_exposure\sensitive_files.txt" 2>nul

REM Credential Manager
cmdkey /list > "%OUT_DIR%\credential_exposure\cmdkey_list.txt" 2>&1

REM WiFi passwords (cleartext)
netsh wlan show profiles > "%OUT_DIR%\credential_exposure\wifi_profiles.txt" 2>&1
for /f "tokens=2 delims=:" %%p in ('netsh wlan show profiles 2^>nul ^| findstr "Profile"') do (
    set "PROFILE=%%p"
    set "PROFILE=!PROFILE:~1!"
    netsh wlan show profile name="!PROFILE!" key=clear >> "%OUT_DIR%\credential_exposure\wifi_passwords.txt" 2>&1
)

call :section_end "credential_exposure"

REM ═══════════════════════════════════════════════════════════════
REM  Section 28: Privilege Escalation
REM ═══════════════════════════════════════════════════════════════
call :section_start "privilege_escalation" 28
mkdir "%OUT_DIR%\privilege_escalation" 2>nul

REM Current privileges
whoami /priv > "%OUT_DIR%\privilege_escalation\whoami_priv.txt" 2>&1
whoami /groups > "%OUT_DIR%\privilege_escalation\whoami_groups.txt" 2>&1

REM AlwaysInstallElevated
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated > "%OUT_DIR%\privilege_escalation\always_install_elevated_hklm.txt" 2>nul
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated > "%OUT_DIR%\privilege_escalation\always_install_elevated_hkcu.txt" 2>nul

REM Unquoted service paths
wmic service get Name,PathName,StartMode,StartName /format:csv > "%OUT_DIR%\privilege_escalation\service_paths.csv" 2>&1

REM Writable PATH directories
echo %PATH% > "%OUT_DIR%\privilege_escalation\system_path.txt" 2>&1

REM Services running as SYSTEM with writable paths
sc query state= all type= service > "%OUT_DIR%\privilege_escalation\all_services.txt" 2>&1

call :section_end "privilege_escalation"

REM ═══════════════════════════════════════════════════════════════
REM  Section 29: Defender Detailed
REM ═══════════════════════════════════════════════════════════════
call :section_start "defender_detailed" 29
mkdir "%OUT_DIR%\defender_detailed" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /s > "%OUT_DIR%\defender_detailed\defender_policy.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /s > "%OUT_DIR%\defender_detailed\defender_status.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s > "%OUT_DIR%\defender_detailed\exclusions.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" > "%OUT_DIR%\defender_detailed\realtime_protection.txt" 2>nul
sc query WinDefend > "%OUT_DIR%\defender_detailed\windefend_service.txt" 2>&1
sc query WdNisSvc > "%OUT_DIR%\defender_detailed\wdnissvc_service.txt" 2>&1

REM Third-party AV via WMI SecurityCenter2
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:list > "%OUT_DIR%\defender_detailed\av_products.txt" 2>&1

call :section_end "defender_detailed"

REM ═══════════════════════════════════════════════════════════════
REM  Section 30: AD Certificate Services
REM ═══════════════════════════════════════════════════════════════
call :section_start "adcs" 30
mkdir "%OUT_DIR%\adcs" 2>nul
certutil -config - -ping > "%OUT_DIR%\adcs\ca_ping.txt" 2>&1
certutil -v -template > "%OUT_DIR%\adcs\templates.txt" 2>&1
certutil -getreg policy\EditFlags > "%OUT_DIR%\adcs\editflags.txt" 2>&1
certutil -TCAInfo > "%OUT_DIR%\adcs\tcainfo.txt" 2>&1
certutil -catemplates > "%OUT_DIR%\adcs\catemplates.txt" 2>&1
call :section_end "adcs"

REM ═══════════════════════════════════════════════════════════════
REM  Section 31: Persistence Mechanisms
REM ═══════════════════════════════════════════════════════════════
call :section_start "persistence_mechanisms" 31
mkdir "%OUT_DIR%\persistence_mechanisms" 2>nul

REM Run/RunOnce keys (duplicated from startup but focused on persistence)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%OUT_DIR%\persistence_mechanisms\run_hklm.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" > "%OUT_DIR%\persistence_mechanisms\runonce_hklm.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%OUT_DIR%\persistence_mechanisms\run_hkcu.txt" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" > "%OUT_DIR%\persistence_mechanisms\runonce_hkcu.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" > "%OUT_DIR%\persistence_mechanisms\runservices_hklm.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce" > "%OUT_DIR%\persistence_mechanisms\runservicesonce_hklm.txt" 2>nul

REM Winlogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit > "%OUT_DIR%\persistence_mechanisms\winlogon_userinit.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell > "%OUT_DIR%\persistence_mechanisms\winlogon_shell.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" /s > "%OUT_DIR%\persistence_mechanisms\winlogon_notify.txt" 2>nul

REM AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs > "%OUT_DIR%\persistence_mechanisms\appinit_dlls.txt" 2>nul
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs >> "%OUT_DIR%\persistence_mechanisms\appinit_dlls.txt" 2>nul

REM Image File Execution Options (debugger hijack)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s > "%OUT_DIR%\persistence_mechanisms\ifeo.txt" 2>nul

REM Scheduled tasks (another copy for persistence context)
schtasks /query /fo csv /v > "%OUT_DIR%\persistence_mechanisms\schtasks.csv" 2>&1

REM WMI event subscriptions (use wmic)
wmic /namespace:\\root\subscription path __EventFilter list full > "%OUT_DIR%\persistence_mechanisms\wmi_eventfilter.txt" 2>&1
wmic /namespace:\\root\subscription path CommandLineEventConsumer list full > "%OUT_DIR%\persistence_mechanisms\wmi_cmdconsumer.txt" 2>&1
wmic /namespace:\\root\subscription path ActiveScriptEventConsumer list full > "%OUT_DIR%\persistence_mechanisms\wmi_scriptconsumer.txt" 2>&1

REM Services (for persistence analysis)
wmic startup list full /format:csv > "%OUT_DIR%\persistence_mechanisms\wmic_startup.csv" 2>&1

call :section_end "persistence_mechanisms"

REM ═══════════════════════════════════════════════════════════════
REM  Section 32: PowerShell Config
REM ═══════════════════════════════════════════════════════════════
call :section_start "powershell_config" 32
mkdir "%OUT_DIR%\powershell_config" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /s > "%OUT_DIR%\powershell_config\policy.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\PowerShell" /s > "%OUT_DIR%\powershell_config\installed.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" > "%OUT_DIR%\powershell_config\scriptblock_logging.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" > "%OUT_DIR%\powershell_config\module_logging.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" > "%OUT_DIR%\powershell_config\transcription.txt" 2>nul
call :section_end "powershell_config"

REM ═══════════════════════════════════════════════════════════════
REM  Section 33: LAPS Config
REM ═══════════════════════════════════════════════════════════════
call :section_start "laps_config" 33
mkdir "%OUT_DIR%\laps_config" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" > "%OUT_DIR%\laps_config\laps_policy.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" > "%OUT_DIR%\laps_config\laps_native.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Laps" > "%OUT_DIR%\laps_config\laps_new_policy.txt" 2>nul
where AdmPwd.dll >nul 2>&1 && echo LAPS DLL found >> "%OUT_DIR%\laps_config\laps_policy.txt"
call :section_end "laps_config"

REM ═══════════════════════════════════════════════════════════════
REM  Section 34: Print Config
REM ═══════════════════════════════════════════════════════════════
call :section_start "print_config" 34
mkdir "%OUT_DIR%\print_config" 2>nul
sc query Spooler > "%OUT_DIR%\print_config\spooler_service.txt" 2>&1
wmic printer list full /format:list > "%OUT_DIR%\print_config\printers.txt" 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /s > "%OUT_DIR%\print_config\printer_policy.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" > "%OUT_DIR%\print_config\point_and_print.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print" /s > "%OUT_DIR%\print_config\print_control.txt" 2>nul
call :section_end "print_config"

REM ═══════════════════════════════════════════════════════════════
REM  Section 35: DNS Config
REM ═══════════════════════════════════════════════════════════════
call :section_start "dns_config" 35
mkdir "%OUT_DIR%\dns_config" 2>nul
ipconfig /displaydns > "%OUT_DIR%\dns_config\dns_cache.txt" 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" > "%OUT_DIR%\dns_config\dns_server_params.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" > "%OUT_DIR%\dns_config\dns_client_params.txt" 2>nul
nslookup %COMPUTERNAME% > "%OUT_DIR%\dns_config\nslookup_self.txt" 2>&1
call :section_end "dns_config"

REM ═══════════════════════════════════════════════════════════════
REM  Section 36: Privacy Artifacts
REM ═══════════════════════════════════════════════════════════════
call :section_start "privacy_artifacts" 36
mkdir "%OUT_DIR%\privacy_artifacts" 2>nul

REM Recent documents
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" > "%OUT_DIR%\privacy_artifacts\recent_docs.txt" 2>nul

REM Typed URLs
reg query "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" > "%OUT_DIR%\privacy_artifacts\typed_urls.txt" 2>nul

REM UserAssist
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s > "%OUT_DIR%\privacy_artifacts\userassist.txt" 2>nul

REM ShimCache / AppCompatCache
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" > "%OUT_DIR%\privacy_artifacts\shimcache.txt" 2>nul

REM MUI Cache
reg query "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" > "%OUT_DIR%\privacy_artifacts\muicache.txt" 2>nul

REM Run dialog history
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" > "%OUT_DIR%\privacy_artifacts\run_mru.txt" 2>nul

REM PowerShell console history
if exist "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
    copy "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "%OUT_DIR%\privacy_artifacts\ps_history.txt" > nul 2>&1
)

call :section_end "privacy_artifacts"

REM ═══════════════════════════════════════════════════════════════
REM  Section 37: Disk Storage
REM ═══════════════════════════════════════════════════════════════
call :section_start "disk_storage" 37
mkdir "%OUT_DIR%\disk_storage" 2>nul
wmic diskdrive list full /format:csv > "%OUT_DIR%\disk_storage\diskdrive.csv" 2>&1
wmic logicaldisk list full /format:csv > "%OUT_DIR%\disk_storage\logicaldisk.csv" 2>&1
wmic volume list full /format:csv > "%OUT_DIR%\disk_storage\volume.csv" 2>&1
wmic diskdrive get Model,MediaType,Size,Status,InterfaceType /format:csv > "%OUT_DIR%\disk_storage\disk_summary.csv" 2>&1
wmic partition list full /format:csv > "%OUT_DIR%\disk_storage\partitions.csv" 2>&1

REM RAID controller probing — Dell PERC (omreport), LSI/Broadcom (MegaCli64/storcli), HP (hpssacli)
where omreport >nul 2>&1
if not errorlevel 1 (
    echo [RAID] Dell OpenManage detected>> "%COLLECTOR_LOG%"
    omreport storage controller > "%OUT_DIR%\disk_storage\raid_controller.txt" 2>&1
    omreport storage vdisk controller=0 > "%OUT_DIR%\disk_storage\raid_vdisk.txt" 2>&1
    omreport storage pdisk controller=0 > "%OUT_DIR%\disk_storage\raid_pdisk.txt" 2>&1
    omreport storage battery controller=0 > "%OUT_DIR%\disk_storage\raid_battery.txt" 2>&1
    omreport storage enclosure controller=0 > "%OUT_DIR%\disk_storage\raid_enclosure.txt" 2>&1
)
where MegaCli64 >nul 2>&1
if not errorlevel 1 (
    echo [RAID] MegaCli64 detected>> "%COLLECTOR_LOG%"
    MegaCli64 -AdpAllInfo -aALL > "%OUT_DIR%\disk_storage\megacli_adapter.txt" 2>&1
    MegaCli64 -LDInfo -Lall -aALL > "%OUT_DIR%\disk_storage\megacli_vdisk.txt" 2>&1
    MegaCli64 -PDList -aALL > "%OUT_DIR%\disk_storage\megacli_pdisk.txt" 2>&1
    MegaCli64 -AdpBbuCmd -aALL > "%OUT_DIR%\disk_storage\megacli_battery.txt" 2>&1
)
where perccli64 >nul 2>&1
if not errorlevel 1 (
    echo [RAID] perccli64 detected>> "%COLLECTOR_LOG%"
    perccli64 /c0 show all > "%OUT_DIR%\disk_storage\perccli_controller.txt" 2>&1
    perccli64 /c0/vall show all > "%OUT_DIR%\disk_storage\perccli_vdisk.txt" 2>&1
    perccli64 /c0/eall/sall show all > "%OUT_DIR%\disk_storage\perccli_pdisk.txt" 2>&1
)
where storcli64 >nul 2>&1
if not errorlevel 1 (
    echo [RAID] storcli64 detected>> "%COLLECTOR_LOG%"
    storcli64 /c0 show all > "%OUT_DIR%\disk_storage\storcli_controller.txt" 2>&1
    storcli64 /c0/vall show all > "%OUT_DIR%\disk_storage\storcli_vdisk.txt" 2>&1
    storcli64 /c0/eall/sall show all > "%OUT_DIR%\disk_storage\storcli_pdisk.txt" 2>&1
)
where hpssacli >nul 2>&1
if not errorlevel 1 (
    echo [RAID] HP Smart Storage detected>> "%COLLECTOR_LOG%"
    hpssacli ctrl all show config detail > "%OUT_DIR%\disk_storage\hpssa_config.txt" 2>&1
    hpssacli ctrl all show status > "%OUT_DIR%\disk_storage\hpssa_status.txt" 2>&1
)
REM Fallback: check common install paths for RAID tools
if exist "C:\Program Files (x86)\Dell\SysMgt\oma\bin\omreport.exe" (
    echo [RAID] Dell OpenManage at default path>> "%COLLECTOR_LOG%"
    "C:\Program Files (x86)\Dell\SysMgt\oma\bin\omreport.exe" storage controller > "%OUT_DIR%\disk_storage\raid_controller.txt" 2>&1
    "C:\Program Files (x86)\Dell\SysMgt\oma\bin\omreport.exe" storage vdisk controller=0 > "%OUT_DIR%\disk_storage\raid_vdisk.txt" 2>&1
    "C:\Program Files (x86)\Dell\SysMgt\oma\bin\omreport.exe" storage pdisk controller=0 > "%OUT_DIR%\disk_storage\raid_pdisk.txt" 2>&1
    "C:\Program Files (x86)\Dell\SysMgt\oma\bin\omreport.exe" storage battery controller=0 > "%OUT_DIR%\disk_storage\raid_battery.txt" 2>&1
)
if exist "C:\Program Files\MegaRAID\MegaCli\MegaCli64.exe" (
    echo [RAID] MegaCli64 at default path>> "%COLLECTOR_LOG%"
    "C:\Program Files\MegaRAID\MegaCli\MegaCli64.exe" -LDInfo -Lall -aALL > "%OUT_DIR%\disk_storage\megacli_vdisk.txt" 2>&1
    "C:\Program Files\MegaRAID\MegaCli\MegaCli64.exe" -PDList -aALL > "%OUT_DIR%\disk_storage\megacli_pdisk.txt" 2>&1
)

REM Disk-specific Windows event log queries (errors, SMART, NTFS)
wevtutil qe System /q:"*[System[Provider[@Name='disk'] or Provider[@Name='Ntfs'] or Provider[@Name='ntfs'] or Provider[@Name='storahci'] or Provider[@Name='stornvme'] or Provider[@Name='iaStor'] or Provider[@Name='megasas'] or Provider[@Name='percsas'] or Provider[@Name='percsas2'] or Provider[@Name='percsas3'] or Provider[@Name='Microsoft-Windows-StorageSpaces-Driver']]]" /c:500 /f:text /rd:true > "%OUT_DIR%\disk_storage\disk_events.txt" 2>&1
wevtutil qe System /q:"*[System[(EventID=7 or EventID=9 or EventID=11 or EventID=15 or EventID=51 or EventID=52 or EventID=55 or EventID=98 or EventID=129 or EventID=137 or EventID=140 or EventID=153 or EventID=154)]]" /c:500 /f:text /rd:true > "%OUT_DIR%\disk_storage\disk_error_events.txt" 2>&1

REM S.M.A.R.T. status via WMIC
wmic /namespace:\\root\WMI path MSStorageDriver_FailurePredictStatus get Active,InstanceName,PredictFailure,Reason /format:csv > "%OUT_DIR%\disk_storage\smart_status.csv" 2>&1
wmic /namespace:\\root\WMI path MSStorageDriver_FailurePredictData get InstanceName,VendorSpecific /format:csv > "%OUT_DIR%\disk_storage\smart_data.csv" 2>&1

call :section_end "disk_storage"

REM ═══════════════════════════════════════════════════════════════
REM  Section 38: Hardware Inventory
REM ═══════════════════════════════════════════════════════════════
call :section_start "hardware_inventory" 38
mkdir "%OUT_DIR%\hardware_inventory" 2>nul
wmic cpu list full /format:csv > "%OUT_DIR%\hardware_inventory\cpu.csv" 2>&1
wmic memorychip list full /format:csv > "%OUT_DIR%\hardware_inventory\memory.csv" 2>&1
wmic baseboard list full /format:csv > "%OUT_DIR%\hardware_inventory\baseboard.csv" 2>&1
wmic bios list full /format:csv > "%OUT_DIR%\hardware_inventory\bios.csv" 2>&1
wmic nic list full /format:csv > "%OUT_DIR%\hardware_inventory\nic.csv" 2>&1
wmic diskdrive list full /format:csv > "%OUT_DIR%\hardware_inventory\diskdrive.csv" 2>&1
wmic path Win32_VideoController list full /format:csv > "%OUT_DIR%\hardware_inventory\gpu.csv" 2>&1
wmic path Win32_SCSIController list full /format:csv > "%OUT_DIR%\hardware_inventory\scsi.csv" 2>&1
wmic path Win32_USBController list full /format:csv > "%OUT_DIR%\hardware_inventory\usb.csv" 2>&1
wmic path Win32_SoundDevice list full /format:csv > "%OUT_DIR%\hardware_inventory\sound.csv" 2>&1
call :section_end "hardware_inventory"

REM ═══════════════════════════════════════════════════════════════
REM  Section 39: Compliance Data (CIS/NIST/STIG)
REM ═══════════════════════════════════════════════════════════════
call :section_start "compliance_data" 39
mkdir "%OUT_DIR%\compliance_data" 2>nul

REM === Screen Saver Settings (CIS 18.9.11) ===
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveActive > "%OUT_DIR%\compliance_data\screensaver.txt" 2>nul
reg query "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure >> "%OUT_DIR%\compliance_data\screensaver.txt" 2>nul
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut >> "%OUT_DIR%\compliance_data\screensaver.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive >> "%OUT_DIR%\compliance_data\screensaver.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure >> "%OUT_DIR%\compliance_data\screensaver.txt" 2>nul

REM === Interactive Logon Settings (CIS 2.3.7) ===
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeCaption > "%OUT_DIR%\compliance_data\logon_banner.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeText >> "%OUT_DIR%\compliance_data\logon_banner.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs >> "%OUT_DIR%\compliance_data\logon_banner.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName >> "%OUT_DIR%\compliance_data\logon_banner.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ScForceOption >> "%OUT_DIR%\compliance_data\logon_banner.txt" 2>nul

REM === MSS Settings (CIS 18.4) ===
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting > "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NodeType >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveTime >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions >> "%OUT_DIR%\compliance_data\mss_settings.txt" 2>nul

REM === Network Security (CIS 2.3.11) ===
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec > "%OUT_DIR%\compliance_data\network_security.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec >> "%OUT_DIR%\compliance_data\network_security.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal >> "%OUT_DIR%\compliance_data\network_security.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel >> "%OUT_DIR%\compliance_data\network_security.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel >> "%OUT_DIR%\compliance_data\network_security.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey >> "%OUT_DIR%\compliance_data\network_security.txt" 2>nul

REM === Remote Assistance (CIS 18.8.36) ===
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp > "%OUT_DIR%\compliance_data\remote_assistance.txt" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl >> "%OUT_DIR%\compliance_data\remote_assistance.txt" 2>nul

REM === Shutdown Settings (CIS 2.3.13) ===
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ShutdownWithoutLogon > "%OUT_DIR%\compliance_data\shutdown.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ClearPageFileAtShutdown >> "%OUT_DIR%\compliance_data\shutdown.txt" 2>nul

REM === Print Spooler (CIS 18.4.8) ===
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload > "%OUT_DIR%\compliance_data\print_spooler.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting >> "%OUT_DIR%\compliance_data\print_spooler.txt" 2>nul

REM === AutoPlay Detailed (CIS 18.9.8) ===
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun > "%OUT_DIR%\compliance_data\autoplay.txt" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun >> "%OUT_DIR%\compliance_data\autoplay.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume >> "%OUT_DIR%\compliance_data\autoplay.txt" 2>nul

REM === WinRM Security (CIS 18.9.102) ===
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /s > "%OUT_DIR%\compliance_data\winrm_client.txt" 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /s > "%OUT_DIR%\compliance_data\winrm_service.txt" 2>nul

REM === AppLocker / SRP (STIG) ===
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /s > "%OUT_DIR%\compliance_data\applocker_srp.txt" 2>nul

call :section_end "compliance_data"

REM ═══════════════════════════════════════════════════════════════
REM  Summary
REM ═══════════════════════════════════════════════════════════════

REM --- End time ---
for /f "tokens=1-3 delims=:." %%a in ("%TIME: =0%") do (
    set /a "END_SEC=(%%a * 3600) + (%%b * 60) + %%c"
)
set /a "ELAPSED=END_SEC - START_SEC"
if !ELAPSED! lss 0 set /a "ELAPSED=ELAPSED + 86400"

REM --- Update meta ---
echo completed=%DATE% %TIME%>> "%META_FILE%"
echo duration_seconds=!ELAPSED!>> "%META_FILE%"
echo sections_collected=!SECT_COUNT!>> "%META_FILE%"
echo sections_failed=!SECT_FAIL!>> "%META_FILE%"

echo.
echo ===================================================================
echo   Collection Complete
echo -------------------------------------------------------------------
echo   Sections collected : !SECT_COUNT!
echo   Sections failed    : !SECT_FAIL!
echo   Duration           : !ELAPSED!s
echo -------------------------------------------------------------------
echo   Output: %OUT_DIR%
echo ===================================================================
echo.

REM --- Write summary to collector log ---
echo ===================================================================>> "%COLLECTOR_LOG%"
echo Collection Complete>> "%COLLECTOR_LOG%"
echo Sections collected: !SECT_COUNT!>> "%COLLECTOR_LOG%"
echo Sections failed: !SECT_FAIL!>> "%COLLECTOR_LOG%"
echo Duration: !ELAPSED!s>> "%COLLECTOR_LOG%"
echo Completed: %DATE% %TIME%>> "%COLLECTOR_LOG%"

endlocal
exit /b 0


REM ═══════════════════════════════════════════════════════════════
REM  Helper subroutines
REM ═══════════════════════════════════════════════════════════════

:section_start
set "SECT_NAME=%~1"
set "SECT_IDX=%~2"
set /a "SECT_PCT=(SECT_IDX * 100) / TOTAL_SECTIONS"
for /f "tokens=1-3 delims=:." %%a in ("%TIME: =0%") do set "SECT_TS=%%a:%%b:%%c"
echo [!SECT_TS!] [%SECT_PCT%%%] Collecting: %SECT_NAME%
echo [!SECT_TS!] [%SECT_PCT%%%] Collecting: %SECT_NAME%>> "%COLLECTOR_LOG%"
exit /b 0

:section_end
set "SECT_NAME=%~1"
for /f "tokens=1-3 delims=:." %%a in ("%TIME: =0%") do set "END_TS=%%a:%%b:%%c"
echo %SECT_NAME%=OK>> "%SECTIONS_FILE%"
echo [!END_TS!] Completed: %SECT_NAME%>> "%COLLECTOR_LOG%"
set /a "SECT_COUNT+=1"
exit /b 0
