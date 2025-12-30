# 🛠️ Avantguard BOF Command Pack (Nighthawk Scripts)

This repository provides a Python wrapper for executing **BOF (Beacon Object File)** commands within **Nighthawk**.
Each command wraps a compiled `.o` object and uses the `Packer` API to prepare parameters for inline BOF execution.

---


## ⚙️ Installation

1. **Clone the repository** into your Nighthawk BOF directory:

   ```bash
   git clone https://github.com/sanackermann/nh_bofs_ag "C:\tools\nighthawk\release-4.1\Bofs\avantguard"
   ```

2. **Load the scripts in Nighthawk:**

   * Open `UI.exe`
   * Go to **Features → Python Modules → Load**
   * Select the file:

     ```
     C:\tools\nighthawk\release-3.7\Bofs\avantguard\avantguard_bof_commands.py
     C:\tools\nighthawk\release-3.7\Bofs\avantguard\avantguard_sql_bof_commands.py
     ```

3. **If Python is not available or the version is incorrect:**

   * Download the official embedded Python release for Windows:
     👉 [python-3.12.2-embed-amd64.zip](https://www.python.org/ftp/python/3.12.2/python-3.12.2-embed-amd64.zip)
   * Extract it to:

     ```
     C:\tools\python-3.12.2-embed-amd64\
     ```

4. **Configure Nighthawk to use the Python DLL:**

   Edit the following section in
   `C:\tools\nighthawk\release-4.1\ThinUI\bin\Release\Nighthawk.xml`
   to point to your embedded Python installation:

   ```xml
   ...
     <modules-ui>
       <python-dll path="C:\tools\python-3.12.2-embed-amd64\python312.dll" />
       <modules>
       </modules>
     </modules-ui>
   ...
   ```

---

## 🔍 Command Overview

*General commands:*
| Command                           | Description                                                                                               | Usage                                                                                                                                          |      |     |                       |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---- | --- | --------------------- |
| **ldapsearch**                    | Performs an LDAP search against Active Directory and returns matching objects/attributes.                 | `ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps] [--save-to-file] [--suppress-console-output] [--notepad]` |      |     |                       |
| **routeprint**                    | Displays the system’s IPv4 routing table and related interface metrics.                                   | `routeprint`                                                                                                                                   |      |     |                       |
| **netGroupList**                  | Lists all groups in the current or specified Active Directory domain.                                     | `netGroupList [domainname] [--notepad]`                                                                                                        |      |     |                       |
| **netGroupListMembers**           | Lists members of a specified domain group.                                                                | `netGroupListMembers "<Group Name>" [domainname] [--notepad]`                                                                                  |      |     |                       |
| **netLocalGroupList**             | Lists all local groups on the current or specified server.                                                | `netLocalGroupList [servername]`                                                                                                               |      |     |                       |
| **netLocalGroupListMembers**      | Lists members of a specified local group on the current or specified server.                              | `netLocalGroupListMembers "<Group Name>" [servername]`                                                                                         |      |     |                       |
| **netLocalGroupListMembers2**     | Lists members of a specified local group (output compatible with BofHound).                               | `netLocalGroupListMembers2 "<Group Name>" [servername]`                                                                                        |      |     |                       |
| **reg_query**                     | Queries a registry key or value on the local or a remote host.                                            | `reg_query [hostname] <HKLM / HKCU / HKU / HKCR> <path> [value]` |
| **reg_query_recursive**           | Recursively enumerates a registry key and subkeys (local or remote).                                      | `reg_query_recursive [hostname] <HKLM / HKCU / HKU / HKCR>  <path>`         |
| **adcs_enum**                     | Enumerates Certificate Authorities (CAs) and certificate templates using Win32 functions.                 | `adcs_enum [domain] [--notepad]`                                                                                                               |      |     |                       |
| **adcs_enum_com**                 | Enumerates CAs and templates using `ICertConfig`, `ICertRequest`, `IX509CertificateTemplate` COM objects. | `adcs_enum_com [--notepad]`                                                                                                                    |      |     |                       |
| **adcs_enum_com2**                | Enumerates CAs and templates using `IX509PolicyServerListManager` and related COM objects.                | `adcs_enum_com2 [--notepad]`                                                                                                                   |      |     |                       |
| **ipconfig**                      | Runs an internal `ipconfig` equivalent (adapters, hostname, DNS servers).                                 | `ipconfig`                                                                                                                                     |      |     |                       |
| **sql-whoami**                    | Gather information about logged in user, mapped user and roles on a SQL server.                           | `server [database] [linkedserver] [impersonate]`                                                                                               |      |     |                       |
| **sql-info**                      | Gather general information about a SQL server.                                                            | `server [database]`                                                                                                                            |      |     |                       |
| **sql-enablexp**                  | Enable xp_cmdshell.                                                                                       | `server [database] [linkedserver] [impersonate]`                                                                                               |      |     |                       |
| **sql-xpcmd**                     | Execute a system command via xp_cmdshell.                                                                 | `server command [database] [linkedserver] [impersonate]`                                                                                       |      |     |                       |
| **probe**                         | Test a TCP port on a remote host.                                                                         | `probe <host> <port>`                                                                                                                          |      |     |                       |
| **enumlocalsessions**             | Enumerate currently attached user sessions (local and RDP).                                               | `enumlocalsessions`                                                                                                                            |      |     |                       |
| **netshares**                     | Lists shares on a local or remote computer (optional “admin” mode).                                       | `netshares <\\\\computername> [--admin]`                                                                                                       |      |     |                       |
| **scshell64**                     | Uses ChangeServiceConfigA to change a service configuration to run an executable.                         | `scshell64 <target> <service> <exepath>`                                                                                                       |      |     |                       |
| **add_machine_account**           | Adds a computer account to the Active Directory domain (ADSI).                                            | `add_machine_account <computername> <password>`                                                                                                |      |     |                       |
| **del_machine_account**           | Deletes a computer account from the Active Directory domain (ADSI).                                       | `del_machine_account <computername>`                                                                                                           |      |     |                       |
| **get_machine_account_quota**     | Reads the domain’s machine account quota (ms-DS-MachineAccountQuota).                                     | `get_machine_account_quota`                                                                                                                    |      |     |                       |
| **petit_potam**                   | Coerces authentication from a target machine to a listener machine (PetitPotam technique).                | `petit_potam <targetMachine> <listenerMachine>`                                                                                                |      |     |                       |
| **always_install_elevated_check** | Checks for AlwaysInstallElevated misconfiguration (priv-esc check).                                       | `always_install_elevated_check`                                                                                                                |      |     |                       |
| **autologon_check**               | Checks registry for stored AutoLogon credentials.                                                         | `autologon_check`                                                                                                                              |      |     |                       |
| **credential_manager_check**      | Enumerates credentials from Windows Credential Manager for current context.                               | `credential_manager_check`                                                                                                                     |      |     |                       |
| **hijackable_path_check**         | Checks for writable directories in the system PATH.                                                       | `hijackable_path_check`                                                                                                                        |      |     |                       |
| **modifiable_autorun_check**      | Checks autorun registry entries for modifiable/writable executables.                                      | `modifiable_autorun_check`                                                                                                                     |      |     |                       |
| **token_privileges_check**        | Enumerates current token privileges and enabled/disabled status.                                          | `token_privileges_check`                                                                                                                       |      |     |                       |
| **unquoted_svc_path_check**       | Checks for unquoted service paths vulnerability.                                                          | `unquoted_svc_path_check`                                                                                                                      |      |     |                       |
| **powershell_history_check**      | Checks for PowerShell PSReadLine history file.                                                            | `powershell_history_check`                                                                                                                     |      |     |                       |
| **uac_status_check**              | Checks UAC configuration, integrity level, and local admin membership.                                    | `uac_status_check`                                                                                                                             |      |     |                       |
| **modifiable_svc_check**          | Checks for services the current user can modify (service ACL/security descriptor check).                  | `modifiable_svc_check`                                                                                                                         |      |     |                       |
| **priv_check_all**                | Runs all PrivCheck checks in sequence.                                                                    | `priv_check_all`                                                                                                                               |      |     |                       |

*SQL Commands:*

| Command             | Description                                                          | Usage                                                                                  |
| ------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **sql-1434udp**     | Obtain SQL Server connection information via 1434/UDP (SQL Browser). | `sql-1434udp <server_ip>`                                                              |
| **sql-adsi**        | Obtain ADSI credentials from an ADSI linked server.                  | `sql-adsi <server> <ADSI_linkedserver> [port] [database] [linkedserver] [impersonate]` |
| **sql-agentcmd**    | Execute a system command using SQL Agent jobs.                       | `sql-agentcmd <server> <command> [database] [linkedserver] [impersonate]`              |
| **sql-agentstatus** | Enumerate SQL Agent status and jobs.                                 | `sql-agentstatus <server> [database] [linkedserver] [impersonate]`                     |
| **sql-checkrpc**    | Enumerate RPC status of linked servers.                              | `sql-checkrpc <server> [database] [linkedserver] [impersonate]`                        |
| **sql-clr**         | Load and execute a .NET assembly in a stored procedure (CLR).        | `sql-clr <server> <dll_path> <function> [database] [linkedserver] [impersonate]`       |
| **sql-columns**     | Enumerate columns within a given table.                              | `sql-columns <server> <table> [database] [linkedserver] [impersonate]`                 |
| **sql-databases**   | Enumerate SQL databases.                                             | `sql-databases <server> [database] [linkedserver] [impersonate]`                       |
| **sql-disableclr**  | Disable CLR integration.                                             | `sql-disableclr <server> [database] [linkedserver] [impersonate]`                      |
| **sql-disableole**  | Disable OLE Automation Procedures.                                   | `sql-disableole <server> [database] [linkedserver] [impersonate]`                      |
| **sql-disablerpc**  | Disable RPC and RPC Out on a linked server.                          | `sql-disablerpc <server> <linkedserver> [database] [impersonate]`                      |
| **sql-disablexp**   | Disable `xp_cmdshell`.                                               | `sql-disablexp <server> [database] [linkedserver] [impersonate]`                       |
| **sql-enableclr**   | Enable CLR integration.                                              | `sql-enableclr <server> [database] [linkedserver] [impersonate]`                       |
| **sql-enableole**   | Enable OLE Automation Procedures.                                    | `sql-enableole <server> [database] [linkedserver] [impersonate]`                       |
| **sql-enablerpc**   | Enable RPC and RPC Out on a linked server.                           | `sql-enablerpc <server> <linkedserver> [database] [impersonate]`                       |
| **sql-impersonate** | Enumerate users that can be impersonated.                            | `sql-impersonate <server> [database]`                                                  |
| **sql-links**       | Enumerate linked servers.                                            | `sql-links <server> [database] [linkedserver] [impersonate]`                           |
| **sql-olecmd**      | Execute a system command using OLE automation procedures.            | `sql-olecmd <server> <command> [database] [linkedserver] [impersonate]`                |
| **sql-query**       | Execute a custom SQL query.                                          | `sql-query <server> <query> [database] [linkedserver] [impersonate]`                   |
| **sql-rows**        | Get the count of rows in a table.                                    | `sql-rows <server> <table> [database] [linkedserver] [impersonate]`                    |
| **sql-search**      | Search a table for a column name / keyword.                          | `sql-search <server> <keyword> [database] [linkedserver] [impersonate]`                |
| **sql-smb**         | Coerce NetNTLM authentication via `xp_dirtree` to a listener.        | `sql-smb <server> <\\\\listener> [database] [linkedserver] [impersonate]`              |
| **sql-tables**      | Enumerate tables within a database.                                  | `sql-tables <server> [database] [linkedserver] [impersonate]`                          |
| **sql-users**       | Enumerate users with database access.                                | `sql-users <server> [database] [linkedserver] [impersonate]`                           |


---

## ⚙️ Example Usages

```bash
# Enumerate Active Directory CAs
adcs_enum CONTOSO.com

# Query a local registry key
reg_query HKLM Software\\Microsoft\\Windows\\CurrentVersion

# Recursively query a remote registry key
reg_query_recursive DC01 HKCU Software\\Policies

# List all domain groups
netGroupList CONTOSO.com

# List members of a local group
netLocalGroupListMembers "Administrators" SERVER01

# Run internal network configuration
ipconfig

# Get user permissions on SQL server
sql-whoami SQL01

# Gather information about SQL server
sql-info SQL01

# Enable xp_cmd on SQL server
sql-enablexp SQL01

# Run system command on SQL server
sql-xpcmd SQL01 ipconfig
```
