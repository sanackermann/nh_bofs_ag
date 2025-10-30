# 🛠️ Avantguard BOF Command Pack (Nighthawk Scripts)

This repository provides a Python wrappers for executing **BOF (Beacon Object File)** commands within **Nighthawk**.
Each command wraps a compiled `.o` object and uses the `Packer` API to prepare parameters for inline BOF execution.

---


## ⚙️ Installation

1. **Clone the repository** into your Nighthawk BOF directory:

   ```bash
   git clone https://github.com/sanackermann/nh_bofs_ag "C:\tools\nighthawk\release-3.7\Bofs\avantguard"
   ```

2. **Load the scripts in Nighthawk:**

   * Open `UI.exe`
   * Go to **Features → Python Modules → Load**
   * Select the file:

     ```
     C:\tools\nighthawk\release-3.7\Bofs\avantguard\avantguard_nh_commands.py
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
   `C:\tools\nighthawk\release-3.7\ThinUI\bin\Release\Nighthawk.xml`
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

| Command                       | Description                                                                                                       | Usage                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **ldapsearch**                | Performs an LDAP search against Active Directory and returns matching objects/attributes.                         | `ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps]` |
| **routeprint**                | Displays the system’s IPv4 routing table and related interface metrics.                                      | `routeprint`                                               |
| **netGroupList**              | Lists all groups in the current or specified Active Directory domain.                                             | `netGroupList [domain]`                                    |
| **netGroupListMembers**       | Lists members of a specified domain group.                                                                        | `netGroupListMembers "<Group Name>" [domain]`              |
| **netLocalGroupList**         | Lists all local groups on the current or specified server.                                                        | `netLocalGroupList [server]`                               |
| **netLocalGroupListMembers**  | Lists members of a specified local group on the current or specified server.                                      | `netLocalGroupListMembers "<Group Name>" [server]`         |
| **netLocalGroupListMembers2** | Lists members of a specified local group (output compatible with BofHound).                                       | `netLocalGroupListMembers2 "<Group Name>" [server]`        |
| **reg_query**                 | Queries a registry key or value on the local or a remote host.                                                    | `reg_query [hostname] <hive> <path> [value]`               |
| **reg_query_recursive**       | Recursively enumerates a registry key and subkeys.                                                                | `reg_query_recursive [hostname] <hive> <path>`             |
| **adcs_enum**                 | Enumerates Certificate Authorities (CAs) and certificate templates in Active Directory using Win32 APIs.          | `adcs_enum [domain]`                                       |
| **adcs_enum_com**             | Enumerates CAs and templates using the `ICertConfig`, `ICertRequest`, and `IX509CertificateTemplate` COM objects. | `adcs_enum_com`                                            |
| **adcs_enum_com2**            | Enumerates CAs and templates using the `IX509PolicyServerListManager` and related COM objects.                    | `adcs_enum_com2`                                           |
| **ipconfig**                  | Runs an internal `ipconfig` equivalent, listing network adapters, hostname, and DNS servers.                      | `ipconfig`                                                 |

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
```
