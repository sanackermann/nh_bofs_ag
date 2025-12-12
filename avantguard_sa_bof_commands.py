import json
import base64

def replace_quotes(s):
        return s.strip().strip('"').strip("'")

def write_output(notification, file_name: str, output_to_console: bool):
    notification = json.loads(notification)
    if file_name != "":
        f = open(file_name, "w", encoding="utf-8")
    for output in notification['CommandResponse']['ExecutionResult']['Outputs']:
        line = f"{base64.b64decode(output['buffer']).decode('utf-8', errors='replace')}"
        if output_to_console:
            nighthawk.console_write(CONSOLE_INFO, line )
        if file_name != "":
            f.write(line)
    
    if file_name != "":
        f.close()

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
    save_to_file = ""
    output_to_console = True

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
            elif option == "--save-to-file":
                save_to_file = value
                i += 1
            elif option == "--suppress-console-output":
                output_to_console = False
            else:
                nighthawk.console_write(CONSOLE_ERROR, f"Unknown argument: {arg}")
                nighthawk.console_write(CONSOLE_ERROR, "Usage: ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps] [--save-to-file]")
                return None
            i += 1

    # Pack parameters
    packer = Packer()
    packer.addstr(query)
    packer.addstr(attributes)
    packer.addint32(result_limit)
    packer.addint32(scope)
    packer.addstr(hostname)
    packer.addstr(dn)
    packer.addbool(ldaps)

    packed_params = packer.getbuffer()

    # You can now call your static function
    # static_call(packed_params, info)
    return packed_params, save_to_file, output_to_console

def ldapsearch(params, info):
    with open(nighthawk.script_resource(f"SA/ldapsearch/ldapsearch.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params, save_to_file, output_to_console = ldapsearch_param(params, info)
    if type(packed_params) != bytes:
        return False
    nighthawk.console_write(CONSOLE_INFO, "executing ldapserach BOF")
    notification = api.execute_bof(f"ldapsearch.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", sync=True)
    write_output(notification, save_to_file, output_to_console)
    nighthawk.console_write(CONSOLE_INFO, "Finished executing ldapsearch BOF")

nighthawk.register_command(ldapsearch, "ldapsearch", "BOF - Perform LDAP search (avantguard script)" , "BOF - Perform LDAP search (avantguard script)", """ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps] [--save-to-file]
	with :
		query => the LDAP query to be performed
		--attributes [comma_separated_attributes] => the attributes to retrieve (default: *)
		--count [count] => the result max size (default: None)
		--scope [scope] => the scope to use [1 = BASE, 2 = LEVEL, 3 = SUBTREE] (default: 3)
		--hostname [hostname] => hostname or IP to perform the LDAP connection on (default: automatic DC resolution)
		--dn [dn] => the LDAP query base
		--ldaps => use of ldaps
                --save-to-file => file to write output to
                --suppress-console-output => suppress output to Nighthawk console
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
    with open(nighthawk.script_resource(f"SA/netshares/netshares.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    host = ""
    admin = False
    for i in range(0, len(params)):
        if (params[i] == "--admin"):
            host = params[0]
        else:
            admin = True
    packer = Packer()
    packer.addwstr(host)
    packer.addbool(admin)
    packed_params = packer.getbuffer()
    if type(packed_params) != bytes:
        return False
    nighthawk.console_write(CONSOLE_INFO, "executing netshares BOF")
    api.execute_bof(f"netshares.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True)


nighthawk.register_command(netshares, "netshares", "BOF - list shares on local or remote computer (avantguard script)" , "BOF - list shares on local or remote computer (avantguard script)", """netshares <\\\\computername> <--admin>
with --admin it finds more info then standard netshares but requires admin

THIS IS AN AVANTGUARD SCRIPT""", "netshares \\\\ws21")

# endregion

# region BOF - adcs_enum

def adcs_enum(params, info):
    with open(nighthawk.script_resource(f"SA/adcs_enum/adcs_enum.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    domain = ""
    if len(params) > 0:
        domain = params[0]
    packer = Packer()
    packer.addwstr(domain)
    packed_params = packer.getbuffer()
    if type(packed_params) != bytes:
        return False
    nighthawk.console_write(CONSOLE_INFO, "executing adcs_enum BOF")
    api.execute_bof(f"adcs_enum.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True)


nighthawk.register_command(adcs_enum, "adcs_enum", "BOF - Enumerates CAs and templates in the AD using Win32 functions (avantguard script)" , "BOF - Enumerates CAs and templates in the AD using Win32 functions (avantguard script)", """adcs_enum <domain>
Summary: This command enumerates the certificate authorities and certificate 
         types (templates) in the Acitive Directory Certificate Services using
         undocumented Win32 functions. It displays basic information as well 
         as the CA cert, flags, permissions, and similar information for the 
         templates.
Usage:   adcs_enum (domain)
		 domain		Optional. Specified domain otherwise uses current domain.

THIS IS AN AVANTGUARD SCRIPT""", "adcs_enum CONTOSO.com")

# endregion

# region BOF - adcs_enum_com

def adcs_enum_com(params, info):
    with open(nighthawk.script_resource(f"SA/adcs_enum_com/adcs_enum_com.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    packer = Packer()
    packed_params = packer.getbuffer()  # no parameters for this one

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing adcs_enum_com BOF")
    api.execute_bof(f"adcs_enum_com.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True)


nighthawk.register_command(
    adcs_enum_com,
    "adcs_enum_com",
    "BOF - Enumerates CAs and templates in the AD using ICertConfig COM object (avantguard script)",
    "BOF - Enumerates CAs and templates in the AD using ICertConfig COM object (avantguard script)",
    """adcs_enum_com
Summary: This command enumerates the certificate authorities and certificate 
         types (templates) in the Active Directory Certificate Services using 
         the ICertConfig, ICertRequest, and IX509CertificateTemplate COM 
         objects. It displays basic information as well as the CA cert, flags, 
         permissions, and similar information for the templates.
Usage:   adcs_enum_com

THIS IS AN AVANTGUARD SCRIPT""",
    "adcs_enum_com"
)

# endregion

# region BOF - adcs_enum_com2

def adcs_enum_com2(params, info):
    with open(nighthawk.script_resource(f"SA/adcs_enum_com2/adcs_enum_com2.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    packer = Packer()
    packed_params = packer.getbuffer()  # no parameters for this one either

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing adcs_enum_com2 BOF")
    api.execute_bof(f"adcs_enum_com2.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True)


nighthawk.register_command(
    adcs_enum_com2,
    "adcs_enum_com2",
    "BOF - Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object (avantguard script)",
    "BOF - Enumerates CAs and templates in the AD using IX509PolicyServerListManager COM object (avantguard script)",
    """adcs_enum_com2
Summary: This command enumerates the certificate authorities and certificate 
         types (templates) in the Active Directory Certificate Services using 
         the IX509PolicyServerListManager, IX509PolicyServerUrl, 
         IX509EnrollmentPolicyServer, ICertificationAuthority, and 
         IX509CertificateTemplate COM objects. It displays basic information as
         well as the CA cert, flags, permissions, and similar information for
         the templates.
Usage:   adcs_enum_com2

THIS IS AN AVANTGUARD SCRIPT""",
    "adcs_enum_com2"
)

# endregion

# region BOF - routeprint

def routeprint(params, info):
    with open(nighthawk.script_resource(f"SA/routeprint/routeprint.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packer = Packer()
    packed_params = packer.getbuffer()
    if type(packed_params) != bytes:
        return False
    nighthawk.console_write(CONSOLE_INFO, "executing routeprint BOF")
    api.execute_bof(f"routeprint.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True)


nighthawk.register_command(routeprint, "routeprint", "BOF - prints ipv4 routes on the machine (avantguard script)", "BOF - prints ipv4 routes on the machine (avantguard script)", """prints ipv4 routes on the machine

THIS IS AN AVANTGUARD SCRIPT""", "routeprint ")

# endregion

# region BOF - ipconfig

def ipconfig(params, info):
    with open(nighthawk.script_resource(f"SA/ipconfig/ipconfig.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    packer = Packer()
    packed_params = packer.getbuffer()  # no parameters for ipconfig

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing ipconfig BOF")
    api.execute_bof(
        f"ipconfig.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "T1016",  # matches the MITRE technique from original
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/netgroup/netgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    domain = ""
    if len(params) > 0:
        domain = params[0]

    packer = Packer()
    packer.addshort(0)         # type = 0 (list groups)
    packer.addwstr(domain)     # domain
    packer.addwstr("")         # group (empty)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing netGroupList BOF")
    api.execute_bof(
        f"netgroup.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


nighthawk.register_command(
    netGroupList,
    "netGroupList",
    "BOF - List Groups in this domain (or specified domain if given) (avantguard script)",
    "BOF - List Groups in this domain (or specified domain if given) (avantguard script)",
    """netGroupList <opt: domainname>
Summary: Lists all groups in this domain or the specified domain.
Usage:   netGroupList [domainname]

THIS IS AN AVANTGUARD SCRIPT""",
    "netGroupList CONTOSO.com"
)


def netGroupListMembers(params, info):
    """
    Lists members of the specified domain group
    """
    with open(nighthawk.script_resource(f"SA/netgroup/netgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    group = ""
    domain = ""
    if len(params) > 0:
        group = params[0]
    if len(params) > 1:
        domain = params[1]

    packer = Packer()
    packer.addshort(1)         # type = 1 (list members)
    packer.addwstr(domain)
    packer.addwstr(group)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing netGroupListMembers BOF")
    api.execute_bof(
        f"netgroup.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


nighthawk.register_command(
    netGroupListMembers,
    "netGroupListMembers",
    "BOF - List the members of the specified group in this domain (avantguard script)",
    "BOF - List the members of the specified group in this domain (avantguard script)",
    """netGroupListMembers <Group Name> <opt: domainname>
Summary: Lists the members of the specified group in this domain or another domain.
Usage:   netGroupListMembers "Domain Admins" CONTOSO.com

THIS IS AN AVANTGUARD SCRIPT""",
    "netGroupListMembers \"Domain Admins\" CONTOSO.com"
)

# endregion

# region BOF - netLocalGroupList / netLocalGroupListMembers

def netLocalGroupList(params, info):
    """
    Lists groups in the local server (or specified server if given)
    """
    with open(nighthawk.script_resource(f"SA/netlocalgroup/netlocalgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    server = ""
    if len(params) > 0:
        server = params[0]

    packer = Packer()
    packer.addshort(0)         # type = 0 (list groups)
    packer.addwstr(server)
    packer.addwstr("")         # group (empty)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing netLocalGroupList BOF")
    api.execute_bof(
        f"netlocalgroup.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/netlocalgroup/netlocalgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    group = ""
    server = ""
    if len(params) > 0:
        group = params[0]
    if len(params) > 1:
        server = params[1]

    packer = Packer()
    packer.addshort(1)         # type = 1 (list members)
    packer.addwstr(server)
    packer.addwstr(group)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing netLocalGroupListMembers BOF")
    api.execute_bof(
        f"netlocalgroup.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/netlocalgroup2/netlocalgroup2.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    group = ""
    server = ""
    if len(params) > 0:
        group = params[0]
    if len(params) > 1:
        server = params[1]

    packer = Packer()
    packer.addwstr(server)
    packer.addwstr(group)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing netLocalGroupListMembers2 BOF")
    api.execute_bof(
        f"netlocalgroup2.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/reg_query/reg_query.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    if len(params) < 2:
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
    if params[0].upper() in reghives:
        # Local machine
        hostname = ""
        hive = reghives[params[0].upper()]
        if len(params) >= 2:
            path = params[1]
        if len(params) >= 3:
            key = params[2]
    else:
        # Remote host
        hostname = f"\\\\{params[0]}"
        if len(params) < 2 or params[1].upper() not in reghives:
            nighthawk.console_write(CONSOLE_ERROR, "Invalid or missing hive name.")
            return False
        hive = reghives[params[1].upper()]
        if len(params) >= 3:
            path = params[2]
        if len(params) >= 4:
            key = params[3]

    packer = Packer()
    packer.addstr(hostname)
    packer.addint32(hive)
    packer.addstr(path)
    packer.addstr(key)
    packer.addint32(recursive_flag)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing reg_query BOF")
    api.execute_bof(
        f"reg_query.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/reg_query/reg_query.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    if len(params) < 2:
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

    if params[0].upper() in reghives:
        # Local
        hive = reghives[params[0].upper()]
        if len(params) >= 2:
            path = params[1]
    else:
        # Remote
        hostname = f"\\\\{params[0]}"
        if len(params) < 2 or params[1].upper() not in reghives:
            nighthawk.console_write(CONSOLE_ERROR, "Invalid or missing hive name.")
            return False
        hive = reghives[params[1].upper()]
        if len(params) >= 3:
            path = params[2]

    packer = Packer()
    packer.addstr(hostname)
    packer.addint32(hive)
    packer.addstr(path)
    packer.addstr("")
    packer.addint32(recursive_flag)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing reg_query_recursive BOF")
    api.execute_bof(
        f"reg_query.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "",
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/enumlocalsessions/enumlocalsessions.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    packer = Packer()
    packed_params = packer.getbuffer()  # no parameters for ipconfig

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing enumlocalsessions BOF")
    api.execute_bof(
        f"enumlocalsessions.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "T1033",  # matches the MITRE technique from original
        show_in_console=True
    )


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
    with open(nighthawk.script_resource(f"SA/probe/probe.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()

    port = 0
    server = ""
    if len(params) > 1:
        server = params[0]
        port = int(params[1])
    else:
        nighthawk.console_write(CONSOLE_ERROR, f"!! Usage:   probe <host> <port>")
        return False

    if port < 1 or port > 65535:
        nighthawk.console_write(CONSOLE_ERROR, f"!! Port out of range of 1-65534")
        return False

    packer = Packer()
    packer.addstr(server)
    packer.addint32(port)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    nighthawk.console_write(CONSOLE_INFO, "executing probe BOF")
    api.execute_bof(
        f"probe.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "T1046",
        show_in_console=True
    )


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
