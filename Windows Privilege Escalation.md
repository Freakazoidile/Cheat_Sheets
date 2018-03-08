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

The following command will use WMIC to list a service name, it's display name, the path of the executable and the start mode while grepping (findstr) for any entry without a quote (").
For details on how to exploit this and why this is vulnerable check out [Pentest Blog](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
)
```wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """```

