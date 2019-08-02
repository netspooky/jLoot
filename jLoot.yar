rule PASSWORD : secret { 
meta:
  Author = "netspooky"
  Description = "Checks for password related strings"
strings:
   $str0 = "password" nocase
   $str1 = "passphrase" nocase
condition:
   any of them
}

rule PRIVKEY : secret { 
meta:
  Author = "netspooky"
  Description = "Checks for keys"
strings:
   $str0 = "BEGIN RSA"
condition:
   $str0
}

rule BASICAUTH : secret { 
meta:
  Author = "netspooky"
  Description = "Checks for basic auth related terms"
strings:
   $str0 = "AuthType Basic"
   $str1 = ".htpasswd"
   $str2 = "Authorization: Basic"
condition:
   any of them
}

rule DEVNOTE : secret { 
meta:
  Author = "netspooky"
  Description = "Checks for developer notes"
strings:
   $str0 = "TODO"
   $str1 = "FIXME"
   $str2 = "NOTE"
   $str4 = "fixed" nocase
condition:
   any of them
}

rule KNOWNVULN : secret { 
meta:
  Author = "netspooky"
  Description = "Checks for discussions about bugs"
strings:
   $str0 = "bug" nocase
   $str1 = "issue" nocase
   $str2 = "vuln" nocase
   $str3 = "hotfix" nocase
condition:
   any of them
}

rule MISCAUTH : secret { 
meta:
  Author = "netspooky"
  Description = "Checks for misc auth related terms"
strings:
   $str0 = "login" nocase
   $str1 = "token" nocase
   $str2 = "secret" nocase
   $str3 = "private" nocase
   $str4 = "root" nocase
   $str5 = "key" nocase
   $str6 = "auth" nocase
   $str7 = "access" nocase
   $str8 = "keystore" nocase
condition:
   any of them
}

rule DATABASE : secret {
meta:
  Author = "netspooky"
  Description = "Checks for database related terms"
strings:
   $str0 = ".db"
   $str1 = "database" nocase
   $str2 = "mongo" nocase
   $str3 = "postgres" nocase
   $str4 = "mysql" nocase
   $str5 = "psql" nocase
   $str6 = "cqlsh" nocase
   $str7 = "sql" nocase
   $str8 = "sqlite" nocase
condition:
   any of them
}

rule OX0BANANA : secret {
meta:
  Author = "0x0Banana"
  Description = "Misc rules by 0x0banana"
strings:
   $str0 = ".squashfs" nocase
   $str1 = "elastic" nocase
   $str2 = "privkey"
   $str3 = "WWW-Authenticate"
   $str4 = ".htaccess"
   $str5 = "id_rsa"
   $str6 = "WONTFIX"
   $str7 = ".gitconfig"
   $str8 = ".bash_history"
   $str9 = "apikey" nocase

condition:
   any of them
}