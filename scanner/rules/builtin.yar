// HybridShield built-in YARA rules.
//
// These target behaviours that signature engines commonly miss: ransomware
// notes, credential dumping, PowerShell download cradles, LOLBin abuse, and
// packed/obfuscated loaders.
//
// Every rule is deliberately narrow. A rule that fires on legitimate software
// trains the user to ignore alerts, which is worse than not having the rule.
// Where a pattern is broad, the condition requires corroboration (two strings,
// or a string plus a size bound).
//
// Calibration is empirical, not assumed: tools/sweep_yara.py runs this corpus
// over real files on the machine and tools/verify_yara_fp.py holds the line on
// known false positives. A rule that describes a *filename* property (such as
// a double extension) does not belong here at all - file content cannot see a
// filename. Those live in scanner/reputation.py, which has the path.

rule Ransomware_Note_Text
{
    meta:
        description = "Ransomware ransom note text"
        severity = "critical"
        author = "HybridShield"
    strings:
        $a1 = "your files have been encrypted" nocase
        $a2 = "all your files are encrypted" nocase
        $a3 = "your documents, photos, databases" nocase
        $a4 = "to decrypt your files" nocase
        $a5 = "decryption key" nocase
        $a6 = "send bitcoin" nocase
        $a7 = "send monero" nocase
        $a8 = "tor browser" nocase
        $a9 = "do not rename" nocase
        $a10 = "recover your files" nocase
    condition:
        2 of them
}

rule Ransomware_Extension_Targeting
{
    meta:
        description = "Code enumerating document extensions for mass encryption"
        severity = "high"
        author = "HybridShield"
    strings:
        // Named $ext*, not $e*: $enc and $del also start with "e", so a
        // wildcard set of $e* silently counted the two API strings the
        // condition already required. The rule was effectively
        // "$enc and $del and 1 of (extensions)".
        $ext1 = ".docx" ascii
        $ext2 = ".xlsx" ascii
        $ext3 = ".pdf" ascii
        $ext4 = ".sql" ascii
        $ext5 = ".bak" ascii
        $ext6 = ".jpg" ascii
        $enc = "CryptEncrypt" ascii
        $del = "DeleteFile" ascii
    condition:
        // Four extensions, not three. A genuine mass-encryption list is long;
        // three extension names plus the words CryptEncrypt/DeleteFile is also
        // what a security write-up about ransomware looks like.
        $enc and $del and 4 of ($ext*)
}

rule Credential_Dumping_Strings
{
    meta:
        description = "Credential dumping tooling (LSASS, SAM, Mimikatz patterns)"
        severity = "critical"
        author = "HybridShield"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "kerberos::golden" nocase
        $m4 = "privilege::debug" nocase
        $m5 = "mimikatz" nocase
        $s1 = "lsass.exe" nocase
        $s4 = "MiniDumpWriteDump" ascii
        $dump_call = "MiniDumpWriteDump(" ascii
    condition:
        // The mimikatz module strings are unambiguous.
        //
        // The MiniDumpWriteDump branch needs a *call site*, not a name in an
        // export table. KernelBase.dll lists MiniDumpWriteDump among its
        // exports and lsass.exe among its module strings, so the previous
        // "$s4 and $s1" form flagged a core Windows DLL at critical severity.
        // A real dump passes the process handle into the call.
        any of ($m*) or ($s4 and $s1 and $dump_call)
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute cradle"
        severity = "high"
        author = "HybridShield"
    strings:
        $p1 = "DownloadString" nocase
        $p2 = "DownloadFile" nocase
        $p4 = "Invoke-Expression" nocase
        $p5 = "IEX(" nocase
        // FromBase64String is declared for documentation of the cradle shape but
        // is deliberately NOT in the execution set: it decodes, it does not run.
        $p7 = "-EncodedCommand" nocase
        $p8 = "Net.WebClient" nocase
        $p9 = "Start-BitsTransfer" nocase
        $url = /https?:\/\/[^\s"'<>]{4,}/
        $bypass = "-ExecutionPolicy Bypass" nocase
        // -w hidden is the abbreviated spelling and the one real launches use.
        $hidden = "-WindowStyle Hidden" nocase
        $hidden2 = "-w hidden" nocase
    condition:
        // The cradle idiom needs a *download* primitive, an *execution*
        // primitive, and a remote location. DownloadData alone plus a stray
        // "IEX(" is coincidence: Windows.ApplicationModel.Store.dll contains
        // both and is a signed system binary.
        (($p1 or $p2 or $p8) and ($p4 or $p5) and $url)
        or ($p9 and ($p4 or $p5) and $url)
        or $p7 and ($bypass or $hidden or $hidden2)
}

rule Obfuscated_PowerShell
{
    meta:
        description = "Heavily obfuscated PowerShell payload"
        severity = "high"
        author = "HybridShield"
    strings:
        $b64 = "FromBase64String" nocase
        $iex = "Invoke-Expression" nocase
        // fullword: bare "IEX" matches inside ordinary identifiers ("iex" is a
        // substring of plenty of .NET symbol names), which put this rule on
        // netstandard.dll.
        $iex2 = "IEX" nocase fullword
        $chars = "char[]" nocase
        $join = "-join" nocase
        $replace = "-replace" nocase
    condition:
        // DeflateStream / GZipStream are ordinary .NET class names present in
        // every assembly, so they are no longer corroboration. Obfuscation is
        // base64 plus an exec plus string assembly or substitution.
        $b64 and ($iex or $iex2 or $chars) and ($join or $replace)
}

rule LOLBin_Abuse
{
    meta:
        description = "Living-off-the-land binary used to proxy execution"
        severity = "high"
        author = "HybridShield"
    strings:
        // A LOLBin download has to fetch from somewhere. Requiring a remote
        // location is what separates abuse from the routine admin commands
        // that use the exact same binaries: `certutil -urlcache * delete` is
        // standard Windows housekeeping and must never fire this rule.
        $url = /https?:\/\/[^\s"'<>]{4,}/

        $certutil = "certutil" nocase
        $urlcache = "-urlcache" nocase
        $verifyctl = "-verifyctl" nocase

        $bitsadmin = "bitsadmin" nocase
        $transfer = "/transfer" nocase

        $mshta = "mshta" nocase
        $javascript = "javascript:" nocase
        $vbscript = "vbscript:" nocase

        $regsvr = "regsvr32" nocase
        $scrobj = "scrobj.dll" nocase

        $rundll = "rundll32" nocase

        $wmic = "wmic" nocase
        $process_call = "process call create" nocase
        // wmic targets a host, not a URL: "/node:10.0.0.5" is the normal
        // spelling and carries no scheme, so requiring http:// missed it.
        $node = /\/node:[^\s"']+/ nocase
    condition:
        // The COM-scriptlet branch needs a *caller*: scrobj.dll is the scriptlet
        // engine itself and contains both its own name and regsvr32 for
        // registration, so matching it flagged the engine as abuse of itself.
        ($certutil and ($urlcache or $verifyctl) and $url)
        or ($bitsadmin and $transfer and $url)
        // Script-host and COM-scriptlet abuse carry their payload inline, so
        // the scheme itself is the evidence and no URL is required.
        or ($mshta and ($javascript or $vbscript))
        or ($regsvr and $scrobj and $url)
        or ($rundll and $javascript)
        or ($wmic and $process_call and ($url or $node))
}

rule Process_Injection_APIs
{
    meta:
        description = "Classic process injection API sequence"
        severity = "high"
        author = "HybridShield"
    strings:
        $va = "VirtualAllocEx" ascii
        $wpm = "WriteProcessMemory" ascii
        $crt = "CreateRemoteThread" ascii
        $open = "OpenProcess" ascii
        // A process-injection *tool* names the target it injects into. The four
        // API names alone fired on kernel32.dll (which exports them), on
        // msedge.exe and on MavInject32.exe. Importing an API is not using it
        // for injection, and kernel32 exports all four by definition.
        $target = /(?:lsass|explorer|svchost|winlogon|csrss|services|rundll32)\.exe/i
        // A *caller* contains the call syntax. KernelBase.dll and kernel32.dll
        // list these names in their export table as bare, dot-separated
        // identifiers ("VirtualAlloc2FromApp.VirtualAlloc.VirtualAllocEx..."),
        // so requiring the parenthesis excludes the module that implements the
        // API while keeping anything that actually invokes it.
        $call_va = "VirtualAllocEx(" ascii
        $call_wpm = "WriteProcessMemory(" ascii
        $call_crt = "CreateRemoteThread(" ascii
    condition:
        $va and $wpm and $crt and $open and $target
        and $call_va and $call_wpm and $call_crt
}

rule Anti_Analysis_Checks
{
    meta:
        description = "Sandbox and debugger evasion checks"
        severity = "medium"
        author = "HybridShield"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii
        $dbg2 = "CheckRemoteDebuggerPresent" ascii
        $vm1 = "VBoxService" nocase
        $vm2 = "vmtoolsd" nocase
        $vm3 = "SbieDll.dll" nocase
        $vm4 = "wine_get_unix_file_name" nocase
        $sleep = "NtDelayExecution" ascii
        $timing = "QueryPerformanceCounter" ascii
    condition:
        ($dbg1 or $dbg2) and 1 of ($vm*)
        or $sleep and $timing and 1 of ($vm*)
}

rule Persistence_Registry_Run
{
    meta:
        description = "Registry Run-key persistence"
        severity = "medium"
        author = "HybridShield"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $r2 = "CurrentVersion\\RunOnce" nocase
        $r3 = "Winlogon\\Shell" nocase
        $r4 = "Image File Execution Options" nocase
        $create = "RegSetValue" nocase
        $create2 = "RegCreateKey" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $system = "/ru SYSTEM" nocase
    condition:
        // Needs a hidden window or a SYSTEM account. RegCreateKey plus a Run key
        // is what every installer and updater does; inseng.dll, urlmon.dll,
        // iertutil.dll and steamservice.exe all fired on that alone.
        ($create or $create2) and 1 of ($r*) and ($hidden or $system)
}

rule Scheduled_Task_Persistence
{
    meta:
        description = "Scheduled task creation for persistence"
        severity = "medium"
        author = "HybridShield"
    strings:
        $s1 = "schtasks" nocase
        $s3 = "RegisterTaskDefinition" nocase
        $s4 = "ITaskService" nocase
        // SYSTEM as the task principal. Anchored on a trailing space because a
        // bare flag substring is not a flag: the old bare "/tr" string matched
        // inside "/TRUEHARMONY" in RCoInstII64.dll.
        $hidden = /\/ru\s+SYSTEM/i
        // The schedule is the discriminator. An installer registering its own
        // task writes `/create /Tn %s /XML "%s" /F` and stops there, which is
        // what RCoInstII64.dll does. Persistence wants the task to come back:
        // a recurrence, a logon/boot trigger, or SYSTEM.
        $create = /\/create\s/i
        $sc = /\/sc\s+(?:minute|hourly|daily|weekly|monthly|once|onlogon|onstart|onidle|onevent|boot)/i
    condition:
        // A scheduled-task command needs the full shape: the tool, the create
        // verb, and either a recurrence/trigger or SYSTEM. `/create` plus a
        // task name alone is an installer doing its job.
        ($s1 and $create and ($sc or $hidden))
        // The COM route: a Task Scheduler client that also sets SYSTEM or a
        // recurrence. RegisterTaskDefinition + ITaskService alone is any
        // legitimate scheduler client.
        or ($s3 and $s4 and ($hidden or $sc))
}

rule Webshell_Indicators
{
    meta:
        description = "Web shell code patterns"
        severity = "critical"
        author = "HybridShield"
    strings:
        $php1 = "eval($_POST" nocase
        $php2 = "eval($_GET" nocase
        $php3 = "eval($_REQUEST" nocase
        $php4 = "assert($_POST" nocase
        $php5 = "system($_GET" nocase
        $php5b = "system($_POST" nocase
        $php5c = "system($_REQUEST" nocase
        $php6 = "passthru($_" nocase
        $asp1 = "Request.Form(" nocase
        $asp2 = "Server.CreateObject(\"WScript.Shell\")" nocase
        $jsp1 = "Runtime.getRuntime().exec" nocase
        $b64 = "base64_decode" nocase
    condition:
        any of ($php*) or ($asp1 and $asp2) or $jsp1 or ($b64 and 1 of ($php*))
}

rule Cryptominer_Indicators
{
    meta:
        description = "Cryptocurrency miner indicators"
        severity = "medium"
        author = "HybridShield"
    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = "pool.minexmr" nocase
        $pool4 = "xmrpool" nocase
        $wallet = "monero" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "cryptonight" nocase
        $miner3 = "randomx" nocase
    condition:
        // A pool URL is unambiguous. The wallet+miner branch needs two miner
        // terms, because "Monero" and "RandomX" both appear in ordinary
        // reporting about cryptocurrency.
        1 of ($pool*) or ($wallet and 2 of ($miner*)) or 3 of ($miner*)
}

rule Suspicious_Base64_Blob
{
    meta:
        description = "Large embedded base64 payload"
        severity = "low"
        author = "HybridShield"
    strings:
        // The decode call must WRAP the blob, not merely coexist with it.
        //
        // A bare "long base64 run" pattern cannot work: the longest run in
        // EpicOnlineServicesUserHelper.exe is 3.5 MB, while a genuine encoded
        // PE payload is 13 KB. Length does not separate them. What separates
        // them is structure - a real payload is passed *into* the decoder.
        $call = /(?:base64_decode|FromBase64String|atob)\s*\(\s*["'][A-Za-z0-9+\/]{200,}/
    condition:
        $call
}

rule UPX_Packed
{
    meta:
        description = "UPX-packed executable"
        severity = "low"
        author = "HybridShield"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        2 of them
}

rule Tor_Onion_Reference
{
    meta:
        description = "Hardcoded Tor hidden service address"
        severity = "medium"
        author = "HybridShield"
    strings:
        $onion = /[a-z2-7]{16}\.onion/
        $tor = "torproject" nocase
        // A socks5 *URL*, not the bare word: documentation that mentions
        // "configure socks5 in settings" is not evidence of Tor routing.
        $proxy = "socks5://" nocase
    condition:
        $onion or ($tor and $proxy)
}

rule Credential_Phishing_Form
{
    meta:
        description = "Credential-harvesting HTML form"
        severity = "high"
        author = "HybridShield"
    strings:
        $form = "<form" nocase
        $pass = "type=\"password\"" nocase
        $pass2 = "type='password'" nocase
        $action = "action=" nocase
        $post = "method=\"post\"" nocase
        $post2 = "method='post'" nocase
        $mail = "mailto:" nocase
        $php = ".php" nocase
    condition:
        $form and ($pass or $pass2) and ($action or $post or $post2)
        and ($mail or $php)
}
