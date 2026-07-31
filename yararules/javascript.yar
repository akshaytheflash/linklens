rule Obfuscated_JavaScript
{
    meta:
        description = "Detects obfuscated JavaScript patterns"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $eval = "eval(" nocase
        $fromcharcode = "fromCharCode" nocase
        $atob = "atob(" nocase
        $unescape = "unescape(" nocase
        $base64 = "base64" nocase
        $btoa = "btoa(" nocase
        $obfuscated = /[a-zA-Z_$][a-zA-Z0-9_$]{50,}/  // Very long variable names
    condition:
        2 of them
}

rule Crypto_Miner
{
    meta:
        description = "Detects cryptocurrency mining scripts"
        author = "Link Scanner"
        severity = "high"
    strings:
        $coinhive = "coinhive" nocase
        $cryptonight = "cryptonight" nocase
        $webassembly = "WebAssembly" nocase
        $miner = "miner" nocase
        $monero = "monero" nocase
        $xmrig = "xmrig" nocase
        $cryptocurrency = "cryptocurrency" nocase
    condition:
        2 of them
}

rule Data_Exfiltration
{
    meta:
        description = "Detects patterns indicating data exfiltration"
        author = "Link Scanner"
        severity = "high"
    strings:
        $xmlhttp = "XMLHttpRequest" nocase
        $fetch = "fetch(" nocase
        $post = ".post(" nocase
        $send = ".send(" nocase
        $external_domain = /https?:\/\/[a-zA-Z0-9.-]+\.(xyz|tk|ml|ga|cf|gq|top|click|download|stream|online|site|website)/ nocase
    condition:
        ($xmlhttp or $fetch) and ($post or $send) and $external_domain
}

rule Suspicious_Event_Handlers
{
    meta:
        description = "Detects suspicious event handlers often used in malicious code"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $onerror = "onerror" nocase
        $onload = "onload" nocase
        $onclick = "onclick" nocase
        $addEventListener = "addEventListener" nocase
        $setTimeout = "setTimeout" nocase
        $setInterval = "setInterval" nocase
    condition:
        3 of them
}

rule Keylogger_Patterns
{
    meta:
        description = "Detects keylogger-like patterns"
        author = "Link Scanner"
        severity = "high"
    strings:
        $keydown = "keydown" nocase
        $keypress = "keypress" nocase
        $keyup = "keyup" nocase
        $keycode = "keyCode" nocase
        $which = "which" nocase
        $charCode = "charCode" nocase
    condition:
        3 of them
}

