rule Base64_Encoded
{
    meta:
        description = "Detects base64 encoded strings (often used for obfuscation)"
        author = "Link Scanner"
        severity = "low"
    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $base64_pattern
}

rule Hex_Encoded
{
    meta:
        description = "Detects hex encoded strings"
        author = "Link Scanner"
        severity = "low"
    strings:
        $hex_pattern = /\\x[0-9a-fA-F]{2}/
    condition:
        #hex_pattern > 10
}

rule Unicode_Escape
{
    meta:
        description = "Detects unicode escape sequences"
        author = "Link Scanner"
        severity = "low"
    strings:
        $unicode = /\\u[0-9a-fA-F]{4}/
    condition:
        #unicode > 5
}

rule Packed_Code
{
    meta:
        description = "Detects packed/compressed code patterns"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $packed = "packed" nocase
        $compress = "compress" nocase
        $deflate = "deflate" nocase
        $inflate = "inflate" nocase
    condition:
        2 of them
}

