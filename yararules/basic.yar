rule Suspicious_Archive
{
    meta:
        description = "Flags common archive file signatures"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $zip = { 50 4B 03 04 }
        $rar = { 52 61 72 21 1A 07 }
        $sevenz = { 37 7A BC AF 27 1C }
        $tar = { 75 73 74 61 72 }
        $gz = { 1F 8B }
    condition:
        any of them
}
