rule IP_Address_Leak
{
    meta:
        description = "Detects IP address tracking patterns"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $ip_api = "ip-api.com" nocase
        $ipify = "ipify" nocase
        $ipinfo = "ipinfo.io" nocase
        $geoip = "geoip" nocase
        $ip_pattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
    condition:
        any of ($ip_api, $ipify, $ipinfo, $geoip) or $ip_pattern
}

rule Suspicious_Domain
{
    meta:
        description = "Detects suspicious domain patterns"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $suspicious_tld = /\.(tk|ml|ga|cf|gq|top|click|download|stream|online|xyz|site|website|top|pw|review|accountant|science|work|racing|faith|date|trade|win|men|loan|men|click|download|stream|online|site|website|top|pw|review|accountant|science|work|racing|faith|date|trade|win|men|loan)/
    condition:
        $suspicious_tld
}

