rule Phishing_Keywords
{
    meta:
        description = "Detects common phishing keywords and patterns"
        author = "Link Scanner"
        severity = "high"
    strings:
        $urgent = "urgent" nocase
        $verify = "verify your account" nocase
        $suspended = "account suspended" nocase
        $locked = "account locked" nocase
        $expire = "expire" nocase
        $immediate = "immediate action" nocase
        $click_here = "click here" nocase
        $login_now = "login now" nocase
        $update_info = "update your information" nocase
    condition:
        2 of them
}

rule Suspicious_Form_Fields
{
    meta:
        description = "Detects suspicious form fields often used in phishing"
        author = "Link Scanner"
        severity = "medium"
    strings:
        $ssn = "ssn" nocase
        $credit_card = "credit card" nocase
        $cvv = "cvv" nocase
        $pin = "pin" nocase
        $password = "password" nocase
        $social_security = "social security" nocase
    condition:
        2 of them
}

rule Brand_Impersonation
{
    meta:
        description = "Detects common brand names used in phishing"
        author = "Link Scanner"
        severity = "high"
    strings:
        $microsoft = "microsoft" nocase
        $paypal = "paypal" nocase
        $amazon = "amazon" nocase
        $apple = "apple" nocase
        $google = "google" nocase
        $bank = "bank" nocase
        $irs = "irs" nocase
    condition:
        any of them
}

