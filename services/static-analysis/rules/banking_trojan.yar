rule BankingTrojan_SMSInterceptor {
    meta:
        description = "Detects SMS interception used in banking trojans"
        author      = "BOI Sentinel AI"
        severity    = "high"
    strings:
        $s1 = "READ_SMS" ascii
        $s2 = "RECEIVE_SMS" ascii
        $s3 = "sendTextMessage" ascii
        $s4 = "SmsMessage" ascii
        $s5 = "getMessageBody" ascii
    condition:
        3 of ($s*)
}

rule BankingTrojan_OverlayAttack {
    meta:
        description = "Detects overlay attack capability used to phish banking credentials"
        author      = "BOI Sentinel AI"
        severity    = "critical"
    strings:
        $o1 = "SYSTEM_ALERT_WINDOW" ascii
        $o2 = "TYPE_APPLICATION_OVERLAY" ascii
        $o3 = "WindowManager.LayoutParams" ascii
        $o4 = "AccessibilityService" ascii
        $o5 = "performGlobalAction" ascii
    condition:
        2 of ($o*)
}

rule BankingTrojan_CredentialHarvester {
    meta:
        description = "Detects credential harvesting patterns"
        author      = "BOI Sentinel AI"
        severity    = "critical"
    strings:
        $c1 = "password" nocase ascii
        $c2 = "credential" nocase ascii
        $c3 = "netbanking" nocase ascii
        $c4 = "getPassword" ascii
        $c5 = "keylog" nocase ascii
        $c6 = "InputMethodService" ascii
    condition:
        3 of ($c*)
}

rule Malware_DynamicCodeLoading {
    meta:
        description = "Detects dynamic code loading — indicator of dropper/downloader"
        author      = "BOI Sentinel AI"
        severity    = "high"
    strings:
        $d1 = "DexClassLoader" ascii
        $d2 = "PathClassLoader" ascii
        $d3 = "InMemoryDexClassLoader" ascii
        $d4 = "loadDex" ascii
    condition:
        any of them
}

rule Malware_C2Communication {
    meta:
        description = "Detects obfuscated C2 communication patterns"
        author      = "BOI Sentinel AI"
        severity    = "high"
    strings:
        $e1 = "Base64" ascii
        $e2 = "AES" ascii
        $e3 = "HttpURLConnection" ascii
        $e4 = "exec(" ascii
        $e5 = "Runtime.getRuntime" ascii
    condition:
        3 of them
}

rule OTPStealer_Indicators {
    meta:
        description = "Detects OTP stealing behavior patterns"
        author      = "BOI Sentinel AI"
        severity    = "critical"
    strings:
        $otp1 = "otp" nocase ascii
        $otp2 = "one.time" nocase ascii
        $otp3 = "RECEIVE_SMS" ascii
        $otp4 = "getMessageBody" ascii
        $otp5 = "broadcastReceiver" nocase ascii
    condition:
        3 of ($otp*)
}
