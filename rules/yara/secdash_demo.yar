/*
  One Eye demo YARA rules. Add your own .yar files to this folder.
  Larger community rule sets (check each license before use):
    - https://github.com/Neo23x0/signature-base
    - https://github.com/Yara-Rules/rules
*/

rule OneEye_Demo_Sample
{
    meta:
        description = "Harmless One Eye test sample (Settings > Create demo files)"
        severity = "demo"
    strings:
        $s = "SecDash harmless test sample"
    condition:
        $s
}

rule Suspicious_Miner_Strings
{
    meta:
        description = "Strings commonly found in cryptominer configs"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "xmrig" nocase
        $c = "--donate-level" nocase
    condition:
        2 of them
}
