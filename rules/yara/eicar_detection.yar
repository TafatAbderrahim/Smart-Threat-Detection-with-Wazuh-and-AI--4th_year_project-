/*
  ============================================================
  YARA Rule File : eicar_detection.yar
  Author         : TAFAT Abderrahim
  Project        : Smart Threat Detection with Wazuh and AI
  Team           : ESI Sidi Bel Abbes — CyS 2SC — 2025/2026
  MITRE          : T1105 — Ingress Tool Transfer
  ============================================================

  What is EICAR:
  The EICAR test file is an industry standard test string used
  to verify that antivirus and IDS systems are working correctly.
  It is completely harmless — it is just a text string that
  security tools are programmed to detect.

  The full EICAR string is:
  X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

  Why we use it:
  - No real malware needed in an academic lab
  - Proves the detection pipeline (Sysmon → Wazuh → YARA) works
  - Industry-recognized test — professor will recognize it
  ============================================================
*/

rule EICAR_Test_File
{
    meta:
        author      = "TAFAT Abderrahim"
        description = "Detects the EICAR standard antivirus test file"
        project     = "Smart Threat Detection — ESI SBA 2025/2026"
        mitre       = "T1105 - Ingress Tool Transfer"
        severity    = "high"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        /*
          $eicar_string matches the exact EICAR signature.
          This is the canonical test string — any file containing
          this exact sequence will match, regardless of the filename
          or file extension.
        */
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

        /*
          $eicar_partial is a shorter match — useful if the file
          was modified slightly (e.g. extra bytes added) but the
          core EICAR marker is still present.
        */
        $eicar_partial = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        /*
          Fire if EITHER the full string OR the partial marker
          is found anywhere in the file. The 'any of them' syntax
          means: match if at least one string from the list matches.
        */
        
}


rule Suspicious_Executable_In_Temp
{
    meta:
        author      = "TAFAT Abderrahim"
        description = "Detects executable files written to temp directories — possible malware drop"
        project     = "Smart Threat Detection — ESI SBA 2025/2026"
        mitre       = "T1105 - Ingress Tool Transfer"
        severity    = "medium"

    strings:
        /*
          Windows PE (Portable Executable) magic bytes — MZ header.
          Every .exe and .dll on Windows starts with these two bytes.
          If we find MZ in a file in a temp path, it is suspicious.
        */
        $mz_header = { 4D 5A }

        /*
          PE signature — follows the MZ header in valid executables.
          Checking both reduces false positives.
        */
        $pe_signature = { 50 45 00 00 }

    condition:
        /*
          Both the MZ header at the start AND the PE signature
          somewhere in the file — this is a valid Windows executable.
          Wazuh triggers this scan only on files in temp paths
          (controlled by active response configuration).
        */
        $mz_header at 0 and $pe_signature
}


rule PowerShell_Download_Cradle_Script
{
    meta:
        author      = "TAFAT Abderrahim"
        description = "Detects PowerShell download cradle scripts saved to disk"
        project     = "Smart Threat Detection — ESI SBA 2025/2026"
        mitre       = "T1059.001 - PowerShell / T1105 - Ingress Tool Transfer"
        severity    = "high"

    strings:
        /*
          These are the most common PowerShell download techniques.
          Finding any of them in a .ps1 file on disk is suspicious.
        */
        $download1 = "DownloadString"    nocase
        $download2 = "DownloadFile"      nocase
        $download3 = "WebClient"         nocase
        $download4 = "Invoke-WebRequest" nocase
        $iex       = "Invoke-Expression" nocase
        $iex_short = "IEX"

        /*
          Base64 encoded payloads — the -EncodedCommand flag tells
          PowerShell to decode and execute a base64 string.
        */
        $encoded   = "-EncodedCommand"   nocase
        $enc_short = "-enc"              nocase

    condition:
        /*
          Match if the script contains BOTH a download method AND
          an execution method. Download alone might be legitimate.
          Download + execute together is almost always malicious.
        */
        (any of ($download*)) and (iex or iex_short or encoded or enc_short)
}
