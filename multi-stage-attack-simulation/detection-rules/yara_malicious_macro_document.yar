/*
    Rule: Suspicious_Macro_Enabled_Office_AutoExec
    Purpose: Flags macro-enabled Office documents (.xlsm/.docm) that contain
             an auto-executing VBA entry point (Document_Open / AutoOpen)
             combined with indicators of shell or download activity —
             consistent with a phishing delivery mechanism observed in
             this simulation (malicious .xlsm attachment spawning
             PowerShell).
    Author:  SOC Internship - Detection Engineering Exercise
    Date:    2026-08-02
    Notes:   This is a behavioral/heuristic rule intended for triage, not
             a signature for a specific known-malware family. Expect some
             false positives on legitimate internal automation macros;
             review flagged files manually before action.
*/

rule Suspicious_Macro_Enabled_Office_AutoExec
{
    meta:
        description = "Detects macro-enabled Office docs with auto-exec VBA and shell/download indicators"
        author = "SOC Internship - Detection Engineering Exercise"
        date = "2026-08-02"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        level = "medium"

    strings:
        // Auto-executing VBA entry points
        $autoexec1 = "Document_Open" ascii wide nocase
        $autoexec2 = "AutoOpen" ascii wide nocase
        $autoexec3 = "Workbook_Open" ascii wide nocase

        // Shell / download indicators commonly paired with malicious macros
        $shell1 = "Shell(" ascii wide nocase
        $shell2 = "WScript.Shell" ascii wide nocase
        $ps1    = "powershell" ascii wide nocase
        $ps2    = "-EncodedCommand" ascii wide nocase
        $ps3    = "-enc " ascii wide nocase
        $net1   = "DownloadString" ascii wide nocase
        $net2   = "Net.WebClient" ascii wide nocase

        // Office Open XML macro container marker (confirms it's a macro-enabled document)
        $vbaproject = "vbaProject.bin" ascii

    condition:
        $vbaproject and
        any of ($autoexec*) and
        any of ($shell1, $shell2, $ps1, $ps2, $ps3, $net1, $net2)
}
