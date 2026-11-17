/* Portable regression tests for the exact C matcher linked into the driver. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../Anti_Ransom_Driver/FastPathPolicy.h"

static void utf16_ascii(const char* src, RG_FP_CHAR* dest, unsigned int capacity)
{
    unsigned int i;
    size_t length = strlen(src);
    if (length >= capacity) abort();
    for (i = 0; i < length; i++) dest[i] = (unsigned char)src[i];
    dest[length] = 0;
}

static unsigned int rg_length(const RG_FP_CHAR* text)
{
    unsigned int n = 0;
    while (text[n]) ++n;
    return n;
}

static int cases_run = 0;
static void check(const char* label, const char* image, const char* command,
                  unsigned int expected_id, unsigned int expected_block)
{
    RG_FP_CHAR image_text[4096];
    RG_FP_CHAR command_text[4096];
    RG_FP_RESULT result;
    utf16_ascii(image, image_text, 4096);
    utf16_ascii(command, command_text, 4096);
    result = RgFastPathEvaluate(image_text, rg_length(image_text),
                                command_text, rg_length(command_text));
    ++cases_run;
    if (result.RuleId != expected_id || result.AllowBlock != expected_block) {
        fprintf(stderr, "%s: expected %u/%u; got %u/%u\n",
                label, expected_id, expected_block, result.RuleId, result.AllowBlock);
        exit(1);
    }
}

int main(void)
{
    /* VSS tools: real image and verb/object sequence required. */
    check("vss delete", "C:\\Windows\\System32\\vssadmin.exe",
          "vssadmin Delete Shadows /all /quiet", 1001, 1);
    check("vss resize", "C:\\Windows\\System32\\VSSADMIN.EXE",
          "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=1GB", 1002, 1);
    check("vss list", "vssadmin.exe", "vssadmin list shadows", 0, 0);
    check("vss help", "vssadmin.exe", "vssadmin delete shadows /?", 0, 0);
    check("vss quote", "vssadmin.exe", "vssadmin \"delete shadows\"", 0, 0);
    check("vss missing noun", "vssadmin.exe", "vssadmin delete backups", 0, 0);
    check("vss false positive echo", "C:\\Windows\\System32\\cmd.exe",
          "cmd /c echo vssadmin delete shadows", 0, 0);
    check("vss false positive powershell", "powershell.exe",
          "powershell -Command \"echo vssadmin delete shadows\"", 0, 0);
    check("vss false positive word", "vssadmin.exe", "vssadmin undelete shadows", 0, 0);

    /* Backup and system recovery configuration. */
    check("wmic", "wmic.exe", "wmic shadowcopy delete", 1003, 1);
    check("wmic where", "wmic.exe", "wmic shadowcopy where ID=foo delete", 1003, 1);
    check("wmic query", "wmic.exe", "wmic shadowcopy list brief", 0, 0);
    check("wbadmin catalog", "wbadmin.exe", "wbadmin delete catalog -quiet", 1004, 1);
    check("wbadmin state", "wbadmin.exe", "wbadmin delete systemstatebackup -keepVersions:0", 1004, 1);
    check("wbadmin backup", "wbadmin.exe", "wbadmin delete backup", 1004, 1);
    check("wbadmin list", "wbadmin.exe", "wbadmin get versions", 0, 0);
    check("bcdedit recovery", "bcdedit.exe", "bcdedit /set {default} recoveryenabled No", 1005, 1);
    check("bcdedit policy", "bcdedit.exe", "bcdedit /set {current} bootstatuspolicy ignoreallfailures", 1006, 1);
    check("bcdedit no set", "bcdedit.exe", "bcdedit recoveryenabled no", 0, 0);
    check("bcdedit info", "bcdedit.exe", "bcdedit /enum all", 0, 0);

    /* Event log and free-space wipe. */
    check("wevtutil clear", "wevtutil.exe", "wevtutil cl System", 1007, 1);
    check("wevtutil list", "wevtutil.exe", "wevtutil el", 0, 0);
    check("wevtutil help", "wevtutil.exe", "wevtutil cl /?", 0, 0);
    check("cipher wipe", "cipher.exe", "cipher /w:C:\\temp", 1008, 1);
    check("cipher generic", "cipher.exe", "cipher /e C:\\temp", 0, 0);

    /* Scripts do not have a safe command grammar; never auto-block. */
    check("powershell suspicious audit", "powershell.exe",
          "powershell -Command \"Get-WmiObject Win32_ShadowCopy | % { $_.Delete() }\"", 1009, 0);
    check("powershell benign", "powershell.exe", "powershell Get-Process", 0, 0);
    check("non-image phrase", "C:\\Temp\\not-vssadmin.exe",
          "vssadmin delete shadows", 0, 0);
    check("file path false-positive", "C:\\Temp\\vssadmin.exe.bak",
          "vssadmin delete shadows", 0, 0);
    printf("PASS %d FastPathPolicy cases\n", cases_run);
    return 0;
}
