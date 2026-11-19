#include "FastPathPolicy.h"

/*
 * Hard bounds: no pool allocations and no unbounded parsing on process create.
 * Inputs exceeding this limit remain observable, but are not eligible for a
 * preemptive block; this limitation is part of the v0.8.0 release contract.
 */
#define RG_FP_SCAN_LIMIT 4096U
#define RG_FP_TOKEN_LIMIT 96U

typedef enum _RG_FP_IMAGE {
    RgFpOther = 0,
    RgFpVssadmin,
    RgFpWmic,
    RgFpWbadmin,
    RgFpBcdedit,
    RgFpWevtutil,
    RgFpCipher,
    RgFpPowershell
} RG_FP_IMAGE;

static unsigned short RgFpLower(unsigned short value)
{
    if (value >= (unsigned short)'A' && value <= (unsigned short)'Z') {
        return (unsigned short)(value + ('a' - 'A'));
    }
    return value;
}

static int RgFpIsSpace(unsigned short value)
{
    return value == (unsigned short)' ' || value == (unsigned short)'\t' ||
           value == (unsigned short)'\r' || value == (unsigned short)'\n';
}

static int RgFpEquals(const RG_FP_CHAR* chars, unsigned int length, const char* ascii)
{
    unsigned int i = 0;
    while (ascii[i] != '\0') {
        if (i >= length || RgFpLower(chars[i]) != (unsigned short)(unsigned char)ascii[i]) {
            return 0;
        }
        ++i;
    }
    return i == length;
}

static int RgFpPrefix(const RG_FP_CHAR* chars, unsigned int length, const char* ascii)
{
    unsigned int i = 0;
    while (ascii[i] != '\0') {
        if (i >= length || RgFpLower(chars[i]) != (unsigned short)(unsigned char)ascii[i]) {
            return 0;
        }
        ++i;
    }
    return 1;
}

static int RgFpContains(const RG_FP_CHAR* chars, unsigned int length, const char* ascii)
{
    unsigned int i;
    for (i = 0; i < length; ++i) {
        if (RgFpPrefix(chars + i, length - i, ascii)) {
            return 1;
        }
    }
    return 0;
}

static RG_FP_IMAGE RgFpImage(const RG_FP_CHAR* path, unsigned int length)
{
    unsigned int i;
    unsigned int base = 0;
    if (path == 0 || length == 0 || length > RG_FP_SCAN_LIMIT) {
        return RgFpOther;
    }
    for (i = 0; i < length; ++i) {
        if (path[i] == (RG_FP_CHAR)'\\' || path[i] == (RG_FP_CHAR)'/') {
            base = i + 1;
        }
    }
    if (RgFpEquals(path + base, length - base, "vssadmin.exe")) return RgFpVssadmin;
    if (RgFpEquals(path + base, length - base, "wmic.exe")) return RgFpWmic;
    if (RgFpEquals(path + base, length - base, "wbadmin.exe")) return RgFpWbadmin;
    if (RgFpEquals(path + base, length - base, "bcdedit.exe")) return RgFpBcdedit;
    if (RgFpEquals(path + base, length - base, "wevtutil.exe")) return RgFpWevtutil;
    if (RgFpEquals(path + base, length - base, "cipher.exe")) return RgFpCipher;
    if (RgFpEquals(path + base, length - base, "powershell.exe") ||
        RgFpEquals(path + base, length - base, "pwsh.exe")) return RgFpPowershell;
    return RgFpOther;
}

static RG_FP_RESULT RgFpResult(unsigned int id, unsigned int block)
{
    RG_FP_RESULT result;
    result.RuleId = id;
    result.AllowBlock = block;
    return result;
}

RG_FP_RESULT RgFastPathEvaluate(
    const RG_FP_CHAR* imagePath, unsigned int imageChars,
    const RG_FP_CHAR* commandLine, unsigned int commandChars)
{
    RG_FP_IMAGE image = RgFpImage(imagePath, imageChars);
    RG_FP_RESULT match = RgFpResult(0, 0);
    RG_FP_CHAR token[RG_FP_TOKEN_LIMIT];
    unsigned int tokenLength;
    unsigned int position = 0;
    unsigned int previous = 0;
    unsigned int seenWmicShadowcopy = 0;
    unsigned int seenBcdeditSet = 0;
    unsigned int helpRequested = 0;

    enum {
        TokNone, TokDelete, TokShadows, TokResize, TokShadowstorage,
        TokShadowcopy, TokCatalog, TokSystemstatebackup, TokBackup,
        TokSet, TokRecoveryenabled, TokNo, TokBootstatuspolicy,
        TokIgnoreallfailures, TokCl, TokWipe
    };

    if (image == RgFpOther || commandLine == 0 || commandChars == 0 ||
        commandChars > RG_FP_SCAN_LIMIT) {
        return match;
    }

    /* PowerShell's script grammar cannot safely be interpreted by a simple
     * CLI token parser. Report the high-risk phrase for user-mode analysis,
     * but NEVER deny process creation on this heuristic alone. */
    if (image == RgFpPowershell) {
        if (RgFpContains(commandLine, commandChars, "win32_shadowcopy") &&
            RgFpContains(commandLine, commandChars, "delete")) {
            return RgFpResult(1009, 0);
        }
        return match;
    }

    while (position < commandChars) {
        unsigned int kind = TokNone;
        unsigned int inQuotes = 0;
        unsigned int overflow = 0;

        while (position < commandChars && RgFpIsSpace(commandLine[position])) {
            ++position;
        }
        if (position == commandChars) break;
        tokenLength = 0;
        while (position < commandChars) {
            unsigned short ch = commandLine[position++];
            if (ch == (RG_FP_CHAR)'"') {
                inQuotes = !inQuotes;
                continue;
            }
            if (!inQuotes && RgFpIsSpace(ch)) break;
            if (tokenLength >= RG_FP_TOKEN_LIMIT - 1) {
                overflow = 1;
            } else {
                token[tokenLength++] = RgFpLower(ch);
            }
        }
        if (overflow || tokenLength == 0) {
            previous = TokNone;
            continue;
        }

        if (RgFpEquals(token, tokenLength, "/?") ||
            RgFpEquals(token, tokenLength, "-?") ||
            RgFpEquals(token, tokenLength, "/help") ||
            RgFpEquals(token, tokenLength, "--help") ||
            RgFpEquals(token, tokenLength, "help")) {
            helpRequested = 1;
        }

        if (RgFpEquals(token, tokenLength, "delete")) kind = TokDelete;
        else if (RgFpEquals(token, tokenLength, "shadows")) kind = TokShadows;
        else if (RgFpEquals(token, tokenLength, "resize")) kind = TokResize;
        else if (RgFpEquals(token, tokenLength, "shadowstorage")) kind = TokShadowstorage;
        else if (RgFpEquals(token, tokenLength, "shadowcopy")) kind = TokShadowcopy;
        else if (RgFpEquals(token, tokenLength, "catalog")) kind = TokCatalog;
        else if (RgFpEquals(token, tokenLength, "systemstatebackup")) kind = TokSystemstatebackup;
        else if (RgFpEquals(token, tokenLength, "backup")) kind = TokBackup;
        else if (RgFpEquals(token, tokenLength, "/set")) kind = TokSet;
        else if (RgFpEquals(token, tokenLength, "recoveryenabled")) kind = TokRecoveryenabled;
        else if (RgFpEquals(token, tokenLength, "no")) kind = TokNo;
        else if (RgFpEquals(token, tokenLength, "bootstatuspolicy")) kind = TokBootstatuspolicy;
        else if (RgFpEquals(token, tokenLength, "ignoreallfailures")) kind = TokIgnoreallfailures;
        else if (RgFpEquals(token, tokenLength, "cl")) kind = TokCl;
        else if (RgFpEquals(token, tokenLength, "/w") ||
                 RgFpPrefix(token, tokenLength, "/w:")) kind = TokWipe;

        if (match.RuleId == 0) {
            switch (image) {
                case RgFpVssadmin:
                    if (previous == TokDelete && kind == TokShadows) match = RgFpResult(1001, 1);
                    else if (previous == TokResize && kind == TokShadowstorage) match = RgFpResult(1002, 1);
                    break;
                case RgFpWmic:
                    if (kind == TokShadowcopy) seenWmicShadowcopy = 1;
                    if (seenWmicShadowcopy && kind == TokDelete) match = RgFpResult(1003, 1);
                    break;
                case RgFpWbadmin:
                    if (previous == TokDelete &&
                        (kind == TokCatalog || kind == TokSystemstatebackup || kind == TokBackup)) {
                        match = RgFpResult(1004, 1);
                    }
                    break;
                case RgFpBcdedit:
                    if (kind == TokSet) seenBcdeditSet = 1;
                    if (seenBcdeditSet && previous == TokRecoveryenabled && kind == TokNo)
                        match = RgFpResult(1005, 1);
                    else if (seenBcdeditSet && previous == TokBootstatuspolicy && kind == TokIgnoreallfailures)
                        match = RgFpResult(1006, 1);
                    break;
                case RgFpWevtutil:
                    if (kind == TokCl) match = RgFpResult(1007, 1);
                    break;
                case RgFpCipher:
                    if (kind == TokWipe) match = RgFpResult(1008, 1);
                    break;
                default:
                    break;
            }
        }
        previous = kind;
    }

    /* A help query is not proof that any destructive command will execute. */
    if (helpRequested) return RgFpResult(0, 0);
    return match;
}
