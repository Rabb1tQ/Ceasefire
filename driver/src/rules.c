#include "../inc/driver.h"

// Static rule ID counter
static UINT32 g_NextRuleId = 1;

// Case-insensitive SUFFIX match: does haystack end with needle?
// Kernel-side semantics only: the haystack is the full NT process path from
// FWPS metadata and the needle is the rule path (already converted to NT form
// by the service). The service-side matcher is a different implementation
// (case-sensitive, compares file names rather than paths).
//
// 安全语义：不能用"包含"匹配——全路径规则可被伪造目录子串绕过
// （如规则 \Windows\svchost.exe 会命中 \Windows\svchost.exe.evil\...）。
// 后缀匹配保留两种规则的预期行为：短写法 \name.exe 仍命中任意目录同名
// 进程，完整路径则精确到目录（\Windows\System32\svchost.exe 不再被
// C:\evil\Windows\System32\svchost.exe 命中）。
static BOOLEAN WcsEndsWithIgnoreCase(_In_ const WCHAR* haystack, _In_ const WCHAR* needle)
{
    SIZE_T hayLen, needleLen, i;

    if (needle == NULL || needle[0] == L'\0') {
        return TRUE;
    }
    if (haystack == NULL) {
        return FALSE;
    }

    hayLen = 0;
    while (haystack[hayLen] != L'\0') hayLen++;
    needleLen = 0;
    while (needle[needleLen] != L'\0') needleLen++;

    if (hayLen < needleLen) {
        return FALSE;
    }

    // Compare the tail of the haystack against the needle, ASCII-only folding
    for (i = 0; i < needleLen; i++) {
        WCHAR a = haystack[hayLen - needleLen + i];
        WCHAR b = needle[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) {
            return FALSE;
        }
    }
    return TRUE;
}

NTSTATUS AddRule(_In_ PRULE_INPUT ruleInput)
{
    PFIREWALL_RULE newRule = NULL;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    PFIREWALL_RULE currentRule;
    PLIST_ENTRY entry;
    ULONG ruleCount = 0;

    KdPrint(("Ceasefire Driver: AddRule called\n"));

    // Allocate memory for new rule
    newRule = (PFIREWALL_RULE)ExAllocatePoolWithTag(NonPagedPool, sizeof(FIREWALL_RULE), 'RlFC');
    if (newRule == NULL) {
        KdPrint(("Ceasefire Driver: Failed to allocate memory for rule\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize rule
    RtlZeroMemory(newRule, sizeof(FIREWALL_RULE));

    // Use the RuleId from input (from service layer)
    newRule->RuleId = ruleInput->RuleId;
    newRule->Priority = ruleInput->Priority;
    newRule->Enabled = ruleInput->Enabled;
    newRule->IsAllow = ruleInput->IsAllow;
    newRule->Direction = ruleInput->Direction;
    newRule->ProcessId = ruleInput->ProcessId;
    newRule->Protocol = ruleInput->Protocol;
    RtlCopyMemory(newRule->RemoteAddr, ruleInput->RemoteAddr, sizeof(newRule->RemoteAddr));
    RtlCopyMemory(newRule->RemoteAddrMask, ruleInput->RemoteAddrMask, sizeof(newRule->RemoteAddrMask));
    newRule->AddressFamily = ruleInput->AddressFamily;
    newRule->RemotePort = ruleInput->RemotePort;
    newRule->LocalPort = ruleInput->LocalPort;
    newRule->RemotePortEnd = ruleInput->RemotePortEnd;
    newRule->LocalPortEnd = ruleInput->LocalPortEnd;

    RtlCopyMemory(newRule->ProcessPath, ruleInput->ProcessPath, MAX_PATH_LENGTH * sizeof(WCHAR));
    // 输入缓冲区按整个 MAX_PATH_LENGTH 数组拷贝，调用方给的 260 个 WCHAR 可能
    // 不含 NUL 终止符；WcsEndsWithIgnoreCase 会先扫描全串求长度，
    // 缺终止符会读越 ProcessPath 数组、扫进结构体后续字段甚至越出池分配。
    // 永远强制最后一格为终止符。
    newRule->ProcessPath[MAX_PATH_LENGTH - 1] = L'\0';

    KdPrint(("Ceasefire Driver: Adding rule - ID=%d, Priority=%d, Enabled=%d, IsAllow=%d, ProcessId=%d, Protocol=%d\n",
        newRule->RuleId, newRule->Priority, newRule->Enabled, newRule->IsAllow, newRule->ProcessId, newRule->Protocol));

    // Add to rule list (sorted by priority)
    KeAcquireSpinLock(&g_RuleListLock, &oldIrql);

    // First pass: count rules and reject duplicate IDs (B10)
    entry = g_RuleList.Flink;
    while (entry != &g_RuleList) {
        currentRule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);
        if (currentRule->RuleId == newRule->RuleId) {
            KeReleaseSpinLock(&g_RuleListLock, oldIrql);
            ExFreePoolWithTag(newRule, 'RlFC');
            KdPrint(("Ceasefire Driver: Duplicate rule ID rejected: %d\n", newRule->RuleId));
            return STATUS_OBJECT_NAME_COLLISION;
        }
        ruleCount++;
        entry = entry->Flink;
    }

    // Enforce a hard cap on rule count (B10)
    if (ruleCount + 1 > MAX_RULES) {
        KeReleaseSpinLock(&g_RuleListLock, oldIrql);
        ExFreePoolWithTag(newRule, 'RlFC');
        KdPrint(("Ceasefire Driver: MAX_RULES (%d) exceeded\n", MAX_RULES));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Second pass: find the insertion point by priority
    entry = g_RuleList.Flink;
    while (entry != &g_RuleList) {
        currentRule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);
        if (newRule->Priority < currentRule->Priority) {
            break;
        }
        entry = entry->Flink;
    }

    InsertHeadList(entry->Blink, &newRule->ListEntry);

    KeReleaseSpinLock(&g_RuleListLock, oldIrql);

    KdPrint(("Ceasefire Driver: Rule added with ID: %d\n", newRule->RuleId));

    return status;
}

NTSTATUS RemoveRule(_In_ UINT32 ruleId)
{
    PFIREWALL_RULE rule = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KdPrint(("Ceasefire Driver: RemoveRule called with ID: %d\n", ruleId));

    KeAcquireSpinLock(&g_RuleListLock, &oldIrql);

    entry = g_RuleList.Flink;
    while (entry != &g_RuleList) {
        rule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);
        if (rule->RuleId == ruleId) {
            RemoveEntryList(&rule->ListEntry);
            found = TRUE;
            break;
        }
        entry = entry->Flink;
    }

    KeReleaseSpinLock(&g_RuleListLock, oldIrql);

    if (found) {
        ExFreePoolWithTag(rule, 'RlFC');
        KdPrint(("Ceasefire Driver: Rule removed with ID: %d\n", ruleId));
        return STATUS_SUCCESS;
    } else {
        KdPrint(("Ceasefire Driver: Rule not found with ID: %d\n", ruleId));
        return STATUS_NOT_FOUND;
    }
}

NTSTATUS UpdateRule(_In_ PRULE_INPUT ruleInput)
{
    PFIREWALL_RULE rule = NULL;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    BOOLEAN reposition = FALSE;

    KdPrint(("Ceasefire Driver: UpdateRule called with ID: %d\n", ruleInput->RuleId));

    KeAcquireSpinLock(&g_RuleListLock, &oldIrql);

    entry = g_RuleList.Flink;
    while (entry != &g_RuleList) {
        rule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);
        if (rule->RuleId == ruleInput->RuleId) {
            // Priority change requires re-inserting to keep the list sorted (B10)
            reposition = (rule->Priority != ruleInput->Priority);
            if (reposition) {
                RemoveEntryList(&rule->ListEntry);
            }
            // Update rule fields
            rule->Priority = ruleInput->Priority;
            rule->Enabled = ruleInput->Enabled;
            rule->IsAllow = ruleInput->IsAllow;
            rule->Direction = ruleInput->Direction;
            rule->ProcessId = ruleInput->ProcessId;
            rule->Protocol = ruleInput->Protocol;
            RtlCopyMemory(rule->RemoteAddr, ruleInput->RemoteAddr, sizeof(rule->RemoteAddr));
            RtlCopyMemory(rule->RemoteAddrMask, ruleInput->RemoteAddrMask, sizeof(rule->RemoteAddrMask));
            rule->AddressFamily = ruleInput->AddressFamily;
            rule->RemotePort = ruleInput->RemotePort;
            rule->LocalPort = ruleInput->LocalPort;
            rule->RemotePortEnd = ruleInput->RemotePortEnd;
            rule->LocalPortEnd = ruleInput->LocalPortEnd;
            RtlCopyMemory(rule->ProcessPath, ruleInput->ProcessPath, MAX_PATH_LENGTH * sizeof(WCHAR));
            // 同 AddRule：输入可能无 NUL 终止符，必须强制最后一格为终止符，
            // 否则 WcsEndsWithIgnoreCase 会读越 ProcessPath 数组。
            rule->ProcessPath[MAX_PATH_LENGTH - 1] = L'\0';
            found = TRUE;
            break;
        }
        entry = entry->Flink;
    }

    if (found && reposition) {
        // Re-insert at the position matching the new priority
        entry = g_RuleList.Flink;
        while (entry != &g_RuleList) {
            PFIREWALL_RULE currentRule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);
            if (rule->Priority < currentRule->Priority) {
                break;
            }
            entry = entry->Flink;
        }
        InsertHeadList(entry->Blink, &rule->ListEntry);
    }

    KeReleaseSpinLock(&g_RuleListLock, oldIrql);

    if (found) {
        KdPrint(("Ceasefire Driver: Rule updated with ID: %d\n", ruleInput->RuleId));
        return STATUS_SUCCESS;
    } else {
        KdPrint(("Ceasefire Driver: Rule not found with ID: %d\n", ruleInput->RuleId));
        return STATUS_NOT_FOUND;
    }
}

NTSTATUS ClearRules(VOID)
{
    PFIREWALL_RULE rule;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KdPrint(("Ceasefire Driver: ClearRules called\n"));

    KeAcquireSpinLock(&g_RuleListLock, &oldIrql);

    while (!IsListEmpty(&g_RuleList)) {
        entry = RemoveHeadList(&g_RuleList);
        rule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);
        ExFreePoolWithTag(rule, 'RlFC');
    }

    KeReleaseSpinLock(&g_RuleListLock, oldIrql);

    KdPrint(("Ceasefire Driver: All rules cleared\n"));

    return STATUS_SUCCESS;
}

BOOLEAN MatchRules(
    _In_ UINT32 processId,
    _In_ const WCHAR* processPath,
    _In_ UINT32 protocol,
    _In_ UINT32 addressFamily,
    _In_ const BYTE (*remoteAddr)[16],
    _In_ UINT16 remotePort,
    _In_ UINT16 localPort,
    _In_ UINT32 direction,
    _Out_ PBOOLEAN allowConnection,
    _Out_ PUINT32 matchedRuleId
)
{
    PFIREWALL_RULE rule;
    PLIST_ENTRY entry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_RuleListLock, &oldIrql);

    entry = g_RuleList.Flink;
    while (entry != &g_RuleList) {
        rule = CONTAINING_RECORD(entry, FIREWALL_RULE, ListEntry);

        // Check if rule is enabled
        if (!rule->Enabled) {
            entry = entry->Flink;
            continue;
        }

        // Direction: rule applies only on its direction (0 = both directions)
        if (rule->Direction != RULE_DIRECTION_BOTH && rule->Direction != direction) {
            entry = entry->Flink;
            continue;
        }

        // Check process ID
        if (rule->ProcessId != 0 && rule->ProcessId != processId) {
            entry = entry->Flink;
            continue;
        }

        // Check process path (B9: case-insensitive SUFFIX match; a full path
        // rule must not be bypassable by a substring-disguised directory, and
        // the \name.exe short form still matches any directory with that name —
        // see WcsEndsWithIgnoreCase above for the kernel-side-only semantics)
        if (rule->ProcessPath[0] != L'\0' &&
            !WcsEndsWithIgnoreCase(processPath, rule->ProcessPath)) {
            entry = entry->Flink;
            continue;
        }

        // Check protocol
        if (rule->Protocol != 0 && rule->Protocol != protocol) {
            entry = entry->Flink;
            continue;
        }

        // Check remote address（双栈：地址族必须一致，V4 走 32 位快路径，
        // V6 走 128 位掩码比较。RemoteAddr 全 0 = 任意地址通配。）
        if (!CfAddrIsZero(rule->RemoteAddr)) {
            if (rule->AddressFamily != addressFamily) {
                entry = entry->Flink;
                continue;
            }
            if (addressFamily == CF_ADDR_FAMILY_V4) {
                UINT32 ruleAddr, ruleMask, connAddr;
                RtlCopyMemory(&ruleAddr, rule->RemoteAddr, sizeof(UINT32));
                RtlCopyMemory(&ruleMask, rule->RemoteAddrMask, sizeof(UINT32));
                RtlCopyMemory(&connAddr, (*remoteAddr), sizeof(UINT32));
                if ((connAddr & ruleMask) != (ruleAddr & ruleMask)) {
                    entry = entry->Flink;
                    continue;
                }
            } else if (addressFamily == CF_ADDR_FAMILY_V6) {
                UINT32 i;
                BOOLEAN mismatch = FALSE;
                for (i = 0; i < 16; i += sizeof(UINT64)) {
                    UINT64 rAddr, rMask, cAddr;
                    RtlCopyMemory(&rAddr, rule->RemoteAddr + i, sizeof(UINT64));
                    RtlCopyMemory(&rMask, rule->RemoteAddrMask + i, sizeof(UINT64));
                    RtlCopyMemory(&cAddr, (*remoteAddr) + i, sizeof(UINT64));
                    if ((cAddr & rMask) != (rAddr & rMask)) {
                        mismatch = TRUE;
                        break;
                    }
                }
                if (mismatch) {
                    entry = entry->Flink;
                    continue;
                }
            } else {
                // 未知地址族的连接不可能匹配已配置的具体地址
                entry = entry->Flink;
                continue;
            }
        }

        // Check remote port: 起点/终点都为 0 = 通配，否则 start <= port <= end
        if ((rule->RemotePort != 0 || rule->RemotePortEnd != 0) &&
            (remotePort < rule->RemotePort || remotePort > rule->RemotePortEnd)) {
            entry = entry->Flink;
            continue;
        }

        // Check local port: 同上
        if ((rule->LocalPort != 0 || rule->LocalPortEnd != 0) &&
            (localPort < rule->LocalPort || localPort > rule->LocalPortEnd)) {
            entry = entry->Flink;
            continue;
        }

        // Rule matched
        *allowConnection = rule->IsAllow;
        *matchedRuleId = rule->RuleId;

        KeReleaseSpinLock(&g_RuleListLock, oldIrql);

        KdPrint(("Ceasefire Driver: Rule matched: ID=%d, Allow=%d\n", rule->RuleId, rule->IsAllow));
        return TRUE;
    }

    KeReleaseSpinLock(&g_RuleListLock, oldIrql);

    // No rule matched, use default policy
    *allowConnection = g_DefaultAllow;
    *matchedRuleId = 0;

    KdPrint(("Ceasefire Driver: No rule matched, using default policy: %d\n", g_DefaultAllow));
    return FALSE;
}
