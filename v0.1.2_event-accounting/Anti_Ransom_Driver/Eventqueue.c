// ===========================================================================
// File: EventQueue.c   (신규)
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "EventQueue.h"

typedef struct _ARW_EVENT_NODE {
    LIST_ENTRY        ListEntry;
    ARW_PROCESS_EVENT Event;
} ARW_EVENT_NODE, * PARW_EVENT_NODE;

static LIST_ENTRY          g_EventListHead;
static KSPIN_LOCK          g_EventListLock;
static ULONG               g_EventListDepth = 0;
static LOOKASIDE_LIST_EX   g_EventLookaside;
static BOOLEAN             g_LookasideReady = FALSE;
static BOOLEAN             g_QueueReady = FALSE;
static WDFQUEUE            g_PendingQueue = NULL;
static volatile LONG64     g_SequenceNumber = 0;

// ---------------------------------------------------------------------------
// 초기화
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwEventQueueInitialize(_In_ WDFQUEUE PendingQueue)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_QueueReady) {
        return STATUS_ALREADY_INITIALIZED;
    }

    InitializeListHead(&g_EventListHead);
    KeInitializeSpinLock(&g_EventListLock);
    g_EventListDepth = 0;

    // 콜백은 임의 스레드 컨텍스트에서 돌고 스핀락을 잡은 채 접근하므로
    // 반드시 NonPagedPoolNx 여야 한다. 페이징 가능 메모리면
    // DISPATCH_LEVEL 에서 페이지 폴트가 나 IRQL_NOT_LESS_OR_EQUAL 로 즉사한다.
    status = ExInitializeLookasideListEx(
        &g_EventLookaside,
        NULL,
        NULL,
        NonPagedPoolNx,
        0,
        sizeof(ARW_EVENT_NODE),
        ARW_POOL_TAG,
        0);

    if (!NT_SUCCESS(status)) {
        ARW_LOG("ExInitializeLookasideListEx failed (0x%08X)\n", status);
        return status;
    }

    g_LookasideReady = TRUE;
    g_PendingQueue = PendingQueue;
    g_QueueReady = TRUE;

    ARW_LOG("Event queue initialized (node=%Iu bytes, max depth=%u)\n",
        sizeof(ARW_EVENT_NODE), ARW_EVENT_QUEUE_MAX_DEPTH);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 해제
// ---------------------------------------------------------------------------
_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwEventQueueUninitialize(VOID)
{
    PAGED_CODE();

    // 신규 적재를 먼저 차단한 뒤 잔여 노드를 비운다.
    g_QueueReady = FALSE;
    ArwEventQueueFlush();

    if (g_LookasideReady) {
        ExDeleteLookasideListEx(&g_EventLookaside);
        g_LookasideReady = FALSE;
    }

    g_PendingQueue = NULL;
    ARW_LOG("Event queue uninitialized.\n");
}

// ---------------------------------------------------------------------------
// 헤더 채우기
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEventInitializeHeader(
    _Out_ PARW_EVENT_HEADER Header,
    _In_  ULONG             EventType,
    _In_  ULONG             PayloadSize
)
{
    LARGE_INTEGER now;

    Header->Magic = ARW_HEADER_MAGIC;
    Header->Version = ARW_DRIVER_VERSION;
    Header->EventType = EventType;
    Header->PayloadSize = PayloadSize;

    // KeQuerySystemTime 은 매크로로 KeQuerySystemTimePrecise 를 쓰지 않으므로
    // 상관분석의 시간 정렬 정확도를 위해 Precise 버전을 명시적으로 쓴다.
    KeQuerySystemTimePrecise(&now);
    Header->TimeStamp = (ULONG64)now.QuadPart;

    Header->SequenceNumber =
        (ULONG64)InterlockedIncrement64(&g_SequenceNumber);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG ArwEventQueueGetDepth(VOID)
{
    KIRQL oldIrql;
    ULONG depth;

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    depth = g_EventListDepth;
    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    return depth;
}

// ---------------------------------------------------------------------------
// 내부: 노드 하나 꺼내기 (없으면 NULL)
// ---------------------------------------------------------------------------
static PARW_EVENT_NODE ArwpPopEventNode(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry = NULL;

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    if (!IsListEmpty(&g_EventListHead)) {
        entry = RemoveHeadList(&g_EventListHead);
        g_EventListDepth--;
    }
    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    if (entry == NULL) {
        return NULL;
    }
    return CONTAINING_RECORD(entry, ARW_EVENT_NODE, ListEntry);
}

// 내부: 소비되지 못한 노드를 원위치(머리)로 되돌린다. 순서 보존이 목적.
static VOID ArwpPushEventNodeFront(_In_ PARW_EVENT_NODE Node)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);
    InsertHeadList(&g_EventListHead, &Node->ListEntry);
    g_EventListDepth++;
    KeReleaseSpinLock(&g_EventListLock, oldIrql);
}

static VOID ArwpFreeEventNode(_In_ PARW_EVENT_NODE Node)
{
    if (g_LookasideReady) {
        ExFreeToLookasideListEx(&g_EventLookaside, Node);
    }
}

// ---------------------------------------------------------------------------
// 이벤트 적재
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS ArwEventQueuePush(_In_ PARW_PROCESS_EVENT Event)
{
    PARW_EVENT_NODE node;
    PARW_EVENT_NODE victim = NULL;
    KIRQL oldIrql;

    if (!g_QueueReady || !g_LookasideReady) {
        return STATUS_DEVICE_NOT_READY;
    }

    node = (PARW_EVENT_NODE)ExAllocateFromLookasideListEx(&g_EventLookaside);
    if (node == NULL) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&node->Event, Event, sizeof(ARW_PROCESS_EVENT));

    KeAcquireSpinLock(&g_EventListLock, &oldIrql);

    // 포화 시 '가장 오래된' 이벤트를 버린다.
    // 신규 이벤트를 버리면 실시간 대응이 무력화되므로 방향이 중요하다.
    if (g_EventListDepth >= ARW_EVENT_QUEUE_MAX_DEPTH) {
        PLIST_ENTRY oldest = RemoveHeadList(&g_EventListHead);
        g_EventListDepth--;
        victim = CONTAINING_RECORD(oldest, ARW_EVENT_NODE, ListEntry);
    }

    InsertTailList(&g_EventListHead, &node->ListEntry);
    g_EventListDepth++;

    KeReleaseSpinLock(&g_EventListLock, oldIrql);

    // 해제는 락 밖에서 수행한다.
    if (victim != NULL) {
        ArwpFreeEventNode(victim);
        InterlockedIncrement64(&g_ArwStatEventsDropped);
    }

    InterlockedIncrement64(&g_ArwStatEventsGenerated);

    // 대기 중인 GET_EVENT 요청이 있으면 즉시 완료시킨다.
    ArwEventQueueDrain();

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// 적재된 이벤트 <-> 대기 중인 요청 매칭
//
// [순서 주의] 요청을 먼저 꺼내면, 줄 이벤트가 없을 때 요청을 되돌리기가 번거롭다.
//            이벤트를 먼저 꺼내고 짝이 없으면 이벤트를 머리로 되돌린다.
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEventQueueDrain(VOID)
{
    NTSTATUS status;
    WDFREQUEST request;
    PARW_EVENT_NODE node;
    PVOID outBuffer;
    size_t outLength;

    if (!g_QueueReady || g_PendingQueue == NULL) {
        return;
    }

    for (;;) {
        node = ArwpPopEventNode();
        if (node == NULL) {
            break;  // 보낼 이벤트 없음
        }

        status = WdfIoQueueRetrieveNextRequest(g_PendingQueue, &request);
        if (!NT_SUCCESS(status)) {
            // 대기 중인 요청이 없다. 이벤트를 되돌리고 종료.
            ArwpPushEventNodeFront(node);
            break;
        }

        status = WdfRequestRetrieveOutputBuffer(
            request,
            sizeof(ARW_PROCESS_EVENT),
            &outBuffer,
            &outLength);

        if (NT_SUCCESS(status) && outLength >= sizeof(ARW_PROCESS_EVENT)) {
            RtlCopyMemory(outBuffer, &node->Event, sizeof(ARW_PROCESS_EVENT));
            WdfRequestCompleteWithInformation(
                request, STATUS_SUCCESS, sizeof(ARW_PROCESS_EVENT));
            InterlockedIncrement64(&g_ArwStatEventsDelivered);
        }
        else {
            // 버퍼가 작으면 이벤트를 되돌려 다음 요청에서 재시도한다.
            ArwpPushEventNodeFront(node);
            WdfRequestComplete(request, STATUS_BUFFER_TOO_SMALL);
            break;
        }

        ArwpFreeEventNode(node);
    }
}

// ---------------------------------------------------------------------------
// 잔여 이벤트 폐기
// ---------------------------------------------------------------------------
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID ArwEventQueueFlush(VOID)
{
    PARW_EVENT_NODE node;

    for (;;) {
        node = ArwpPopEventNode();
        if (node == NULL) {
            break;
        }
        ArwpFreeEventNode(node);
        InterlockedIncrement64(&g_ArwStatEventsFlushed);
    }
}

// ---------------------------------------------------------------------------
// manual 큐에 걸린 요청이 취소될 때 (엔진 종료, Ctrl+C 등)
//
// 이 콜백이 없으면 취소된 요청이 큐에 영원히 남아 드라이버 언로드를 막는다.
// ---------------------------------------------------------------------------
VOID ArwEvtIoCanceledOnQueue(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(Queue);
    WdfRequestComplete(Request, STATUS_CANCELLED);
}