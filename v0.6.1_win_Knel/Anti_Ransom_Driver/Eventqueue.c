// ===========================================================================
// File: EventQueue.c   (신규)
// Developer: CHOI HWAN
// ===========================================================================
#include "Driver.h"
#include "EventQueue.h"

// 노드 하나가 어떤 타입의 이벤트든 담는다(union, Common.h ARW_EVENT_ANY).
// 크기는 가장 큰 멤버(ARW_FILE_EVENT 2232B) 기준 — 깊이 1024 에서 약 2.3MB
// NonPaged 상한(lookaside 는 지연 할당). 타입별 lookaside 로 쪼개지 않는
// 이유: 프로세스/파일 이벤트가 **하나의 FIFO** 에서 발생 순서대로 나가야
// 상관분석의 시간 정렬이 성립하기 때문.
// 실제 유효 바이트는 Event.Header.PayloadSize 이고, 그 뒤 꼬리는 미초기화
// 상태로 남지만 Drain 이 PayloadSize 만 복사하므로 유저로 유출되지 않는다.
typedef struct _ARW_EVENT_NODE {
    LIST_ENTRY     ListEntry;
    ARW_EVENT_ANY  Event;
} ARW_EVENT_NODE, * PARW_EVENT_NODE;

C_ASSERT(sizeof(ARW_EVENT_NODE) == sizeof(LIST_ENTRY) + ARW_MAX_EVENT_SIZE);

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
NTSTATUS ArwEventQueuePush(_In_ PARW_EVENT_HEADER Event)
{
    PARW_EVENT_NODE node;
    PARW_EVENT_NODE victim = NULL;
    KIRQL oldIrql;
    ULONG payloadSize;

    if (!g_QueueReady || !g_LookasideReady) {
        return STATUS_DEVICE_NOT_READY;
    }

    // 복사 길이는 호출자가 헤더에 적은 PayloadSize 를 신뢰한다 — 단, 노드를
    // 넘치는 값(오버플로우)과 헤더보다 작은 값(쓰레기 헤더)은 거부한다.
    // 커널 내부 호출자(ProcessMonitor / 미니필터 콜백)만 이 함수를 쓰므로
    // 여기서 걸리면 호출자 버그다. 유저 입력이 아니다.
    payloadSize = Event->PayloadSize;
    if (payloadSize < sizeof(ARW_EVENT_HEADER) || payloadSize > ARW_MAX_EVENT_SIZE) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        return STATUS_INVALID_PARAMETER;
    }

    node = (PARW_EVENT_NODE)ExAllocateFromLookasideListEx(&g_EventLookaside);
    if (node == NULL) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&node->Event, Event, payloadSize);

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
    ULONG payloadSize;

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

        // 이 노드의 실제 크기만큼만 요구·복사한다(프로세스 1616B / 파일 2232B).
        // Push 가 범위를 검증했으므로 여기서는 노드 안의 값을 신뢰한다.
        payloadSize = node->Event.Header.PayloadSize;

        status = WdfRequestRetrieveOutputBuffer(
            request,
            payloadSize,
            &outBuffer,
            &outLength);

        if (NT_SUCCESS(status) && outLength >= payloadSize) {
            RtlCopyMemory(outBuffer, &node->Event, payloadSize);
            WdfRequestCompleteWithInformation(
                request, STATUS_SUCCESS, payloadSize);
            // 통계: 전달 완료. 전역은 .data(NonPaged) 이고 Interlocked 는
            // IRQL 제약이 없어 DISPATCH_LEVEL 에서도 안전하다.
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
        // 통계: 미전달 폐기. 엔진 해제(ArwpUnregisterEngine)와
        // 언로드(ArwEventQueueUninitialize) 양쪽 호출 모두 집계된다.
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

// ===========================================================================
// 파일 이벤트 싱크 (Anti_Ransom_FsFilter -> 이 드라이버)
//
// 두 드라이버는 별개 .sys 라 함수를 직접 부를 수 없다. 커널 콜백 객체
// (ExCreateCallback / ExRegisterCallback / ExNotifyCallback)로 단방향 전달한다.
//   - 로드 순서 무관: 먼저 뜬 쪽이 객체를 만들고, 나중 쪽은 같은 이름을 연다.
//   - 이 드라이버가 없으면 미니필터의 ExNotifyCallback 은 no-op (이벤트 유실,
//     미니필터 쪽 카운터로 관측). 하드 의존(import)이 없어 격리 원칙 유지.
//
// 규약 (Common.h ARW_FILE_EVENT_CALLBACK_NAME 주석과 동일):
//   Argument1 = PARW_FILE_EVENT — 송신자의 NonPaged 버퍼. 이 호출 동안만 유효.
//   Argument2 = NULL
//   송신자는 Header.EventType / 페이로드만 채운다. 이 루틴이 송신자 버퍼의
//   Header 를 **덮어써서**(Magic/Version/TimeStamp/SequenceNumber) 프로세스
//   이벤트와 단일 시퀀스 공간을 만든 뒤 Push 한다. Push 가 노드로 복사하므로
//   여기서 별도 버퍼를 할당하지 않는다(2232B 를 스택에 올리지도 않는다).
//
// IRQL: ExNotifyCallback 은 송신자 IRQL 그대로 들어온다. 미니필터 post-op 는
//   DISPATCH_LEVEL 일 수 있으므로 이 루틴은 DISPATCH 에서 안전해야 한다 —
//   InitializeHeader / Push 모두 DISPATCH 허용, 페이지드 메모리 접근 없음.
//   (이 함수는 페이지드 섹션에 두지 않는다.)
//
// 언로드 순서: g_SinkActive=FALSE -> ExUnregisterCallback(진행 중 호출 완료를
//   기다린다) -> ObDereferenceObject. 이 뒤에 큐를 해제해야 한다.
// ===========================================================================
static PCALLBACK_OBJECT g_FileEventCallbackObject = NULL;
static PVOID            g_FileEventCallbackHandle = NULL;
static volatile LONG    g_SinkActive = 0;

static VOID
ArwpFileEventSinkRoutine(
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    PARW_FILE_EVENT ev = (PARW_FILE_EVENT)Argument1;
    ULONG type;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Argument2);

    if (ev == NULL) {
        return;
    }
    // 언로드 진행 중이거나 큐가 아직 없으면 조용히 버린다.
    if (InterlockedCompareExchange(&g_SinkActive, 0, 0) == 0 || !g_QueueReady) {
        return;
    }

    // 규약 검증 — 송신자 버그 방어. 유저 모드로 올라가기 전에 여기서 걸러둔다.
    //   1) EventType 은 파일 이벤트 둘 중 하나
    //   2) EventType 과 OperationType 이 일치
    //   3) 길이 필드가 배열을 넘지 않음 (엔진이 길이로 역참조한다)
    type = ev->Header.EventType;
    if (type != EVENT_TYPE_FILE_WRITE && type != EVENT_TYPE_FILE_RENAME) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        return;
    }
    if ((type == EVENT_TYPE_FILE_WRITE  && ev->OperationType != ARW_FILE_OP_WRITE) ||
        (type == EVENT_TYPE_FILE_RENAME && ev->OperationType != ARW_FILE_OP_RENAME)) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        return;
    }
    if (ev->FilePathLength     > sizeof(ev->FilePath) ||
        ev->NewExtensionLength > sizeof(ev->NewExtension)) {
        InterlockedIncrement64(&g_ArwStatEventsDropped);
        return;
    }

    ArwEventInitializeHeader(&ev->Header, type, sizeof(ARW_FILE_EVENT));
    ArwEventQueuePush(&ev->Header);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ArwFileEventSinkInitialize(VOID)
{
    NTSTATUS          status;
    UNICODE_STRING    name;
    OBJECT_ATTRIBUTES oa;

    PAGED_CODE();

    if (g_FileEventCallbackObject != NULL) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlInitUnicodeString(&name, ARW_FILE_EVENT_CALLBACK_NAME);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Create=TRUE: 없으면 만들고 있으면 연다. AllowMultipleCallbacks=TRUE:
    // 미니필터도 같은 객체를 열어 쓰므로(송신 전용이라 등록은 안 하지만) 허용.
    status = ExCreateCallback(&g_FileEventCallbackObject, &oa, TRUE, TRUE);
    if (!NT_SUCCESS(status)) {
        ARW_LOG("ExCreateCallback(%wZ) failed (0x%08X)\n", &name, status);
        g_FileEventCallbackObject = NULL;
        return status;
    }

    g_FileEventCallbackHandle =
        ExRegisterCallback(g_FileEventCallbackObject, ArwpFileEventSinkRoutine, NULL);
    if (g_FileEventCallbackHandle == NULL) {
        ARW_LOG("ExRegisterCallback failed\n");
        ObDereferenceObject(g_FileEventCallbackObject);
        g_FileEventCallbackObject = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InterlockedExchange(&g_SinkActive, 1);
    ARW_LOG("File event sink registered on %wZ\n", &name);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID ArwFileEventSinkUninitialize(VOID)
{
    PAGED_CODE();

    // 1) 신규 수신 차단. 2) 진행 중인 수신이 끝날 때까지 ExUnregisterCallback 이
    //    동기화한다. 3) 객체 참조 해제. 이 순서 뒤에만 큐를 지워도 안전하다.
    InterlockedExchange(&g_SinkActive, 0);

    if (g_FileEventCallbackHandle != NULL) {
        ExUnregisterCallback(g_FileEventCallbackHandle);
        g_FileEventCallbackHandle = NULL;
    }
    if (g_FileEventCallbackObject != NULL) {
        ObDereferenceObject(g_FileEventCallbackObject);
        g_FileEventCallbackObject = NULL;
    }
    ARW_LOG("File event sink unregistered.\n");
}