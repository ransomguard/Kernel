"""Offline source-structure checks; these are NOT WDK build/runtime tests."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "Anti_Ransom_Driver" / "Eventqueue.c").read_text(encoding="utf-8-sig")


class QueueOrderSourceTests(unittest.TestCase):
    def test_initializer_does_not_assign_producer_order(self):
        initializer = SOURCE.split("VOID ArwEventInitializeHeader(", 1)[1].split(
            "ULONG ArwEventQueueGetDepth(", 1
        )[0]
        self.assertIn("Header->SequenceNumber = 0;", initializer)
        self.assertNotIn("InterlockedIncrement64(&g_SequenceNumber)", initializer)

    def test_queue_assigns_sequence_inside_fifo_lock(self):
        push = SOURCE.split("NTSTATUS ArwEventQueuePush(", 1)[1].split(
            "VOID ArwEventQueueDrain(", 1
        )[0]
        acquired = push.index("KeAcquireSpinLock(&g_EventListLock, &oldIrql);")
        sequenced = push.index("InterlockedIncrement64(&g_SequenceNumber)")
        inserted = push.index("InsertTailList(&g_EventListHead, &node->ListEntry);")
        released = push.index("KeReleaseSpinLock(&g_EventListLock, oldIrql);")
        self.assertLess(acquired, sequenced)
        self.assertLess(sequenced, inserted)
        self.assertLess(inserted, released)
        self.assertEqual(SOURCE.count("InterlockedIncrement64(&g_SequenceNumber)"), 1)

    def test_abi_layout_is_unchanged(self):
        common = (ROOT / "Shared" / "Common.h").read_text(encoding="utf-8-sig")
        self.assertIn("C_ASSERT(sizeof(ARW_EVENT_HEADER) == 32);", common)
        self.assertIn("ARW_EVENT_QUEUE_MAX_DEPTH  1024U", common)


if __name__ == "__main__":
    unittest.main()
