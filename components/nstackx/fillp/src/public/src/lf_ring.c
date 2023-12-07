/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "log.h"
#include "fillp_function.h"
#include "lf_ring.h"

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Function    : FillpLfRingCalMemSize
 *
 * Description : This function will be invoked to calculate the memory size
 * required for lock-free queue, based on size.
 *
 * Input       : size - no of items of lock-free queue
 *
 * Output      : None
 *
 * Return      : Memory size of lock-free queue
 */
size_t FillpLfRingCalMemSize(size_t size)
{
    size_t memSize = size * sizeof(void *);
    if ((memSize == 0) || (memSize / sizeof(void *) != size)) {
        return 0;
    }

    memSize = memSize + sizeof(struct FillpLfRing);
    if (memSize < sizeof(struct FillpLfRing)) {
        return 0;
    }
    return memSize;
}

/*
 * Function    : FillpLfRingInit
 *
 * Description : This function will be invoked to init the lock-free queue.
 *
 * Input       : ring - lock-free queue to be initialized
 * name - name to be added to the lock-free queue
 * size - size of lock-free queue
 *
 * Output      : ring - initialized lock-free queue
 *
 * Return      : None
 */
void FillpLfRingInit(struct FillpLfRing *ring, char *name, size_t size)
{
    FILLP_UNUSED_PARA(name);
    if (ring == FILLP_NULL_PTR) {
        return;
    }

    if (size == 0) {
        return;
    }

    ring->size = (FILLP_ULONG)size;

    ring->cons.head = 0;
    ring->cons.tail = 0;

    ring->prod.head = 0;
    ring->prod.tail = 0;
    ring->consSafe = FILLP_TRUE;
    ring->prodSafe = FILLP_TRUE;

    (void)memset_s(ring->name, sizeof(ring->name), '\0', sizeof(ring->name));
}

void FillpLfRingSetProdSafe(struct FillpLfRing *ring, FILLP_BOOL safe)
{
    ring->prodSafe = safe;
}

void FillpLfRingSetConsSafe(struct FillpLfRing *ring, FILLP_BOOL safe)
{
    ring->consSafe = safe;
}

static FILLP_ULONG FillpLfRingMpEnqueueWait(struct FillpLfRing *ring, FILLP_UINT count,
    FILLP_ULONG *prodHead, FILLP_ULONG *prodNext)
{
    FILLP_ULONG consTail;
    FILLP_ULONG freeEntries;
    FILLP_ULONG ret;
    do {
        *prodHead = ring->prod.head;
        consTail = ring->cons.tail;

        sys_arch_compiler_barrier();
        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * prod_head > cons_tail). So 'free_entries' is always between 0
         * and size(ring). */
        freeEntries = (ring->size + consTail - *prodHead);

        /* check that we have enough room in ring */
        if (freeEntries == 0) {
            return 0;
        }
        ret = ((freeEntries > count) ? count : freeEntries);
        *prodNext = *prodHead + ret;

        if (!ring->prodSafe) {
            ring->prod.head = *prodNext;
            break;
        }
    } while (unlikely(!CAS(&ring->prod.head, *prodHead, *prodNext)));

    return ret;
}

FillpErrorType FillpLfRingMpEnqueue(struct FillpLfRing *ring, void **dataTable, FILLP_UINT count)
{
    FILLP_ULONG prodHead = 0;
    FILLP_ULONG prodNext = 0;
    FILLP_ULONG i;
    FILLP_ULONG j;
    FILLP_ULONG rep = 0;
    FILLP_ULONG ret;

    if ((ring == FILLP_NULL_PTR) || (dataTable == FILLP_NULL_PTR) || (count == 0)) {
        return ERR_PARAM;
    }
    /* move prod.head atomically */
    ret = FillpLfRingMpEnqueueWait(ring, count, &prodHead, &prodNext);
    if (ret == 0) {
        return ERR_NOBUFS;
    }

    /* write entries in ring */
    for (i = 0, j = 1; i < (FILLP_UINT)ret; i++, j++) {
        ring->ringCache[(prodHead + j) % ring->size] = dataTable[i];
    }

    sys_arch_compiler_barrier();

    /*
     * If there are other enqueues in progress that preceded us,
     * we need to wait for them to complete
     */
    while (unlikely(ring->prod.tail != prodHead)) {
        FILLP_RTE_PAUSE();

        /* Set FTDP_RING_PAUSE_REP_COUNT to avoid spin too long waiting
         * for other thread finish. It gives pre-empted thread a chance
         * to proceed and finish with ring dequeue operation. */
#if LF_RING_PAUSE_REP_COUNT
        if (++rep == LF_RING_PAUSE_REP_COUNT) {
            rep = 0;
            (void)SYS_ARCH_SCHED_YIELD();
        }
#endif
    }

    ring->prod.tail = prodNext;

    FILLP_UNUSED_PARA(rep);

    return (FillpErrorType)ret;
}

static FILLP_ULONG FillpLfRingMcDequeueWait(struct FillpLfRing *ring, FILLP_UINT count, FILLP_ULONG *consHead,
    FILLP_ULONG *consNext)
{
    FILLP_ULONG prodTail;
    FILLP_ULONG entries;
    FILLP_ULONG ret;

    do {
        *consHead = ring->cons.head;
        prodTail = ring->prod.tail;
        sys_arch_compiler_barrier();
        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * cons_head > prod_tail). So 'entries' is always between 0
         * and size(ring)-1. */
        entries = (prodTail - *consHead);

        /* Set the actual entries for dequeue */
        if (entries == 0) {
            return 0;
        }
        ret = ((entries > count) ? count : entries);
        *consNext = *consHead + ret;

        if (!ring->consSafe) {
            ring->cons.head = *consNext;
            break;
        }
    } while (unlikely(!CAS(&ring->cons.head, *consHead, *consNext)));

    return ret;
}

FILLP_INT FillpLfRingMcDequeue(struct FillpLfRing *ring, void **dataTable, FILLP_UINT count)
{
    FILLP_ULONG consHead;
    FILLP_ULONG consNext;
    FILLP_ULONG rep = 0;
    FILLP_ULONG i;
    FILLP_ULONG j;
    FILLP_ULONG ret;

    if ((ring == FILLP_NULL_PTR) || (dataTable == FILLP_NULL_PTR) || (count == 0)) {
        return ERR_PARAM;
    }
    /* move cons.head atomically */
    ret = FillpLfRingMcDequeueWait(ring, count, &consHead, &consNext);
    if (ret == 0) {
        return ERR_NOBUFS;
    }

    /* copy in table */
    for (i = 0, j = 1; i < ret; i++, j++) {
        dataTable[i] = ring->ringCache[(consHead + j) % ring->size];
    }

    sys_arch_compiler_barrier();

    /*
     * If there are other dequeues in progress that preceded us,
     * we need to wait for them to complete
     */
    while (unlikely(ring->cons.tail != consHead)) {
        FILLP_RTE_PAUSE();

        /* Set RTE_RING_PAUSE_REP_COUNT to avoid spin too long waiting
         * for other thread finish. It gives pre-empted thread a chance
         * to proceed and finish with ring dequeue operation. */
#if LF_RING_PAUSE_REP_COUNT
        if (++rep == LF_RING_PAUSE_REP_COUNT) {
            rep = 0;
            (void)SYS_ARCH_SCHED_YIELD();
        }
#endif
    }

    ring->cons.tail = consNext;

    FILLP_UNUSED_PARA(rep);

    return (FILLP_INT)ret;
}

FILLP_INT FillpRingEmpty(const struct FillpLfRing *r)
{
    FILLP_ULONG prodTail = r->prod.tail;
    FILLP_ULONG consTail = r->cons.tail;
    return (consTail == prodTail);
}


FILLP_INT FillpRingFreeEntries(const struct FillpLfRing *r)
{
    FILLP_ULONG consTail;
    FILLP_ULONG prodHead;
    FILLP_ULONG remain;
    FILLP_INT cnt;

    if (r == FILLP_NULL_PTR) {
        FILLP_LOGERR("ring is NULL pointer");
        return 0;
    }

    consTail = r->cons.tail;
    prodHead = r->prod.head;

    remain = (r->size + consTail - prodHead);
    cnt = (int)remain;
    if (cnt < 0) {
        FILLP_LOGERR("cnt is %d, real size:%lu", cnt, remain);
        cnt = 0;
    }

    return cnt;
}

FILLP_ULONG FillpRingValidOnes(struct FillpLfRing *r)
{
    FILLP_ULONG prodTail;
    FILLP_ULONG consHead;
    FILLP_ULONG ret;
    if (r == FILLP_NULL_PTR) {
        return 0;
    }

    prodTail = r->prod.tail;
    consHead = r->cons.head;

    ret = prodTail - consHead;
    if (((FILLP_SLONG)ret) < 0) {
        ret = r->size;
    }
    return ret;
}

#ifdef __cplusplus
}
#endif
