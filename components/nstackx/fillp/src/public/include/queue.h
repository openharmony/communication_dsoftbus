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

#ifndef FILLP_QUEUE_H
#define FILLP_QUEUE_H

#include "lf_ring.h"
#include "log.h"
#include "spunge_mem.h"
#include "fillp_function.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct InnerfillpQueue {
    FILLP_INT allocType;
#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
    size_t size;
    struct FillpLfRing ring;
} FillpQueue;

static __inline FillpErrorType FillpQueuePush(FillpQueue *q, void **msg, FILLP_INT isTryPush, FILLP_UINT count)
{
    FILLP_INT ret;
    FILLP_INT totalPush = 0;
    for (;;) {
        ret = FillpLfRingMpEnqueue(&q->ring, &msg[totalPush], count - (FILLP_UINT)totalPush);
        if (ret > 0) {
            totalPush += ret;
            if ((FILLP_UINT)totalPush == count) {
                return ERR_OK;
            }
        } else if (isTryPush) {
            return ERR_NOBUFS;
        }
    }
}

static __inline FILLP_INT FillpQueuePop(FillpQueue *q, void **msg, FILLP_UINT count)
{
    if ((q == FILLP_NULL_PTR) || (msg == FILLP_NULL_PTR)) {
        return -1;
    }

    return FillpLfRingMcDequeue(&q->ring, msg, count);
}

static __inline int QueueEmpty(FILLP_CONST FillpQueue *q)
{
    return FillpRingEmpty(&q->ring);
}

static __inline size_t FillpQueueCalMemSize(size_t size)
{
    size_t tmpSize = FillpLfRingCalMemSize(size);
    size_t memSize = tmpSize + sizeof(FillpQueue);

    if ((tmpSize == 0) || (memSize < sizeof(FillpQueue))) {
        return 0;
    }

    return memSize;
}

static __inline void FillpQueueSetProdSafe(FillpQueue *q, FILLP_BOOL safe)
{
    FillpLfRingSetProdSafe(&q->ring, safe);
}

static __inline void FillpQueueSetConsSafe(FillpQueue *q, FILLP_BOOL safe)
{
    FillpLfRingSetConsSafe(&q->ring, safe);
}

static __inline void FillpQueueInit(FillpQueue *q, char *name, size_t size, FILLP_INT allocType)
{
    FillpLfRingInit(&q->ring, name, size);

    q->allocType = allocType;
    q->size = size;
}

static __inline FillpQueue *FillpQueueCreate(char *name, size_t size, FILLP_INT allocType)
{
    FillpQueue *q;
    q = (FillpQueue *)SpungeAlloc(1, FillpQueueCalMemSize(size), allocType);
    if (q == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate the memory for queue \r\n");
        return FILLP_NULL_PTR;
    }

    FillpQueueInit(q, name, size, allocType);

    return q;
}

static __inline void FillpQueueDestroy(FillpQueue *q)
{
    if (q == FILLP_NULL_PTR) {
        return;
    }

    if ((q->allocType == SPUNGE_ALLOC_TYPE_MALLOC) || (q->allocType == SPUNGE_ALLOC_TYPE_CALLOC)) {
        SpungeFree(q, q->allocType);
    }
}

static __inline FILLP_ULONG FillpQueueValidOnes(FillpQueue *q)
{
    if (q == FILLP_NULL_PTR) {
        return 0;
    }
    return FillpRingValidOnes(&q->ring);
}

#ifdef __cplusplus
}
#endif

#endif /* FILLP_QUEUE_H */
