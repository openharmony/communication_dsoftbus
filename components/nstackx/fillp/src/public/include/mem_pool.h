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

#ifndef FILLP_MEM_POOL_H
#define FILLP_MEM_POOL_H

#include "lf_ring.h"
#include "queue.h"
#include "log.h"
#ifdef __cplusplus
extern "C" {
#endif

struct MemPool {
    FILLP_UINT32 size; /* Total size */
    FILLP_INT allocType;
    void *allocArg;
    void *memStart; /* Memory start */
    FillpQueue q;
};

struct MemPoolItem {
    void *p; /* data */
    struct MemPool *pool;
};

static __inline struct MemPoolItem *MpItemEntry(void *ptr)
{
    return (struct MemPoolItem *)((char *)(ptr) - sizeof(struct MemPoolItem));
};

/*******************************************************************************
    Function    : MpCalMemSize

    Description : This function will be invoked to calculate the memory size
                  required for memory pool, based on size and num.

    Input       : itemSize - Size of item
                  itemNum - item number

    Output      : None

    Return      : Memory size of memory pool.
*******************************************************************************/
size_t MpCalMemSize(size_t itemSize, size_t itemNum);

/*******************************************************************************
    Function    : MpDestroyMemPool

    Description : This function will be invoked to destroy the memory pool
                  created using MpCreateMemPool.

    Input       : pool - memory pool handle

    Output      : None

    Return      : None
*******************************************************************************/
void MpDestroyMemPool(struct MemPool *pool);

/*******************************************************************************
    Function    : MpCreateMemPool

    Description : This function will be invoked to create memory pool, based on
                  size and num.

    Input       : name - memory pool name
                  itemSize - Size of item
                  itemNum - item number
                  allocType - type of alloc
                  allocArg - memory zone

    Output      : None

    Return      : Memory pool handle.
*******************************************************************************/
struct MemPool *MpCreateMemPool(FILLP_CHAR *name, FILLP_SIZE_T itemSize, FILLP_SIZE_T itemNum, FILLP_INT allocType);

void MpSetConsSafe(struct MemPool *mp, FILLP_BOOL consSafe);
void MpSetProdSafe(struct MemPool *mp, FILLP_BOOL prodSafe);

FillpErrorType MpMallocWait(struct MemPool *mp, void **pp);
void MpFreeWithPool(void *data, struct MemPool *pool);

#define MP_MALLOC(mp, pp) MpMallocWait((mp), (void **)(pp))

#ifdef __cplusplus
}
#endif

#endif /* FILLP_MEM_POOL_H */
