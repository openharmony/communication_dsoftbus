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

#include "mem_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
    Function    : MpDestroyMemPool

    Description : This function will be invoked to destroy the memory pool
                  created using MpCreateMemPool.

    Input       : pool - memory pool handle

    Output      : None

    Return      : None
*******************************************************************************/
void MpDestroyMemPool(struct MemPool *pool)
{
    if (pool == FILLP_NULL_PTR) {
        return;
    }

    switch (pool->allocType) {
        case SPUNGE_ALLOC_TYPE_MALLOC:
        case SPUNGE_ALLOC_TYPE_CALLOC:
            SpungeFree(pool, pool->allocType);
            break;
        default:
            break;
    }
    return;
}

/*******************************************************************************
    Function    : MpCalMemSize

    Description : This function will be invoked to calculate the memory size
                  required for memory pool, based on size and num.

    Input       : itemSize - Size of item
                  itemNum - item number

    Output      : None

    Return      : Memory size of memory pool.
*******************************************************************************/
size_t MpCalMemSize(size_t itemSize, size_t itemNum)
{
    size_t sizePrepare;
    size_t memSize;

    sizePrepare = itemSize + sizeof(struct MemPoolItem);
    if ((itemSize == 0) || (sizePrepare < sizeof(struct MemPoolItem))) {
        return 0;
    }

    memSize = (sizePrepare * itemNum);
    if ((memSize == 0) || (memSize / sizePrepare != itemNum)) {
        return 0;
    }

    memSize = memSize + sizeof(struct MemPool);
    if (memSize < sizeof(struct MemPool)) {
        return 0;
    }

    sizePrepare = FillpQueueCalMemSize(itemNum);
    memSize = memSize + sizePrepare;
    if ((sizePrepare == 0) || (memSize < sizePrepare)) {
        return 0;
    }

    return memSize;
}

/*******************************************************************************
    Function    : MpCreateMemPool

    Description : This function will be invoked to create memory pool, based on
                  size and num.

    Input       : name - memory pool name
                  itemSize - Size of item
                  itemNum - item number
                  allocType - type of alloc

    Output      : None

    Return      : Memory pool handle.
*******************************************************************************/
struct MemPool *MpCreateMemPool(
    FILLP_CHAR *name,
    FILLP_SIZE_T itemSize,
    FILLP_SIZE_T itemNum,
    FILLP_INT allocType)
{
    FILLP_SIZE_T i;
    FILLP_SIZE_T offset;
    struct MemPool *pool = FILLP_NULL_PTR;
    FILLP_SIZE_T itemTotalSize = itemSize + sizeof(struct MemPoolItem);
    if (itemNum == 0) {
        return FILLP_NULL_PTR;
    }

    pool = (struct MemPool *)SpungeAlloc(1, MpCalMemSize(itemSize, itemNum), allocType);
    if (pool == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate the MemPool data \n");
        return FILLP_NULL_PTR;
    }

    pool->allocType = allocType;

    FillpQueueInit(&pool->q, name, itemNum, allocType);

    pool->memStart = (void *)((char *)&pool->q + FillpQueueCalMemSize(itemNum));
    pool->size = 0;

    offset = 0;
    for (i = 0; i < itemNum; i++) {
        struct MemPoolItem *item = (struct MemPoolItem *)(void *)((char *)pool->memStart + offset);
        offset += itemTotalSize;

        item->p = (void *)((char *)item + sizeof(struct MemPoolItem));
        item->pool = pool;

        if (FillpQueuePush(&pool->q, (void *)&item, FILLP_TRUE, 1)) {
            FILLP_LOGERR("Failed to enqueue item \r\n");
            MpDestroyMemPool(pool);
            return FILLP_NULL_PTR;
        }

        pool->size++;
    }

    return pool;
}

void MpSetConsSafe(struct MemPool *mp, FILLP_BOOL consSafe)
{
    FillpQueueSetConsSafe(&mp->q, consSafe);
}

void MpSetProdSafe(struct MemPool *mp, FILLP_BOOL prodSafe)
{
    FillpQueueSetProdSafe(&mp->q, prodSafe);
}


/*******************************************************************************
    Function    : MpMallocWait

    Description : This function will be invoked to create memory pool, based on
                  size and num.

    Input       : mp - memory pool handle
                  pp - memory to be allocated
                  wait - flag to wait

    Output      : pp - allocated memory

    Return      : ERR_OK on success. Error codes on failure.
*******************************************************************************/
FillpErrorType MpMallocWait(struct MemPool *mp, void **pp)
{
    struct MemPoolItem *tmp = FILLP_NULL_PTR;
    if (mp == FILLP_NULL_PTR) {
        FILLP_LOGERR("MemPool pointer is invalid \n");
        return ERR_NULLPTR;
    }

    if (FillpQueuePop(&mp->q, (void *)&tmp, 1) <= 0) {
        return ERR_NOBUFS;
    }
    *pp = (char *)tmp + sizeof(struct MemPoolItem); /* For Shaed Memory, access tmp->p may core dump */
    return ERR_OK;
}

/* Shared Memory . Can't access item->pool, so has to delivery the pool
 pool should be ok to access, and data is the address of FillP */
void MpFreeWithPool(void *data, struct MemPool *pool)
{
    struct MemPoolItem *item = FILLP_NULL_PTR;
    if ((data == FILLP_NULL_PTR) || (pool == FILLP_NULL_PTR)) {
        return;
    }

    item = MpItemEntry(data);
    if (FillpQueuePush(&pool->q, (void *)&item, FILLP_FALSE, 1)) {
        return;
    }
}

#ifdef __cplusplus
}
#endif
