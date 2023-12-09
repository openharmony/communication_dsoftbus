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

#include "dympool.h"

#ifdef __cplusplus
extern "C" {
#endif
DympoolType *DympCreatePool(int initSize, int maxSize, int itemSize, FILLP_BOOL autoExpand,
                            DympoolItemOperaCbSt *itemOperaCb)
{
    DympoolType *pool = FILLP_NULL_PTR;
    if ((initSize <= 0) || (maxSize <= 0) || (itemSize <= 0)) {
        FILLP_LOGERR("Error to create pool initSize:%d,maxSize:%d,itemSize:%d", initSize, maxSize, itemSize);
        return FILLP_NULL_PTR;
    }

    pool = SpungeAlloc(1, sizeof(DympoolType), SPUNGE_ALLOC_TYPE_MALLOC);
    if (pool == FILLP_NULL_PTR) {
        FILLP_LOGERR("Can't alloc dympool");
        goto CREATE_FAIL;
    }

    pool->maxSize = maxSize;
    pool->itemSize = itemSize;
    pool->currentSize = 0;
    pool->itemOperaCb.createCb = itemOperaCb->createCb;
    pool->itemOperaCb.destroyCb = itemOperaCb->destroyCb;
    pool->autoExpand = autoExpand;
    pool->initSize = initSize;

    HLIST_INIT(&pool->mlist);

    pool->mp = FillpQueueCreate("dymp_memory_pool", (FILLP_SIZE_T)(unsigned int)maxSize, SPUNGE_ALLOC_TYPE_MALLOC);
    if (pool->mp == FILLP_NULL_PTR) {
        FILLP_LOGERR("Can't alloc queue");
        goto CREATE_FAIL;
    }

    pool->currentSize = DympAskMoreMemory(pool, initSize, FILLP_FALSE);
    if (pool->currentSize <= 0) {
        FILLP_LOGERR("Initial memory fail");
        goto CREATE_FAIL;
    }

    FILLP_LOGINF("Create pool success, maxSize:%d, currentSize:%d, itemSize:%d",
        maxSize, pool->currentSize, itemSize);

    return pool;

CREATE_FAIL:
    if (pool != FILLP_NULL_PTR) {
        if (pool->mp != FILLP_NULL_PTR) {
            FillpQueueDestroy(pool->mp);
            pool->mp = FILLP_NULL_PTR;
        }
        SpungeFree(pool, SPUNGE_ALLOC_TYPE_MALLOC);
    }

    return FILLP_NULL_PTR;
}

void DympDestroyPool(DympoolType *pool)
{
    struct HlistNode *node = FILLP_NULL_PTR;
    DympMemory *mem = FILLP_NULL_PTR;

    if (pool == FILLP_NULL_PTR) {
        return;
    }

    node = HLIST_FIRST(&pool->mlist);
    while (node != FILLP_NULL_PTR) {
        mem = DympMemoryNodeEntry(node);
        if (pool->itemOperaCb.destroyCb != FILLP_NULL_PTR) {
            char *dataPointer = (char *)((char *)mem + sizeof(DympMemory));
            int i;
            for (i = 0; i < mem->itemCnt; i++) {
                DympItemType *item = (DympItemType *)(dataPointer);
                pool->itemOperaCb.destroyCb(item);
                item->mp = FILLP_NULL_PTR;
                int offset = (int)(pool->itemSize + ((int)sizeof(DympItemType)));
                dataPointer += offset;
            }
        }

        node = node->next;
        SpungeFree(mem, SPUNGE_ALLOC_TYPE_MALLOC);
    }

    if (pool->mp != FILLP_NULL_PTR) {
        FillpQueueDestroy(pool->mp);
    }

    SpungeFree(pool, SPUNGE_ALLOC_TYPE_MALLOC);
}

void DympSetConsSafe(DympoolType *pool, FILLP_BOOL safe)
{
    FillpQueueSetConsSafe(pool->mp, safe);
}

void DympSetProdSafe(DympoolType *pool, FILLP_BOOL safe)
{
    FillpQueueSetProdSafe(pool->mp, safe);
}

static int DympExpandMemory(DympoolType *pool, int stepSizeWork)
{
    int i;
    char *dataPointer = FILLP_NULL_PTR;
    DympMemory *mem = FILLP_NULL_PTR;

    if (((FILLP_INT)((size_t)pool->itemSize + sizeof(DympItemType)) == 0) ||
        ((FILLP_INT)(FILLP_MAX_INT_VALUE - sizeof(DympMemory)) /
        (FILLP_INT)((size_t)pool->itemSize + sizeof(DympItemType))) < stepSizeWork) {
        FILLP_LOGERR("Error to ask memory, because ask size too big");
        return -1;
    }
    int askSize = (int)((size_t)stepSizeWork * ((size_t)pool->itemSize + sizeof(DympItemType)) + sizeof(DympMemory));
    mem = (DympMemory *)SpungeAlloc(1, (FILLP_SIZE_T)((FILLP_UINT)askSize), (FILLP_INT)SPUNGE_ALLOC_TYPE_MALLOC);
    if (mem == FILLP_NULL_PTR) {
        FILLP_LOGERR("Fail to alloc memory");
        return -1;
    }

    dataPointer = (char *)((char *)mem + sizeof(DympMemory));

    HLIST_INIT_NODE(&mem->hnode);
    HlistAddTail(&pool->mlist, &mem->hnode);
    int itemCount = 0;
    for (i = 0; i < stepSizeWork; i++) {
        FILLP_INT err = 0;
        DympItemType *item = (DympItemType *)(dataPointer);
        int offset = (int)(pool->itemSize + ((int)sizeof(DympItemType)));
        dataPointer += offset;

        item->mp = pool->mp;

        if (pool->itemOperaCb.createCb != FILLP_NULL_PTR) {
            err = pool->itemOperaCb.createCb(item);
        }

        if (err != FILLP_OK) {
            continue;
        }

        (void)FillpQueuePush(item->mp, (void *)&item, FILLP_FALSE, 1);
        itemCount++;
    }

    pool->currentSize += itemCount;
    if (itemCount != 0) {
        mem->itemCnt = itemCount;
        FILLP_LOGINF("stepSize:%d, Current pool size:%d", itemCount, pool->currentSize);
    } else {
        HlistDelete(&pool->mlist, &mem->hnode);
        SpungeFree(mem, SPUNGE_ALLOC_TYPE_MALLOC);
    }

    return itemCount;
}

int DympAskMoreMemory(DympoolType *pool, int stepSize, int throttleGrow)
{
    int stepSizeWork = stepSize;
    int maxSizeRemain;
    int tempMax;

    FILLP_UNUSED_PARA(throttleGrow);

    if ((pool == FILLP_NULL_PTR) || (stepSize <= 0)) {
        FILLP_LOGERR("Wrong to ask memory, stepSize:%d", stepSize);
        return -1;
    }

    tempMax = pool->maxSize;

    maxSizeRemain = tempMax - pool->currentSize;
    if (maxSizeRemain <= 0) {
        FILLP_LOGDBG("maxSizeRemain=%d is invalid, unable to expand memory", maxSizeRemain);
        return 0;
    }

    if (stepSizeWork > maxSizeRemain) {
        stepSizeWork = maxSizeRemain;
    }
    return DympExpandMemory(pool, stepSizeWork);
}


int DympAlloc(DympoolType *pool, void **data, int throttleGrow)
{
    DympItemType *tmp = FILLP_NULL_PTR;
    FILLP_INT ret = 0;
    int i;

    if ((pool == FILLP_NULL_PTR) || (data == FILLP_NULL_PTR)) {
        FILLP_LOGERR("MemPool pointer is invalid \n");
        return ERR_NULLPTR;
    }

    for (i = 0; i < pool->maxSize; i++) {
        ret = FillpQueuePop(pool->mp, (void *)&tmp, 1);
        if ((ret <= 0) && (pool->autoExpand == FILLP_TRUE) && (pool->currentSize < pool->maxSize) &&
            (DympAskMoreMemory(pool, pool->initSize, throttleGrow) > 0)) {
            continue;
        }

        break;
    }

    if (ret <= 0) {
        return ERR_NOBUFS;
    }

    *data = (char *)tmp + sizeof(DympItemType);
    return ERR_OK;
}

void DympFree(void *data)
{
    DympItemType *item = FILLP_NULL_PTR;
    if (data == FILLP_NULL_PTR) {
        return;
    }

    item = (DympItemType *)DYMP_GET_ITEM_FROM_DATA(data);
    if (FillpQueuePush(item->mp, (void *)&item, FILLP_FALSE, 1) != ERR_OK) {
        FILLP_LOGWAR("Mem Pool free enqueue Error \n");
        return;
    }

    return;
}

#ifdef __cplusplus
}
#endif
