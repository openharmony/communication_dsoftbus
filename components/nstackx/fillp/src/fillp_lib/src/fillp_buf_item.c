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

#include "lf_ring.h"
#include "queue.h"
#include "log.h"
#include "fillp.h"
#include "dympool.h"
#include "fillp_buf_item.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline FILLP_INT FillpCreateDympCreateCb(DympItemType *item)
{
    struct FillpPcbItem *pcbItem = (struct FillpPcbItem *)DYMP_ITEM_DATA(item);
    pcbItem->buf.p = (char *)pcbItem + sizeof(struct FillpPcbItem);
    pcbItem->fpcb = FILLP_NULL_PTR;
    return FILLP_OK;
}

void *FillpCreateBufItemPool(int poolSize, int initSize, int pktSize)
{
    int initialSize = UTILS_MIN(poolSize, initSize);
    DympoolItemOperaCbSt itemOperaCb = {FillpCreateDympCreateCb, FILLP_NULL_PTR};
    return (void *)DympCreatePool(initialSize, poolSize,
                                  ((int)sizeof(struct FillpPcbItem) + (int)(pktSize + FILLP_HLEN)),
                                  FILLP_FALSE, &itemOperaCb);
}

void FillbufItemPoolSetConflictSafe(void *pool, FILLP_BOOL consSafe, FILLP_BOOL prodSafe)
{
    DympSetConsSafe((DympoolType *)pool, consSafe);
    DympSetProdSafe((DympoolType *)pool, prodSafe);
}

int FillpMallocBufItem(void *pool, void **data, int throttleGrow)
{
    return DympAlloc((DympoolType *)pool, data, throttleGrow);
}

int FillpAskMoreBufItem(void *pool, int stepSize, int throttleGrow)
{
    return DympAskMoreMemory((DympoolType *)pool, stepSize, throttleGrow);
}

void FillpFreeBufItem(void *data)
{
    struct FillpPcb *fpcb = FILLP_NULL_PTR;
    if (data == FILLP_NULL_PTR) {
        return;
    }
    fpcb = (struct FillpPcb *)(((struct FillpPcbItem *)data)->fpcb);
    if ((fpcb != FILLP_NULL_PTR) && (fpcb->send.preItem == data)) {
        fpcb->send.preItem = FILLP_NULL_PTR;
    }
    FillpFrameFreeItem((struct FillpPcbItem *)data);
    DympFree(data);
}


void FillpDestroyBufItemPool(void *pool)
{
    if (pool == FILLP_NULL_PTR) {
        return;
    }

    DympDestroyPool((DympoolType *)pool);
}

#ifdef __cplusplus
}
#endif
