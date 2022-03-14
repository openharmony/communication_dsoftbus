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

#ifndef FILLP_DYMPOOL_H
#define FILLP_DYMPOOL_H

#include "hlist.h"
#include "queue.h"
#include "spunge_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct InnerdympMemoryT {
    struct HlistNode hnode;
    int itemCnt;
} DympMemory;

static __inline DympMemory *DympMemoryNodeEntry(struct HlistNode *node)
{
    return (DympMemory *)((char *)(node) - (uintptr_t)(&(((DympMemory *)0)->hnode)));
}

typedef struct DympItemTypeStruct {
    FillpQueue *mp; /* Queue of memory, for free */
} DympItemType;

#define DYMP_ITEM_DATA(_item) ((void *)((char *)(_item) + sizeof(DympItemType)))
#define DYMP_GET_ITEM_FROM_DATA(_data) ((void *)((char *)(_data) - sizeof(DympItemType)))


typedef FILLP_INT (*DympoolCreateCb)(DympItemType *item);
typedef void (*DympoolDestroyCb)(DympItemType *item);
typedef struct DympoolItemOperaCb {
    DympoolCreateCb createCb;
    DympoolDestroyCb destroyCb;
} DympoolItemOperaCbSt;

typedef struct DympoolTypeStrunct {
    FillpQueue *mp;        /* Queue of memory alloc */
    int itemSize;          /* Size of every memory item size */
    int maxSize;           /* Max memory item size,and althrough it is the max size of queue */
    int currentSize;       /* Current size of memory alloced */
    int initSize;          /* Initial size when do create */
    FILLP_BOOL autoExpand; /* If auto expand if no item can be alloced */
    struct Hlist mlist;    /* List of alloced memory */
    DympoolItemOperaCbSt itemOperaCb; /* item creation and destroy callback structure */
} DympoolType;

DympoolType *DympCreatePool(int initSize, int maxSize, int itemSize, FILLP_BOOL autoExpand,
                            DympoolItemOperaCbSt *itemOperaCb);


void DympDestroyPool(DympoolType *pool);
void DympSetConsSafe(DympoolType *pool, FILLP_BOOL safe);
void DympSetProdSafe(DympoolType *pool, FILLP_BOOL safe);
int DympAskMoreMemory(DympoolType *pool, int stepSize, int throttleGrow);
int DympAlloc(DympoolType *pool, void **data, int throttleGrow);
void DympFree(void *data);
#define DYMP_GET_CUR_SIZE(_pool) (((DympoolType *)(_pool))->currentSize)


#ifdef __cplusplus
}
#endif


#endif /* FILLP_DYMPOOL_H */
