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

#ifndef FILLP_LF_RING_H
#define FILLP_LF_RING_H
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LF_RING_NAMESIZE 32

#ifndef LF_RING_PAUSE_REP_COUNT
/** Yield after pause num of times, no yield if FTDP_RING_PAUSE_REP not defined. */
#define LF_RING_PAUSE_REP_COUNT 0
#endif
struct FillpLfRing {
    char name[LF_RING_NAMESIZE];

    /* Ring producer status */
    struct _prod {
        volatile FILLP_ULONG head;
        volatile FILLP_ULONG tail;
    } prod;

    struct _cons {
        volatile FILLP_ULONG head;
        volatile FILLP_ULONG tail;
    } cons;

    FILLP_ULONG size;
    FILLP_BOOL prodSafe;
    FILLP_BOOL consSafe;
    FILLP_UINT8 padd[6];
    /* Should be last element of the structure. DO NOT reorder or change */
    void *ringCache[1]; /* Data */
};

/*******************************************************************************
    Function    : FillpLfRingInit

    Description : This function will be invoked to init the lock-free queue.

    Input       : ring - lock-free queue to be initialized
                  name - name to be added to the lock-free queue
                  size - size of lock-free queue

    Output      : ring - initialized lock-free queue

    Return      : None
*******************************************************************************/
void FillpLfRingInit(struct FillpLfRing *ring, char *name, size_t size);

/*******************************************************************************
    Function    : FillpLfRingCalMemSize

    Description : This function will be invoked to calculate the memory size
                  required for lock-free queue, based on size.

    Input       : size - no of items of lock-free queue

    Output      : None

    Return      : Memory size of lock-free queue
*******************************************************************************/
size_t FillpLfRingCalMemSize(size_t size);

/* multi-consumers safe */
/*******************************************************************************
    Function    : FillpLfRingMpEnqueue

    Description : This function will be invoked to add data to lock-free queue.

    Input       : ring - lock-free queue to be initialized
                  dataTable - data table to be added to lock-free queue
                  count -

    Output      : None

    Return      : Memory size of lock-free queue
*******************************************************************************/
FillpErrorType FillpLfRingMpEnqueue(struct FillpLfRing *ring, void **dataTable, FILLP_UINT count);

/* multi-consumers safe */
/*******************************************************************************
    Function    : FillpLfRingMcDequeue

    Description : This function will be invoked to remove a data to lock-free
                  queue.

    Input       : ring - lock-free queue to be initialized
                  dataTable - data table to be added to lock-free queue
                  count -

    Output      : None

    Return      : ERR_OK if success, or Error codes on failures
*******************************************************************************/
FILLP_INT FillpLfRingMcDequeue(struct FillpLfRing *ring, void **dataTable, FILLP_UINT count);

FILLP_INT FillpRingEmpty(const struct FillpLfRing *r);


void FillpLfRingSetConsSafe(struct FillpLfRing *ring, FILLP_BOOL safe);

void FillpLfRingSetProdSafe(struct FillpLfRing *ring, FILLP_BOOL safe);

FILLP_INT FillpRingFreeEntries(const struct FillpLfRing *r);

FILLP_ULONG FillpRingValidOnes(struct FillpLfRing *r);

#ifdef __cplusplus
}
#endif
#endif /* FILLP_LF_RING_H */
