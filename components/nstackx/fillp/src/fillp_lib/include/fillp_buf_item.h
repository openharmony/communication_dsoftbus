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

#ifndef FILLP_BUFITEM_H
#define FILLP_BUFITEM_H

#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FillpItemPoolStruct {
    void *pool;
} FillpItemPoolSt;

int FillpMallocBufItem(void *pool, void **data, int throttleGrow);
void FillpDestroyBufItemPool(void *pool);
void FillpFreeBufItem(void *data);
void *FillpCreateBufItemPool(int poolSize, int initSize, int pktSize);
int FillpAskMoreBufItem(void *pool, int stepSize, int throttleGrow);
void FillbufItemPoolSetConflictSafe(void *pool, FILLP_BOOL consSafe, FILLP_BOOL prodSafe);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_BUFITEM_H */