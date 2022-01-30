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

#ifndef SPUNGE_MEM_H
#define SPUNGE_MEM_H
#include "fillptypes.h"

#ifdef __cplusplus
extern "C" {
#endif

enum InnerSpungeAllocType {
    SPUNGE_ALLOC_TYPE_MALLOC,
    SPUNGE_ALLOC_TYPE_CALLOC,
};

void *SpungeAlloc(size_t blockNum, size_t blockSize, FILLP_INT allocType);
void SpungeFree(void *p, FILLP_INT allocType);

#ifdef __cplusplus
}
#endif

#endif /* SPUNGE_MEM_H */