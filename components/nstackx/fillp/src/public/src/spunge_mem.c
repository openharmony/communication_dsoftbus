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

#include "spunge_mem.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif
void *SpungeAlloc(size_t blockNum, size_t blockSize, FILLP_INT allocType)
{
    if (blockSize == 0) {
        return FILLP_NULL_PTR;
    }

    switch (allocType) {
        case SPUNGE_ALLOC_TYPE_MALLOC: {
            FILLP_UINT32 totalSize = (FILLP_UINT32)(blockSize * blockNum);
            if ((totalSize == 0) || (blockNum != totalSize / blockSize)) {
                return FILLP_NULL_PTR;
            }

            return FILLP_MALLOC((FILLP_UINT32)totalSize);
        }
        case SPUNGE_ALLOC_TYPE_CALLOC: {
            if ((blockNum == 0) || (blockNum > FILLP_INVALID_UINT32) || (blockSize > FILLP_INVALID_UINT32)) {
                return FILLP_NULL_PTR;
            }
            return FILLP_CALLOC((FILLP_UINT32)blockNum, (FILLP_UINT32)blockSize);
        }
        default:
            return FILLP_NULL_PTR;
    }
}

void SpungeFree(void *p, FILLP_INT allocType)
{
    if (p == FILLP_NULL_PTR) {
        return;
    }

    switch (allocType) {
        case SPUNGE_ALLOC_TYPE_MALLOC:
        /* fall-through: mem alloc by malloc or calloc, can be freed by free func */
        case SPUNGE_ALLOC_TYPE_CALLOC:
            FILLP_FREE(p);

            FILLP_UNUSED_PARA(p);
            return;
        default:
            return;
    }
}

#ifdef __cplusplus
}
#endif
