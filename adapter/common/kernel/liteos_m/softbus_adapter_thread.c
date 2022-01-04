/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_adapter_thread.h"

void *SoftBusMalloc(unsigned int size)
{
    if (size > MAX_MALLOC_SIZE) {
        return NULL;
    }

#if defined(OHOS_MEM)
    void *tmp = OhosMalloc(MEM_TYPE_SOFTBUS_LSRAM, size);
#else
    void *tmp = malloc(size);
#endif
    return tmp;
}
