/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "softbus_rc_collection.h"

#include "comm_log.h"
#include "softbus_error_code.h"

int32_t SoftBusRcCollectionConstruct(const char *name, SoftBusRcCollection *collection, SoftBusRcIdGenerator generator)
{
    (void)name;
    (void)collection;
    (void)generator;
    COMM_LOGE(COMM_UTILS, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void SoftBusRcCollectionDestruct(SoftBusRcCollection *collection)
{
    (void)collection;
    COMM_LOGE(COMM_UTILS, "not support");
}

int32_t SoftBusRcSave(SoftBusRcCollection *collection, SoftBusRcObject *object)
{
    (void)collection;
    (void)object;
    COMM_LOGE(COMM_UTILS, "not support");
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

SoftBusRcObject *SoftBusRcGetCommon(SoftBusRcCollection *collection, SoftBusRcObjectMatcher matcher, const void *arg)
{
    (void)collection;
    (void)matcher;
    (void)arg;
    COMM_LOGE(COMM_UTILS, "not support");
    return NULL;
}

SoftBusRcObject *SoftBusRcGetById(SoftBusRcCollection *collection, uint32_t id)
{
    (void)collection;
    (void)id;
    COMM_LOGE(COMM_UTILS, "not support");
    return NULL;
}

void SoftBusRcRemove(SoftBusRcCollection *collection, SoftBusRcObject *object)
{
    (void)collection;
    (void)object;
    COMM_LOGE(COMM_UTILS, "not support");
}
