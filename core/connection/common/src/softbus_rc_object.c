/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "softbus_rc_object.h"

#include "comm_log.h"

static int32_t Lock(SoftBusRcObject *object)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(object != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "object is null");
    return SoftBusMutexLock(&object->mutex);
}

static void Unlock(SoftBusRcObject *object)
{
    COMM_CHECK_AND_RETURN_LOGE(object != NULL, COMM_UTILS, "object is null");
    (void)SoftBusMutexUnlock(&object->mutex);
}

int32_t Reference(SoftBusRcObject *object)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(object != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "object is null");

    int32_t ret = Lock(object);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_UTILS,
        "%{public}s lock failed: id=%{public}d, error=%{public}d", object->name, object->id, ret);
    object->objectRc += 1;
    Unlock(object);
    return SOFTBUS_OK;
}

void Deference(SoftBusRcObject **ptr)
{
    COMM_CHECK_AND_RETURN_LOGE(ptr != NULL, COMM_UTILS, "ptr is null");
    SoftBusRcObject *object = *ptr;
    COMM_CHECK_AND_RETURN_LOGE(object != NULL, COMM_UTILS, "object is null");

    int32_t ret = Lock(object);
    COMM_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, COMM_UTILS, "%{public}s lock failed: id=%{public}d, error=%{public}d",
        object->name, object->id, ret);
    object->objectRc -= 1;
    int32_t remain = object->objectRc;
    Unlock(object);

    if (remain <= 0) {
        COMM_LOGW(COMM_UTILS, "%{public}s is not referenced by anyone, id=%{public}d, object rc=%{public}d",
            object->name, object->id, object->objectRc);
        object->freehook(object);
    }
    *ptr = NULL;
}

int32_t SoftBusRcObjectConstruct(const char *name, SoftBusRcObject *object, SoftBusRcFreeHook hook)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(name != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "name is null");
    COMM_CHECK_AND_RETURN_RET_LOGE(object != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "object is null");
    COMM_CHECK_AND_RETURN_RET_LOGE(hook != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "free hook is null");

    ListInit(&object->node);
    object->id = 0;
    object->mutex = (SoftBusMutex)0;
    SoftBusMutexAttr attr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t ret = SoftBusMutexInit(&object->mutex, &attr);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, COMM_UTILS, "%{public}s init lock failed: error=%{public}d", name, ret);
    // assigned 1, as object is referenced by local construct progress
    object->objectRc = 1;
    object->freehook = hook;
    object->name = name;

    object->Lock = Lock;
    object->Unlock = Unlock;
    object->Reference = Reference;
    object->Dereference = Deference;

    return SOFTBUS_OK;
}

void SoftBusRcObjectDestruct(SoftBusRcObject *object)
{
    COMM_CHECK_AND_RETURN_LOGE(object != NULL, COMM_UTILS, "object is null");

    ListDelete(&object->node);
    object->id = 0;
    (void)SoftBusMutexDestroy(&object->mutex);
    object->objectRc = 0;
    object->freehook = NULL;
    object->name = NULL;

    object->Lock = NULL;
    object->Unlock = NULL;
    object->Reference = NULL;
    object->Dereference = NULL;
}