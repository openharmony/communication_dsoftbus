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
#include "softbus_rc_collection.h"

#include "softbus_utils.h"

#include "comm_log.h"

static uint32_t AllocateUniqueIdUnsafe(SoftBusRcCollection *collection, SoftBusRcObject *object, uint16_t maxRetry)
{
    if (maxRetry == 0) {
        return 0;
    }

    static uint16_t nextId = 1;
    if (nextId == 0) {
        nextId = 1;
    }
    uint32_t id = collection->idGenerator(object, nextId++);
    SoftBusList *objects = collection->objects;
    SoftBusRcObject *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &objects->list, SoftBusRcObject, node) {
        if (id == it->id) {
            COMM_LOGW(
                COMM_UTILS, "%{public}s, object id=%{public}u is already used, retry next one", collection->name, id);
            return AllocateUniqueIdUnsafe(collection, object, maxRetry - 1);
        }
    }
    return id;
}

int32_t SoftBusRcSave(SoftBusRcCollection *collection, SoftBusRcObject *object)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(collection != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "collection is null");
    COMM_CHECK_AND_RETURN_RET_LOGE(object != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "object is null");

    SoftBusList *objects = collection->objects;
    int32_t code = SoftBusMutexLock(&objects->lock);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        code == SOFTBUS_OK, code, COMM_UTILS, "%{public}s, lock failed: error=%{public}d", collection->name, code);

    if (collection->idGenerator != NULL) {
        uint32_t id = AllocateUniqueIdUnsafe(collection, object, UINT16_MAX);
        if (id == 0) {
            COMM_LOGW(COMM_UTILS, "%{public}s, id exhausted, object leak may occurred", collection->name);
            SoftBusMutexUnlock(&objects->lock);
            return SOFTBUS_RC_ID_EXHAUSTED_ERR;
        }
        object->id = id;
    }
    code = object->Reference(object);
    if (code != SOFTBUS_OK) {
        COMM_LOGW(COMM_UTILS, "%{public}s, reference object failed: error=%{public}d", collection->name, code);
        SoftBusMutexUnlock(&objects->lock);
        return code;
    }

    ListTailInsert(&objects->list, &object->node);
    SoftBusMutexUnlock(&objects->lock);
    return SOFTBUS_OK;
}

SoftBusRcObject *SoftBusRcGetCommon(SoftBusRcCollection *collection, SoftBusRcObjectMatcher matcher, const void *arg)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(collection != NULL, NULL, COMM_UTILS, "collection is null");
    COMM_CHECK_AND_RETURN_RET_LOGE(matcher != NULL, NULL, COMM_UTILS, "matcher is null");
    // arg is nullable

    SoftBusList *objects = collection->objects;
    int32_t code = SoftBusMutexLock(&objects->lock);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        code == SOFTBUS_OK, NULL, COMM_UTILS, "%{public}s, lock failed: error=%{public}d", collection->name, code);

    SoftBusRcObject *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &objects->list, SoftBusRcObject, node) {
        if (!matcher(it, arg)) {
            continue;
        }
        code = it->Reference(it);
        SoftBusMutexUnlock(&objects->lock);
        if (code != SOFTBUS_OK) {
            COMM_LOGW(COMM_UTILS, "%{public}s, reference object failed: object id=%{public}d, error=%{public}d",
                collection->name, it->id, code);
            return NULL;
        }
        return it;
    }
    SoftBusMutexUnlock(&objects->lock);
    COMM_LOGI(COMM_UTILS, "%{public}s, object not found", collection->name);
    return NULL;
}

static bool IdMatcher(const SoftBusRcObject *object, const void *arg)
{
    uint32_t id = *(uint32_t *)arg;
    return object->id == id;
}

SoftBusRcObject *SoftBusRcGetById(SoftBusRcCollection *collection, uint32_t id)
{
    return SoftBusRcGetCommon(collection, IdMatcher, &id);
}

static bool PointerMatcher(const SoftBusRcObject *object, const void *arg)
{
    return (const void *)object == arg;
}

void SoftBusRcRemove(SoftBusRcCollection *collection, SoftBusRcObject *object)
{
    COMM_CHECK_AND_RETURN_LOGE(collection != NULL, COMM_UTILS, "collection is null");
    COMM_CHECK_AND_RETURN_LOGE(object != NULL, COMM_UTILS, "object is null");

    SoftBusList *objects = collection->objects;
    int32_t code = SoftBusMutexLock(&objects->lock);
    COMM_CHECK_AND_RETURN_LOGE(
        code == SOFTBUS_OK, COMM_UTILS, "%{public}s, lock failed: error=%{public}d", collection->name, code);
    SoftBusRcObject *exist = SoftBusRcGetCommon(collection, PointerMatcher, object);
    if (exist == NULL) {
        COMM_LOGW(COMM_UTILS, "%{public}s, object not found: object id=%{public}d", collection->name, object->id);
        SoftBusMutexUnlock(&objects->lock);
        return;
    }
    ListDelete(&exist->node);

    // deference 2 times for 'SoftBusRcSave' and 'SoftBusRcGetCommon'
    SoftBusRcObject *copy = exist;
    copy->Dereference(&copy);
    exist->Dereference(&exist);

    SoftBusMutexUnlock(&objects->lock);
}

int32_t SoftBusRcCollectionConstruct(const char *name, SoftBusRcCollection *collection, SoftBusRcIdGenerator generator)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(name != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "name is null");
    COMM_CHECK_AND_RETURN_RET_LOGE(collection != NULL, SOFTBUS_INVALID_PARAM, COMM_UTILS, "collection is null");
    // generator is nullable

    SoftBusList *objects = CreateSoftBusList();
    COMM_CHECK_AND_RETURN_RET_LOGE(objects, SOFTBUS_MALLOC_ERR, COMM_UTILS, "create list failed");
    collection->objects = objects;
    collection->idGenerator = generator;
    collection->name = name;

    return SOFTBUS_OK;
}

void SoftBusRcCollectionDestruct(SoftBusRcCollection *collection)
{
    COMM_CHECK_AND_RETURN_LOGE(collection != NULL, COMM_UTILS, "collection is null");
    SoftBusList *objects = collection->objects;
    int32_t code = SoftBusMutexLock(&objects->lock);
    if (objects != NULL) {
        SoftBusRcObject *it = NULL;
        SoftBusRcObject *next = NULL;
        COMM_CHECK_AND_RETURN_LOGE(
            code == SOFTBUS_OK, COMM_UTILS, "%{public}s, lock failed: error=%{public}d", collection->name, code);
        LIST_FOR_EACH_ENTRY_SAFE(it, next, &objects->list, SoftBusRcObject, node) {
            COMM_LOGW(COMM_UTILS,
                "%{public}s, object still in collection, remove it before destructing: object id=%{public}d",
                collection->name, it->id);
            ListDelete(&it->node);
            it->Dereference(&it);
        }
        DestroySoftBusList(objects);
        collection->objects = NULL;
    }
    collection->idGenerator = NULL;
    collection->name = NULL;
    SoftBusMutexUnlock(&objects->lock);
}
