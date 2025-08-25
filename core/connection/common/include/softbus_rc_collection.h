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
#ifndef SOFTBUS_RC_COLLECTION_H
#define SOFTBUS_RC_COLLECTION_H

#include <stdint.h>

#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_rc_object.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*SoftBusRcIdGenerator)(const SoftBusRcObject *object, uint16_t index);
typedef bool (*SoftBusRcObjectMatcher)(const SoftBusRcObject *object, const void *arg);

typedef struct {
    SoftBusList *objects;
    SoftBusRcIdGenerator idGenerator;
    const char *name;
} SoftBusRcCollection;

int32_t SoftBusRcCollectionConstruct(const char *name, SoftBusRcCollection *collection, SoftBusRcIdGenerator generator);
void SoftBusRcCollectionDestruct(SoftBusRcCollection *collection);

int32_t SoftBusRcSave(SoftBusRcCollection *collection, SoftBusRcObject *object);
SoftBusRcObject *SoftBusRcGetCommon(SoftBusRcCollection *collection, SoftBusRcObjectMatcher matcher, const void *arg);
SoftBusRcObject *SoftBusRcGetById(SoftBusRcCollection *collection, uint32_t id);
void SoftBusRcRemove(SoftBusRcCollection *collection, SoftBusRcObject *object);

#ifdef __cplusplus
}
#endif

#endif