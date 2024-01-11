/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "json_protocol.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "cJSON.h"
#include "string.h"
#include "softbus_json_utils.h"

#define DEFAULT_CAPACITY 1000
#define CAPACITY_MAX (1024 * 64)

/* private method forward declare */
static bool SetDataSource(struct WifiDirectProtocol *base, const uint8_t *data, size_t size);

/* public interface */
static enum WifiDirectProtocolType GetType(void)
{
    return WIFI_DIRECT_PROTOCOL_JSON;
}

static bool Pack(struct WifiDirectProtocol *base, struct InfoContainer *container, uint8_t **outBuffer, size_t *size)
{
    struct WifiDirectJsonProtocol *self = (struct WifiDirectJsonProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOGW(container, false, CONN_WIFI_DIRECT, "container is null");

    if (!container->marshalling(container, base)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "marshalling failed");
        return false;
    }

    char *msgStr = cJSON_PrintUnformatted(self->cJsonOfMsg);
    size_t writeSize = strlen(msgStr) + 1;

    SoftBusFree(self->data);
    self->data = SoftBusCalloc(writeSize);
    CONN_CHECK_AND_RETURN_RET_LOGE(self->data, false, CONN_WIFI_DIRECT, "alloc failed");
    int32_t ret = memcpy_s(self->data, writeSize, msgStr, writeSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, false, CONN_WIFI_DIRECT, "copy failed");
    self->writePos = writeSize;
    cJSON_free(msgStr);
    *outBuffer = self->data;
    *size = self->writePos;
    return true;
}

static bool SetDataSource(struct WifiDirectProtocol *base, const uint8_t *data, size_t size)
{
    struct WifiDirectJsonProtocol *self = (struct WifiDirectJsonProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOGW(data, false, CONN_WIFI_DIRECT, "data is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(size > 0 && size <= CAPACITY_MAX, false, CONN_WIFI_DIRECT,
        "size is too large. size=%{public}zu", size);
    CONN_LOGI(CONN_WIFI_DIRECT, "size=%{public}zu", size);
    cJSON_Delete(self->cJsonOfMsg);
    self->cJsonOfMsg = cJSON_ParseWithLength((char *)data, size);
    CONN_CHECK_AND_RETURN_RET_LOGW(self->cJsonOfMsg, false, CONN_WIFI_DIRECT, "cJsonOfMsg is null");
    self->readPos = self->cJsonOfMsg->child;
    CONN_CHECK_AND_RETURN_RET_LOGW(self->cJsonOfMsg->child, false, CONN_WIFI_DIRECT, "cJsonOfMsg->child is null");
    return true;
}

static bool Unpack(struct WifiDirectProtocol *base, struct InfoContainer *container)
{
    struct WifiDirectJsonProtocol *self = (struct WifiDirectJsonProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOGW(self->cJsonOfMsg, false, CONN_WIFI_DIRECT, "not set data source");
    CONN_CHECK_AND_RETURN_RET_LOGW(container, false, CONN_WIFI_DIRECT, "container is NULL");
    return container->unmarshalling(container, base);
}

static bool WriteData(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty,
                      uint8_t *data, size_t size)
{
    struct WifiDirectJsonProtocol* self = (struct WifiDirectJsonProtocol*)base;
    switch (keyProperty->type) {
        case STRING: {
            if (!AddStringToJsonObject(self->cJsonOfMsg, keyProperty->content, (char *)data)) {
                CONN_LOGW(CONN_WIFI_DIRECT, "JsonProtocol pack: msg failed");
                return false;
            }
            break;
        }
        case INT: {
            if (!AddNumberToJsonObject(self->cJsonOfMsg, keyProperty->content, *(int *)data)) {
                CONN_LOGW(CONN_WIFI_DIRECT, "JsonProtocol pack: msg failed");
                return false;
            }
            break;
        }
        case BOOLEAN: {
            if (!AddBoolToJsonObject(self->cJsonOfMsg, keyProperty->content, *(bool*)data)) {
                CONN_LOGW(CONN_WIFI_DIRECT, "JsonProtocol pack: msg failed");
                return false;
            }
            break;
        }
        default: {
            CONN_LOGW(CONN_WIFI_DIRECT, "JsonProtocol pack: invalid value type=%{public}d", keyProperty->type);
            return false;
        }
    }
    return true;
}

static bool ReadData(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty,
                     uint8_t **data, size_t *size)
{
    struct WifiDirectJsonProtocol *self = (struct WifiDirectJsonProtocol *)base;

    cJSON *json = self->readPos;
    CONN_CHECK_AND_RETURN_RET_LOGW(json, false, CONN_WIFI_DIRECT, "self->readPos is null");
    keyProperty->content = json->string;
    keyProperty->tag = -1;

    switch (self->readPos->type) {
        case cJSON_String: {
            if (!GetJsonObjectStringItem(self->cJsonOfMsg, keyProperty->content,
                (char *)self->data, DEFAULT_CAPACITY)) {
                CONN_LOGE(CONN_WIFI_DIRECT, "JsonProtocol unpack: json to msg failed");
                return false;
            }
            *data = self->data;
            *size = strlen((char *)self->data);
            break;
        }
        case cJSON_Number: {
            if (!GetJsonObjectInt32Item(self->cJsonOfMsg, keyProperty->content, (int32_t *)self->data)) {
                CONN_LOGE(CONN_WIFI_DIRECT, "JsonProtocol unpack: json to msg failed");
                return false;
            }
            *data = self->data;
            *size = sizeof(int);
            break;
        }
        case cJSON_True:
        case cJSON_False : {
            if (!GetJsonObjectBoolItem(self->cJsonOfMsg, keyProperty->content, (bool *)self->data)) {
                CONN_LOGE(CONN_WIFI_DIRECT, "JsonProtocol unpack: json to msg failed");
                return false;
            }
            *data = self->data;
            *size = sizeof(bool);
            break;
        }
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "invalid cJson type=%{public}d", self->readPos->type);
            return false;
    }
    self->readPos = self->readPos->next;
    return true;
}

static void SetFormat(struct WifiDirectProtocol *self, struct ProtocolFormat *format)
{
    self->format = *format;
}

static void Destructor(struct WifiDirectProtocol *base)
{
    struct WifiDirectJsonProtocol *self = (struct WifiDirectJsonProtocol *)base;
    SoftBusFree(self->data);
    cJSON_Delete(self->cJsonOfMsg);
}

bool WifiDirectJsonProtocolConstructor(struct WifiDirectJsonProtocol *self)
{
    self->capacity = DEFAULT_CAPACITY;
    self->data = SoftBusCalloc(self->capacity);
    CONN_CHECK_AND_RETURN_RET_LOGE(self->data, false, CONN_WIFI_DIRECT, "alloc failed");
    self->cJsonOfMsg = cJSON_CreateObject();
    CONN_CHECK_AND_RETURN_RET_LOGW(self->cJsonOfMsg, false, CONN_WIFI_DIRECT, "cJSON_CreateObject failed");
    self->getType = GetType;
    self->pack = Pack;
    self->setDataSource = SetDataSource;
    self->unpack = Unpack;
    self->writeData = WriteData;
    self->readData = ReadData;
    self->destructor = Destructor;
    self->setFormat = SetFormat;

    return true;
}