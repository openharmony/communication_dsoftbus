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

#include "tlv_protocol.h"
#include "securec.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "utils/wifi_direct_utils.h"

#define DEFAULT_CAPACITY 128
#define CAPACITY_MAX (1024 * 64)

/* private method forward declare */
static bool Grow(struct WifiDirectTlvProtocol *self, size_t writeSize);
static bool WriteTlvData(struct WifiDirectTlvProtocol *self, struct InfoContainerKeyProperty *keyProperty,
                         size_t length, uint8_t *value);
static bool SetDataSource(struct WifiDirectProtocol *base, const uint8_t *data, size_t size);

/* public interface */
static enum WifiDirectProtocolType GetType(void)
{
    return WIFI_DIRECT_PROTOCOL_TLV;
}

static bool Pack(struct WifiDirectProtocol *base, struct InfoContainer *container, uint8_t **outBuffer, size_t *size)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOGW(container, false, CONN_WIFI_DIRECT, "container is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(container->marshalling(container, base), false, CONN_WIFI_DIRECT,
        "marshalling failed");
    *outBuffer = self->data;
    *size = self->writePos;
    return true;
}

static bool SetDataSource(struct WifiDirectProtocol *base, const uint8_t *data, size_t size)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOGW(data, false, CONN_WIFI_DIRECT, "data is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(size > 0 && size <= CAPACITY_MAX, false, CONN_WIFI_DIRECT,
        "size invalid. size=%{public}zu", size);

    if (self->data != NULL) {
        SoftBusFree(self->data);
    }
    self->data = (uint8_t *)SoftBusMalloc(size);
    CONN_CHECK_AND_RETURN_RET_LOGE(self->data, false, CONN_WIFI_DIRECT, "alloc failed");

    if (memcpy_s(self->data, size, data, size) != EOK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "self->data memcpy fail");
        return false;
    }
    self->size = size;
    self->readPos = 0;

    return true;
}

static bool Unpack(struct WifiDirectProtocol *base, struct InfoContainer *container)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOGW(self->data, false, CONN_WIFI_DIRECT, "not set data source");
    CONN_CHECK_AND_RETURN_RET_LOGW(container, false, CONN_WIFI_DIRECT, "container is NULL");
    return container->unmarshalling(container, base);
}

static bool WriteData(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty,
                      uint8_t *data, size_t size)
{
    return WriteTlvData((struct WifiDirectTlvProtocol *)base, keyProperty, size, data);
}

static bool ReadData(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty,
                     uint8_t **data, size_t *size)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    if (self->format.tagSize == 0 || self->format.lengthSize == 0) {
        CONN_LOGW(CONN_WIFI_DIRECT, "no setting of tlv format");
        return false;
    }
    if (self->size - self->readPos < self->format.tagSize + self->format.lengthSize) {
        CONN_LOGE(CONN_WIFI_DIRECT, "size sub readPos invalid");
        return false;
    }

    keyProperty->content = NULL;
    keyProperty->tag = GetWifiDirectUtils()->bytesToInt(self->data + self->readPos, self->format.tagSize);
    self->readPos += self->format.tagSize;
    *size = GetWifiDirectUtils()->bytesToInt(self->data + self->readPos, self->format.lengthSize);
    self->readPos += self->format.lengthSize;
    if (self->readPos >= self->size || self->size - self->readPos < *size) {
        CONN_LOGW(CONN_WIFI_DIRECT, "readPos is invalid. readPos=%{public}zu", self->readPos);
        return false;
    }
    *data = self->data + self->readPos;
    self->readPos += *size;
    return true;
}

static void SetFormat(struct WifiDirectProtocol *base, struct ProtocolFormat *format)
{
    base->format = *format;
}

static void Destructor(struct WifiDirectProtocol *base)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    SoftBusFree(self->data);
}

/* private method implement */
static bool Grow(struct WifiDirectTlvProtocol *self, size_t writeSize)
{
    size_t capacity = self->capacity;
    while (capacity < self->capacity + writeSize) {
        capacity += capacity;
    }

    uint8_t *data = SoftBusCalloc(capacity);
    CONN_CHECK_AND_RETURN_RET_LOGE(data, false, CONN_WIFI_DIRECT, "alloc failed");
    int32_t ret = memcpy_s(data, capacity, self->data, self->writePos);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, false, CONN_WIFI_DIRECT, "copy failed");

    SoftBusFree(self->data);
    self->data = data;
    self->capacity = capacity;

    return true;
}

static bool WriteTlvData(struct WifiDirectTlvProtocol *self, struct InfoContainerKeyProperty *keyProperty,
                         size_t length, uint8_t *value)
{
    if (self->format.tagSize == 0 || self->format.lengthSize == 0) {
        CONN_LOGW(CONN_WIFI_DIRECT, "not set tlv format");
        return false;
    }

    size_t writeSize = self->format.tagSize + self->format.lengthSize + length;
    if (self->capacity - self->writePos < writeSize) {
        if (!Grow(self, writeSize)) {
            return false;
        }
    }

    GetWifiDirectUtils()->intToBytes(keyProperty->tag, self->format.tagSize, self->data + self->writePos,
                                     self->capacity - self->writePos);
    self->writePos += self->format.tagSize;
    GetWifiDirectUtils()->intToBytes(length, self->format.lengthSize, self->data + self->writePos,
                                     self->capacity - self->writePos);
    self->writePos += self->format.lengthSize;
    int32_t ret = memcpy_s(self->data + self->writePos, self->capacity - self->writePos, value, length);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == EOK, false, CONN_WIFI_DIRECT, "copy value failed");
    self->writePos += length;

    return true;
}

bool WifiDirectTlvProtocolConstructor(struct WifiDirectTlvProtocol *self)
{
    self->format.tagSize = 0;
    self->format.lengthSize = 0;
    self->capacity = DEFAULT_CAPACITY;
    self->data = SoftBusCalloc(self->capacity);
    CONN_CHECK_AND_RETURN_RET_LOGE(self->data, false, CONN_WIFI_DIRECT, "alloc failed");

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