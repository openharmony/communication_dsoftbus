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
#include "softbus_log_old.h"
#include "softbus_adapter_mem.h"
#include "utils/wifi_direct_utils.h"

#define LOG_LABEL "[WD] Tlv: "

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
    CONN_CHECK_AND_RETURN_RET_LOG(container, false, LOG_LABEL "container is null");
    CONN_CHECK_AND_RETURN_RET_LOG(container->marshalling(container, base), false, LOG_LABEL "marshalling failed");
    *outBuffer = self->data;
    *size = self->writePos;
    return true;
}

static bool SetDataSource(struct WifiDirectProtocol *base, const uint8_t *data, size_t size)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOG(data, false, LOG_LABEL "data is null");
    CONN_CHECK_AND_RETURN_RET_LOG(size > 0 && size <= CAPACITY_MAX, false, "size=%u invalid", size);
    self->data = (uint8_t *)SoftBusMalloc(size);
    CONN_CHECK_AND_RETURN_RET_LOG(self->data, false, LOG_LABEL "alloc failed");

    if (memcpy_s(self->data, size, data, size) != EOK) {
        CLOGE("self->data memcpy fail");
        return false;
    }
    self->size = size;
    self->readPos = 0;

    return true;
}

static bool Unpack(struct WifiDirectProtocol *base, struct InfoContainer *container)
{
    struct WifiDirectTlvProtocol *self = (struct WifiDirectTlvProtocol *)base;
    CONN_CHECK_AND_RETURN_RET_LOG(self->data, false, LOG_LABEL "not set data source");
    CONN_CHECK_AND_RETURN_RET_LOG(container, false, LOG_LABEL "container is NULL");
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
        CLOGE(LOG_LABEL "no setting of tlv format");
        return false;
    }
    if (self->size - self->readPos < self->format.tagSize + self->format.lengthSize) {
        return false;
    }

    keyProperty->content = NULL;
    keyProperty->tag = GetWifiDirectUtils()->bytesToInt(self->data + self->readPos, self->format.tagSize);
    self->readPos += self->format.tagSize;
    *size = GetWifiDirectUtils()->bytesToInt(self->data + self->readPos, self->format.lengthSize);
    self->readPos += self->format.lengthSize;
    if (self->readPos >= self->size || self->size - self->readPos < *size) {
        CLOGE(LOG_LABEL "readPos=%zu is invalid", self->readPos);
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
    CONN_CHECK_AND_RETURN_RET_LOG(data, false, LOG_LABEL "alloc failed");
    int32_t ret = memcpy_s(data, capacity, self->data, self->writePos);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, false, LOG_LABEL "copy failed");

    SoftBusFree(self->data);
    self->data = data;
    self->capacity = capacity;

    return true;
}

static bool WriteTlvData(struct WifiDirectTlvProtocol *self, struct InfoContainerKeyProperty *keyProperty,
                         size_t length, uint8_t *value)
{
    if (self->format.tagSize == 0 || self->format.lengthSize == 0) {
        CLOGE("not set tlv format");
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
    CONN_CHECK_AND_RETURN_RET_LOG(ret == EOK, false, LOG_LABEL "copy value failed");
    self->writePos += length;

    return true;
}


bool WifiDirectTlvProtocolConstructor(struct WifiDirectTlvProtocol *self)
{
    self->format.tagSize = 0;
    self->format.lengthSize = 0;
    self->capacity = DEFAULT_CAPACITY;
    self->data = SoftBusCalloc(self->capacity);
    CONN_CHECK_AND_RETURN_RET_LOG(self->data, false, LOG_LABEL "alloc failed");

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