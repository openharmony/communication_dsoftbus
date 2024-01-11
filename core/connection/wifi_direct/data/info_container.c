/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use self file except in compliance with the License.
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
#include "info_container.h"

#include <string.h>
#include "securec.h"

#include "conn_log.h"
#include "softbus_errcode.h"
#include "softbus_adapter_mem.h"

#include "wifi_direct_types.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_anonymous.h"

#define INT_ARRAY_BUFFER_LEN 128
#define IPV4_INFO_ARRAY_BUFFER_LEN 256

static void DeepCopy(struct InfoContainer *self, struct InfoContainer *other)
{
    void *value = NULL;
    size_t keySize = other->getKeySize();

    for (size_t key = 0; key < keySize; key++) {
        value = other->entries[key].data;
        size_t size = other->entries[key].size;
        size_t count = other->entries[key].count;

        if (!value) {
            continue;
        }

        struct InfoContainerKeyProperty *keyProperty = other->getKeyProperty(other, key);
        switch (keyProperty->flag) {
            case CONTAINER_FLAG:
                self->putContainer(self, key, value, size);
                break;
            case CONTAINER_ARRAY_FLAG:
                self->putContainerArray(self, key, value, count, size / count);
                break;
            default:
                self->putRawData(self, key, value, size);
        }
    }
}

static void PutRawData(struct InfoContainer *self, size_t key, void *value, size_t size)
{
    void *oldData = self->entries[key].data;
    if (oldData) {
        SoftBusFree(oldData);
        self->entries[key].data = NULL;
    }

    if (!value || !size) {
        return;
    }

    void *data = SoftBusCalloc(size);
    if (data) {
        if (memcpy_s(data, size, value, size) != EOK) {
            SoftBusFree(data);
            return;
        }
        self->entries[key].data = data;
        self->entries[key].size = size;
        self->entries[key].remove = false;
    }
}

static void PutInt(struct InfoContainer *self, size_t key, int32_t value)
{
    self->putRawData(self, key, &value, sizeof(value));
}

static void PutBoolean(struct InfoContainer *self, size_t key, bool value)
{
    self->putRawData(self, key, &value, sizeof(value));
}

static void PutPointer(struct InfoContainer *self, size_t key, void **ptr)
{
    self->putRawData(self, key, ptr, sizeof(*ptr));
}

static void PutString(struct InfoContainer *self, size_t key, const char *value)
{
    self->putRawData(self, key, (void *)value, strlen(value) + 1);
}

static void PutIntArray(struct InfoContainer *self, size_t key, int32_t *array, size_t arraySize)
{
    self->putRawData(self, key, array, sizeof(int32_t) * arraySize);
}

static void PutContainer(struct InfoContainer *self, size_t key, struct InfoContainer *value, size_t size)
{
    struct InfoContainer *oldContainer = self->entries[key].data;
    if (oldContainer) {
        oldContainer->destructor(oldContainer);
    }

    if (!value) {
        return;
    }

    self->putRawData(self, key, value, size);
    struct InfoContainer *container = self->entries[key].data;

    if (container) {
        for (size_t i = 0; i < container->getKeySize(); i++) {
            container->entries[i].data = NULL;
        }

        container->deepCopy(container, value);
    }
}

static void PutContainerArray(struct InfoContainer *self, size_t key, struct InfoContainer *containerArray,
                              size_t containerArraySizes, size_t containerSize)
{
    char *data = self->entries[key].data;
    size_t count = self->entries[key].count;
    for (size_t i = 0; i < count; i++) {
        ((struct InfoContainer *)data)->destructor((struct InfoContainer *)data);
        data += containerSize;
    }

    self->putRawData(self, key, containerArray, containerSize * containerArraySizes);
    if (!containerArray) {
        self->entries[key].count = 0;
        self->entries[key].size = 0;
        return;
    }

    self->entries[key].count = containerArraySizes;

    data = self->entries[key].data;
    if (data == NULL) {
        return;
    }

    for (size_t i = 0; i < containerArraySizes; i++) {
        struct InfoContainer *container = (struct InfoContainer *)data;
        for (size_t j = 0; j < container->getKeySize(); j++) {
            container->entries[j].data = NULL;
        }
        data += containerSize;
    }

    char *target = self->entries[key].data;
    char *source = (char *)containerArray;

    for (size_t index = 0; index < containerArraySizes; index++) {
        struct InfoContainer *sourceContainer = (struct InfoContainer *)source;
        struct InfoContainer *targetContainer = (struct InfoContainer *)target;

        targetContainer->deepCopy(targetContainer, sourceContainer);

        source += containerSize;
        target += containerSize;
    }
}

static void *Get(struct InfoContainer *self, size_t key, size_t *size, size_t *count)
{
    if (size) {
        *size = self->entries[key].size;
    }
    if (count) {
        *count = self->entries[key].count;
    }
    return self->entries[key].data;
}

static void Remove(struct InfoContainer *self, size_t key)
{
    uint32_t flag = self->keyProperties[key].flag;
    if (flag == CONTAINER_FLAG) {
        self->putContainer(self, key, NULL, 0);
    } else if (flag == CONTAINER_ARRAY_FLAG) {
        self->putContainerArray(self, key, NULL, 0, 0);
    } else {
        self->putRawData(self, key, NULL, 0);
    }
    self->entries[key].remove = true;
}

static bool IsEmpty(struct InfoContainer *self)
{
    size_t keySize = self->getKeySize();
    for (size_t key = 0; key < keySize; key++) {
        if (self->entries[key].data) {
            return false;
        }
    }
    return true;
}

static int32_t GetInt(struct InfoContainer *self, size_t key, int32_t defaultValue)
{
    int32_t *value = self->get(self, key, NULL, NULL);
    if (value) {
        return *value;
    }
    return defaultValue;
}

static bool GetBoolean(struct InfoContainer *self, size_t key, bool defaultValue)
{
    bool *value = self->get(self, key, NULL, NULL);
    if (value) {
        return *value;
    }
    return defaultValue;
}

static void *GetPointer(struct InfoContainer *self, size_t key, void *defaultValue)
{
    void **value = self->get(self, key, NULL, NULL);
    if (value) {
        return *value;
    }
    return defaultValue;
}

static char *GetString(struct InfoContainer *self, size_t key, const char *defaultValue)
{
    char *value = self->get(self, key, NULL, NULL);
    if (value) {
        return value;
    }
    return (char *)defaultValue;
}

static int32_t *GetIntArray(struct InfoContainer *self, size_t key, size_t *arraySize, void *defaultValue)
{
    size_t size = 0;
    int32_t *value = self->get(self, key, &size, NULL);
    if (value) {
        *arraySize = size / sizeof(int32_t);
        return value;
    }
    return defaultValue;
}

static void *GetContainer(struct InfoContainer *self, size_t key)
{
    return self->get(self, key, NULL, NULL);
}

static void *GetContainerArray(struct InfoContainer *self, size_t key, size_t *containerArraySize)
{
    return self->get(self, key, NULL, containerArraySize);
}

static void *GetRawData(struct InfoContainer *self, size_t key, size_t *size, void *defaultValue)
{
    char *value = self->get(self, key, size, NULL);
    if (value) {
        return value;
    }
    return defaultValue;
}

static struct InfoContainerKeyProperty *GetKeyProperty(struct InfoContainer *self, uint32_t key)
{
    return self->keyProperties + key;
}

static void DumpStringContentWithFd(struct InfoContainerKeyProperty *keyProperty, struct InfoContainer *self,
                                    size_t key, int32_t fd)
{
    if (keyProperty->flag & MAC_ADDR_FLAG) {
        dprintf(fd, "%s=%s\n", keyProperty->content, WifiDirectAnonymizeMac(self->getString(self, key, "")));
    } else if (keyProperty->flag & IP_ADDR_FLAG) {
        dprintf(fd, "%s=%s\n", keyProperty->content, WifiDirectAnonymizeIp(self->getString(self, key, "")));
    } else if (keyProperty->flag & DEVICE_ID_FLAG) {
        dprintf(fd, "%s=%s\n", keyProperty->content, WifiDirectAnonymizeDeviceId(self->getString(self, key, "")));
    } else {
        dprintf(fd, "%s=%s\n", keyProperty->content, self->getString(self, key, ""));
    }
}

static void DumpStringContent(struct InfoContainerKeyProperty *keyProperty, struct InfoContainer *self, size_t key)
{
    if (keyProperty->flag & MAC_ADDR_FLAG) {
        CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, mac=%{public}s", keyProperty->content,
            WifiDirectAnonymizeMac(self->getString(self, key, "")));
    } else if (keyProperty->flag & IP_ADDR_FLAG) {
        CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, ip=%{public}s", keyProperty->content,
            WifiDirectAnonymizeIp(self->getString(self, key, "")));
    } else if (keyProperty->flag & DEVICE_ID_FLAG) {
        CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, devId=%{public}s", keyProperty->content,
            WifiDirectAnonymizeDeviceId(self->getString(self, key, "")));
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, string=%{public}s", keyProperty->content,
            self->getString(self, key, ""));
    }
}

static void DumpIntArrayContent(struct InfoContainerKeyProperty *keyProperty, const int32_t *item, size_t totalSize,
                                int32_t fd)
{
    char buffer[INT_ARRAY_BUFFER_LEN] = {0};
    int32_t pos = 0;
    for (size_t i = 0; i < totalSize / sizeof(int32_t); i++) {
        int32_t ret = sprintf_s(buffer + pos, sizeof(buffer) - pos, "%d ", item[i]);
        if (ret < 0) {
            break;
        }
        pos += ret;
    }
    if (fd != 0) {
        dprintf(fd, "%s=%s\n", keyProperty->content, buffer);
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, buffer=%{public}s", keyProperty->content, buffer);
    }
}

static void DumpIpv4InfoContent(struct InfoContainerKeyProperty *keyProperty, struct WifiDirectIpv4Info *ipv4,
                                int32_t fd)
{
    char ipString[IP_ADDR_STR_LEN] = {0};
    WifiDirectIpv4ToString(ipv4, ipString, sizeof(ipString));
    if (fd != 0) {
        dprintf(fd, "%s=%s\n", keyProperty->content, WifiDirectAnonymizeIp(ipString));
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT,
            "content=%{public}s, ip=%{public}s", keyProperty->content, WifiDirectAnonymizeIp(ipString));
    }
}

static void DumpIpv4InfoArrayContent(struct InfoContainerKeyProperty *keyProperty, const uint8_t *item, size_t size,
                                     int32_t fd)
{
    struct WifiDirectIpv4Info ipv4[INTERFACE_NUM_MAX];
    size_t count = INTERFACE_NUM_MAX;
    WifiDirectIpv4BytesToInfo(item, size, ipv4, &count);
    char ipString[IP_ADDR_STR_LEN] = {0};
    char buffer[IPV4_INFO_ARRAY_BUFFER_LEN] = {0};
    int32_t pos = 0;
    for (size_t i = 0; i < count; i++) {
        int32_t ret = WifiDirectIpv4ToString(ipv4 + i, ipString, sizeof(ipString));
        if (ret != SOFTBUS_OK) {
            break;
        }
        ret = sprintf_s(buffer + pos, sizeof(buffer) - pos, "%s ", WifiDirectAnonymizeIp(ipString));
        if (ret < 0) {
            break;
        }
        pos += ret;
    }
    if (fd != 0) {
        dprintf(fd, "%s=%s\n", keyProperty->content, buffer);
    } else {
        CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, buffer=%{public}s", keyProperty->content, buffer);
    }
}

static void DumpContentWithFd(struct InfoContainerKeyProperty *keyProperty, struct InfoContainer *self, size_t key,
                              void *item, size_t totalSize, int32_t fd)
{
    switch (keyProperty->type) {
        case BOOLEAN:
            dprintf(fd, "%s=%d\n", keyProperty->content, self->getBoolean(self, key, false));
            break;
        case INT:
            dprintf(fd, "%s=%d\n", keyProperty->content, self->getInt(self, key, 0));
            break;
        case STRING:
            DumpStringContentWithFd(keyProperty, self, key, fd);
            break;
        case BYTE_ARRAY:
            dprintf(fd, "%s=(%zd)\n", keyProperty->content, totalSize);
            break;
        case INT_ARRAY:
            DumpIntArrayContent(keyProperty, item, totalSize, fd);
            break;
        case IPV4_INFO:
            DumpIpv4InfoContent(keyProperty, item, fd);
            break;
        case IPV4_INFO_ARRAY:
            DumpIpv4InfoArrayContent(keyProperty, item, totalSize, fd);
            break;
        case AUTH_CONNECTION:
            dprintf(fd, "%s=%s\n", keyProperty->content, item ? "not null" : "null");
            break;
        default:
            break;
    }
}

static void DumpContent(struct InfoContainerKeyProperty *keyProperty, struct InfoContainer *self, size_t key,
                        void *item, size_t totalSize)
{
    switch (keyProperty->type) {
        case BOOLEAN:
            CONN_LOGI(CONN_WIFI_DIRECT,
                "content=%{public}s, key=%{public}d", keyProperty->content, self->getBoolean(self, key, false));
            break;
        case INT:
            CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, key=%{public}d",
                keyProperty->content, self->getInt(self, key, 0));
            break;
        case STRING:
            DumpStringContent(keyProperty, self, key);
            break;
        case BYTE_ARRAY:
            CONN_LOGI(CONN_WIFI_DIRECT, "content=%{public}s, totalSize=%{public}zd", keyProperty->content, totalSize);
            break;
        case INT_ARRAY:
            DumpIntArrayContent(keyProperty, item, totalSize, 0);
            break;
        case IPV4_INFO:
            DumpIpv4InfoContent(keyProperty, item, 0);
            break;
        case IPV4_INFO_ARRAY:
            DumpIpv4InfoArrayContent(keyProperty, item, totalSize, 0);
            break;
        case AUTH_CONNECTION:
            CONN_LOGI(CONN_WIFI_DIRECT,
                "content=%{public}s, itemIsNull=%{public}s", keyProperty->content, item ? "not null" : "null");
            break;
        default:
            break;
    }
}

static void DumpWithFd(struct InfoContainer *self, int32_t fd)
{
    dprintf(fd, "--%s--\n", self->getContainerName());
    size_t keyMax = self->getKeySize();
    for (size_t key = 0; key < keyMax; key++) {
        struct InfoContainerKeyProperty *keyProperty = self->getKeyProperty(self, key);
        if (self->dumpFilter && !(keyProperty->flag & DUMP_FLAG)) {
            continue;
        }
        size_t totalSize = 0;
        size_t itemCount = 0;
        void *item = self->get(self, key, &totalSize, &itemCount);
        if (!item) {
            continue;
        }

        if (keyProperty->flag == CONTAINER_FLAG) {
            dprintf(fd, "[%s] >>\n", keyProperty->content);
            ((struct InfoContainer *)item)->dump(item, fd);
            dprintf(fd, "[%s] <<\n", keyProperty->content);
        } else if (keyProperty->flag == CONTAINER_ARRAY_FLAG) {
            dprintf(fd, "[%s] count=%zu >>\n", keyProperty->content, itemCount);
            size_t itemSize = totalSize / itemCount;
            for (size_t i = 0; i < itemCount; i++) {
                struct InfoContainer *container = (struct InfoContainer *)((uint8_t *) item + itemSize * i);
                container->dump(container, fd);
            }
            dprintf(fd, "[%s] count=%zu <<\n", keyProperty->content, itemCount);
        } else {
            DumpContentWithFd(keyProperty, self, key, item, totalSize, fd);
        }
    }
}

static void Dump(struct InfoContainer *self, int32_t fd)
{
    if (fd != 0) {
        DumpWithFd(self, fd);
        return;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "-- containerName=%{public}s", self->getContainerName());
    size_t keyMax = self->getKeySize();
    for (size_t key = 0; key < keyMax; key++) {
        struct InfoContainerKeyProperty *keyProperty = self->getKeyProperty(self, key);
        if (self->dumpFilter && !(keyProperty->flag & DUMP_FLAG)) {
            continue;
        }
        size_t totalSize = 0;
        size_t itemCount = 0;
        void *item = self->get(self, key, &totalSize, &itemCount);
        if (!item) {
            continue;
        }

        if (keyProperty->flag == CONTAINER_FLAG) {
            CONN_LOGI(CONN_WIFI_DIRECT, ">> content=%{public}s", keyProperty->content);
            ((struct InfoContainer *)item)->dump(item, fd);
            CONN_LOGI(CONN_WIFI_DIRECT, "<< content=%{public}s", keyProperty->content);
        } else if (keyProperty->flag == CONTAINER_ARRAY_FLAG) {
            CONN_LOGI(CONN_WIFI_DIRECT, ">> content=%{public}s, count=%{public}zu", keyProperty->content, itemCount);
            size_t itemSize = totalSize / itemCount;
            for (size_t i = 0; i < itemCount; i++) {
                struct InfoContainer *container = (struct InfoContainer *)((uint8_t *) item + itemSize * i);
                container->dump(container, fd);
            }
            CONN_LOGI(CONN_WIFI_DIRECT, "<< content=%{public}s, count=%{public}zu", keyProperty->content, itemCount);
        } else {
            DumpContent(keyProperty, self, key, item, totalSize);
        }
    }
}

void InfoContainerConstructor(struct InfoContainer *self, struct InfoContainerKeyProperty *keyProperties, size_t max)
{
    CONN_CHECK_AND_RETURN_LOGW(self != NULL, CONN_WIFI_DIRECT, "self is null");
    self->dumpFilter = true;
    for (size_t key = 0; key < max; key++) {
        self->entries[key].data = NULL;
        self->entries[key].size = 0;
        self->entries[key].count = 0;
        self->entries[key].remove = false;
    }

    self->deepCopy = DeepCopy;
    self->putInt = PutInt;
    self->putBoolean = PutBoolean;
    self->putPointer = PutPointer;
    self->putString = PutString;
    self->putIntArray = PutIntArray;
    self->putRawData = PutRawData;
    self->putContainer = PutContainer;
    self->putContainerArray = PutContainerArray;
    self->get = Get;
    self->getBoolean = GetBoolean;
    self->getPointer = GetPointer;
    self->getInt = GetInt;
    self->getString = GetString;
    self->getIntArray = GetIntArray;
    self->getContainer = GetContainer;
    self->getContainerArray = GetContainerArray;
    self->getRawData = GetRawData;
    self->isEmpty = IsEmpty;
    self->remove = Remove;
    self->getKeyProperty = GetKeyProperty;
    self->dump = Dump;
    self->keyProperties = keyProperties;
}

void InfoContainerDestructor(struct InfoContainer *self, size_t max)
{
    CONN_CHECK_AND_RETURN_LOGW(self != NULL, CONN_WIFI_DIRECT, "self is null");
    for (size_t key = 0; key < max; key++) {
        char *data = self->entries[key].data;
        if (data) {
            uint32_t keyFlag = self->getKeyProperty(self, key)->flag;
            if (keyFlag == CONTAINER_FLAG) {
                ((struct InfoContainer *)data)->destructor((struct InfoContainer *)data);
            } else if (keyFlag == CONTAINER_ARRAY_FLAG) {
                char *iterator = data;
                size_t count = self->entries[key].count;
                size_t size = self->entries[key].size / count;
                for (size_t i = 0; i < count; i++) {
                    ((struct InfoContainer *)iterator)->destructor((struct InfoContainer *)iterator);
                    iterator += size;
                }
            }

            SoftBusFree(data);
            self->entries[key].data = NULL;
        }
    }
}