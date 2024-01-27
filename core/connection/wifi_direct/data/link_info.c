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

#include "link_info.h"
#include <securec.h>
#include <string.h>
#include <cJSON.h>
#include "conn_log.h"
#include "softbus_error_code.h"
#include "protocol/wifi_direct_protocol.h"
#include "utils/wifi_direct_ipv4_info.h"

#define LI_TAG_LOCAL_INTERFACE 0
#define LI_TAG_REMOTE_INTERFACE 1
#define LI_TAG_LOCAL_LINK_MODE 2
#define LI_TAG_REMOTE_LINK_MODE 3
#define LI_TAG_CENTER_20M 4
#define LI_TAG_CENTER_FREQUENCY1 5
#define LI_TAG_CENTER_FREQUENCY2 6
#define LI_TAG_BANDWIDTH 7
#define LI_TAG_SSID 8
#define LI_TAG_BSSID 9
#define LI_TAG_PSK 10
#define LI_TAG_IS_DHCP 11
#define LI_TAG_LOCAL_IPV4 12
#define LI_TAG_REMOTE_IPV4 13
#define LI_TAG_AUTH_PORT 14
#define LI_TAG_MAX_PHYSICAL_RATE 15
#define LI_TAG_REMOTE_DEVICE 16
#define LI_TAG_STATUS 17
#define LI_TAG_LOCAL_BASE_MAC 18
#define LI_TAG_REMOTE_BASE_MAC 19
#define LI_TAG_IS_CLIENT 20

IC_DECLARE_KEY_PROPERTIES(LinkInfo, LI_KEY_MAX) = {
    IC_KEY_PROPERTY(LI_KEY_LOCAL_INTERFACE, LI_TAG_LOCAL_INTERFACE, "LOCAL_INTERFACE", STRING, 0),
    IC_KEY_PROPERTY(LI_KEY_REMOTE_INTERFACE, LI_TAG_REMOTE_INTERFACE, "REMOTE_INTERFACE", STRING, 0),
    IC_KEY_PROPERTY(LI_KEY_LOCAL_LINK_MODE, LI_TAG_LOCAL_LINK_MODE, "LOCAL_LINK_MODE", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_REMOTE_LINK_MODE, LI_TAG_REMOTE_LINK_MODE, "REMOTE_LINK_MODE", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_CENTER_20M, LI_TAG_CENTER_20M, "CENTER_20M", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_CENTER_FREQUENCY1, LI_TAG_CENTER_FREQUENCY1, "CENTER_FREQUENCY1", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_CENTER_FREQUENCY2, LI_TAG_CENTER_FREQUENCY2, "CENTER_FREQUENCY2", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_BANDWIDTH, LI_TAG_BANDWIDTH, "BANDWIDTH", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_SSID, LI_TAG_SSID, "SSID", STRING, 0),
    IC_KEY_PROPERTY(LI_KEY_BSSID, LI_TAG_BSSID, "BSSID", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(LI_KEY_PSK, LI_TAG_PSK, "PSK", STRING, 0),
    IC_KEY_PROPERTY(LI_KEY_IS_DHCP, LI_TAG_IS_DHCP, "IS_DHCP", BOOLEAN, 0),
    IC_KEY_PROPERTY(LI_KEY_LOCAL_IPV4, LI_TAG_LOCAL_IPV4, "LOCAL_IPV4", IPV4_INFO, 0),
    IC_KEY_PROPERTY(LI_KEY_REMOTE_IPV4, LI_TAG_REMOTE_IPV4, "REMOTE_IPV4", IPV4_INFO, 0),
    IC_KEY_PROPERTY(LI_KEY_AUTH_PORT, LI_TAG_AUTH_PORT, "AUTH_PORT", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_MAX_PHYSICAL_RATE, LI_TAG_MAX_PHYSICAL_RATE, "MAX_PHYSICAL_RATE", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_REMOTE_DEVICE, LI_TAG_REMOTE_DEVICE, "REMOTE_DEVICE", STRING, 0),
    IC_KEY_PROPERTY(LI_KEY_STATUS, LI_TAG_STATUS, "STATUS", INT, 0),
    IC_KEY_PROPERTY(LI_KEY_LOCAL_BASE_MAC, LI_TAG_LOCAL_BASE_MAC, "LOCAL_BASE_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(LI_KEY_REMOTE_BASE_MAC, LI_TAG_REMOTE_BASE_MAC, "REMOTE_BASE_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(LI_KEY_IS_CLIENT, LI_TAG_IS_CLIENT, "IS_CLIENT", BOOLEAN, 0),
};

/* private method forward declare */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty);
static bool UnmarshallingPrimary(struct LinkInfo *self, enum LinkInfoKey key, uint8_t *data, size_t size);

/* public interface */
static size_t GetKeySize(void)
{
    return LI_KEY_MAX;
}

static const char *GetContainerName(void)
{
    return "LinkInfo";
}

static bool Marshalling(struct LinkInfo *self, struct WifiDirectProtocol *protocol)
{
    for (size_t key = 0; key < LI_KEY_MAX; key++) {
        size_t size = 0;
        uint8_t *value = self->get(self, key, &size, NULL);
        if (!value || !size) {
            continue;
        }

        bool ret = false;
        struct InfoContainerKeyProperty *keyProperty = self->keyProperties + key;
        switch (keyProperty->type) {
            case BOOLEAN: {
                    uint8_t boolValue = (uint8_t)!!*(bool *)value;
                    ret = protocol->writeData(protocol, keyProperty, &boolValue, 1);
                    break;
                }
            case STRING:
                ret = protocol->writeData(protocol, keyProperty, value, size >= 1 ? size - 1 : 0);
                break;
            case INT:
                ret = protocol->writeData(protocol, keyProperty, value, size);
                break;
            case IPV4_INFO: {
                    uint8_t ipv4Bytes[IPV4_INFO_BYTES_ARRAY_LEN] = {0};
                    size_t ipv4BytesLen = IPV4_INFO_BYTES_ARRAY_LEN;
                    WifiDirectIpv4InfoToBytes((struct WifiDirectIpv4Info *)value, 1, ipv4Bytes, &ipv4BytesLen);
                    ret = protocol->writeData(protocol, keyProperty, ipv4Bytes, ipv4BytesLen);
                    break;
                }
            default:
                ret = true;
                break;
        }

        CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "marshalling failed");
    }

    return true;
}

static bool Unmarshalling(struct LinkInfo *self, struct WifiDirectProtocol *protocol)
{
    size_t size = 0;
    uint8_t *data = NULL;
    struct InfoContainerKeyProperty keyProperty;

    while (protocol->readData(protocol, &keyProperty, &data, &size)) {
        bool ret = true;
        enum LinkInfoKey key = GetKeyFromKeyProperty(&keyProperty);
        CONN_CHECK_AND_RETURN_RET_LOGW(key < LI_KEY_MAX, false, CONN_WIFI_DIRECT, "key out of range, tag=%{public}d",
            keyProperty.tag);

        switch (LinkInfoKeyProperties[key].type) {
            case INT:
                self->putRawData(self, key, data, ALIGN_SIZE_4(size));
                break;
            case BOOLEAN:
                self->putBoolean(self, key, (bool)data[0]);
                break;
            case IPV4_INFO: {
                    struct WifiDirectIpv4Info ipv4;
                    size_t ipv4Count = 1;
                    WifiDirectIpv4BytesToInfo(data, size, &ipv4, &ipv4Count);
                    self->putRawData(self, key, &ipv4, sizeof(ipv4));
                    break;
                }
            case STRING: {
                char *string = SoftBusCalloc(size + 1);
                CONN_CHECK_AND_RETURN_RET_LOGE(string, false, CONN_WIFI_DIRECT, "alloc failed");
                if (memcpy_s(string, size + 1, data, size) != EOK) {
                    CONN_LOGW(CONN_WIFI_DIRECT, "string memcpy fail");
                    SoftBusFree(string);
                    return false;
                }
                ret = UnmarshallingPrimary(self, key, (uint8_t *) string, size + 1);
                SoftBusFree(string);
            }
                break;
            default:
                continue;
        }
        CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "unmarshalling failed key=%{public}d", key);
    }

    return true;
}

/* private method implement */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty)
{
    struct InfoContainerKeyProperty *predefineKeyProperty = NULL;
    for (size_t key = 0; key < LI_KEY_MAX; key++) {
        predefineKeyProperty = LinkInfoKeyProperties + key;
        if ((keyProperty->content && strcmp(keyProperty->content, predefineKeyProperty->content) == 0) ||
            (keyProperty->tag == predefineKeyProperty->tag)) {
            *keyProperty = *predefineKeyProperty;
            return key;
        }
    }

    return LI_KEY_MAX;
}

static bool UnmarshallingPrimary(struct LinkInfo *self, enum LinkInfoKey key,
                                 uint8_t *data, size_t size)
{
    self->putRawData(self, key, data, ALIGN_SIZE_4(size));
    return true;
}

#define BAND_2G 0x01
#define BAND_5G 0x02
#define BAND_6G 0x04

#define BANDWIDTH_80M 0x03

static cJSON *ToJsonObject(struct LinkInfo *self)
{
    cJSON *object = cJSON_CreateObject();
    if (!object) {
        return NULL;
    }

    cJSON_AddStringToObject(object, "KEY_LOCAL_IFACE", self->getString(self, LI_KEY_LOCAL_INTERFACE, ""));
    cJSON_AddStringToObject(object, "KEY_REMOTE_IFACE", self->getString(self, LI_KEY_REMOTE_INTERFACE, ""));
    cJSON_AddNumberToObject(object, "KEY_PREF_BAND", BAND_2G | BAND_5G | BAND_6G);
    cJSON_AddNumberToObject(object, "KEY_PREF_BW", BANDWIDTH_80M);
    cJSON_AddNumberToObject(object, "KEY_LOCAL_MODE", self->getInt(self, LI_KEY_LOCAL_LINK_MODE, -1));
    cJSON_AddNumberToObject(object, "KEY_REMOTE_MODE", self->getInt(self, LI_KEY_REMOTE_LINK_MODE, -1));
    cJSON_AddStringToObject(object, "KEY_REMOTE_DEV", self->getString(self, LI_KEY_REMOTE_DEVICE, ""));

    return object;
}

static int32_t GetLocalIpString(struct LinkInfo *self, char *ipString, int32_t ipStringSize)
{
    struct WifiDirectIpv4Info *ipv4 = self->getRawData(self, LI_KEY_LOCAL_IPV4, NULL, NULL);
    return WifiDirectIpv4ToString(ipv4, ipString, ipStringSize);
}

static int32_t GetRemoteIpString(struct LinkInfo *self, char *ipString, int32_t ipStringSize)
{
    struct WifiDirectIpv4Info *ipv4 = self->getRawData(self, LI_KEY_REMOTE_IPV4, NULL, NULL);
    return WifiDirectIpv4ToString(ipv4, ipString, ipStringSize);
}

static void PutLocalIpString(struct LinkInfo *self, const char *ipString)
{
    struct WifiDirectIpv4Info ipv4;
    int32_t ret = WifiDirectIpStringToIpv4(ipString, &ipv4);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "ip to ipv4 failed");
    self->putRawData(self, LI_KEY_LOCAL_IPV4, &ipv4, sizeof(ipv4));
}

static void PutRemoteIpString(struct LinkInfo *self, const char *ipString)
{
    struct WifiDirectIpv4Info ipv4;
    int32_t ret = WifiDirectIpStringToIpv4(ipString, &ipv4);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "ip to ipv4 failed");
    self->putRawData(self, LI_KEY_REMOTE_IPV4, &ipv4, sizeof(ipv4));
}

/* constructor and destructor */
void LinkInfoConstructor(struct LinkInfo *self)
{
    InfoContainerConstructor((struct InfoContainer *)self, LinkInfoKeyProperties, LI_KEY_MAX);

    self->getKeySize = GetKeySize;
    self->getContainerName = GetContainerName;
    self->marshalling = Marshalling;
    self->unmarshalling = Unmarshalling;
    self->destructor = LinkInfoDestructor;

    self->toJsonObject = ToJsonObject;
    self->getLocalIpString = GetLocalIpString;
    self->getRemoteIpString = GetRemoteIpString;
    self->putLocalIpString = PutLocalIpString;
    self->putRemoteIpString = PutRemoteIpString;

    self->dumpFilter = false;
    ListInit(&self->node);
}

void LinkInfoDestructor(struct LinkInfo *self)
{
    CONN_CHECK_AND_RETURN_LOGW(self != NULL, CONN_WIFI_DIRECT, "self is null");
    InfoContainerDestructor((struct InfoContainer *)self, LI_KEY_MAX);
}

void LinkInfoConstructorWithNameAndMode(struct LinkInfo* self, const char *localName, const char *remoteName,
                                        uint32_t localMode, uint32_t remoteMode)
{
    LinkInfoConstructor(self);
    self->putString(self, LI_KEY_LOCAL_INTERFACE, localName);
    self->putString(self, LI_KEY_REMOTE_INTERFACE, remoteName);
    self->putInt(self, LI_KEY_LOCAL_LINK_MODE, (int32_t)localMode);
    self->putInt(self, LI_KEY_REMOTE_LINK_MODE, (int32_t)remoteMode);
}

/* new and delete */
struct LinkInfo *LinkInfoNew(void)
{
    struct LinkInfo *self = (struct LinkInfo *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "self is null");
    LinkInfoConstructor(self);

    return self;
}

struct LinkInfo* LinkInfoNewWithNameAndMode(const char *localName, const char *remoteName,
                                            uint32_t localMode, uint32_t remoteMode)
{
    struct LinkInfo *self = (struct LinkInfo *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "self is null");
    LinkInfoConstructorWithNameAndMode(self, localName, remoteName, localMode, remoteMode);

    return self;
}

void LinkInfoDelete(struct LinkInfo *self)
{
    LinkInfoDestructor(self);
    SoftBusFree(self);
}