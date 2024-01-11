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

#include "interface_info.h"

#include <string.h>
#include "securec.h"

#include "conn_log.h"
#include "softbus_error_code.h"

#include "protocol/wifi_direct_protocol.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_utils.h"

#define II_TAG_DYNAMIC_MAC 0
#define II_TAG_INTERFACE_NAME 1
#define II_TAG_CONNECT_CAPABILITY 2
#define II_TAG_WIFI_DIRECT_ROLE 3
#define II_TAG_BASE_MAC 4
#define II_TAG_PHYSICAL_RATE 5
#define II_TAG_SUPPORT_BAND 6
#define II_TAG_CHANNEL_AND_BANDWIDTH 7
#define II_TAG_COEXIST_CHANNEL_LIST 8
#define II_TAG_HML_LINK_COUNT 9
#define II_TAG_ISLAND_DEVICE_COUNT 10
#define II_TAG_COEXIST_VAP_COUNT 11
#define II_TAG_IPV4 12
#define II_TAG_CHANNEL_5G_LIST 13
#define II_TAG_SSID 14
#define II_TAG_PORT 15
#define II_TAG_IS_WIDE_BAND_SUPPORT 16
#define II_TAG_CENTER_20M 17
#define II_TAG_CENTER_FREQUENCY1 18
#define II_TAG_CENTER_FREQUENCY2 19
#define II_TAG_BANDWIDTH 20
#define II_TAG_WIFI_CFG_INFO 21
#define II_TAG_IS_ENABLE 22
#define II_TAG_CONNECTED_DEVICE_COUNT 23
#define II_TAG_PSK 24
#define II_TAG_REUSE_COUNT 25
#define II_TAG_IS_AVAILABLE 26
#define II_TAG_COEXIST_RULE 27

IC_DECLARE_KEY_PROPERTIES(InterfaceInfo, II_KEY_MAX) = {
    IC_KEY_PROPERTY(II_KEY_DYNAMIC_MAC, II_TAG_DYNAMIC_MAC, "DYNAMIC_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(II_KEY_INTERFACE_NAME, II_TAG_INTERFACE_NAME, "INTERFACE_NAME", STRING, DUMP_FLAG),
    IC_KEY_PROPERTY(II_KEY_CONNECT_CAPABILITY, II_TAG_CONNECT_CAPABILITY, "CONNECT_CAPABILITY", INT, 0),
    IC_KEY_PROPERTY(II_KEY_WIFI_DIRECT_ROLE, II_TAG_WIFI_DIRECT_ROLE, "WIFI_DIRECT_ROLE", INT, DUMP_FLAG),
    IC_KEY_PROPERTY(II_KEY_BASE_MAC, II_TAG_BASE_MAC, "BASE_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(II_KEY_PHYSICAL_RATE, II_TAG_PHYSICAL_RATE, "PHYSICAL_RATE", INT, 0),
    IC_KEY_PROPERTY(II_KEY_SUPPORT_BAND, II_TAG_SUPPORT_BAND, "SUPPORT_BAND", BYTE, 0),
    IC_KEY_PROPERTY(II_KEY_CHANNEL_AND_BANDWIDTH, II_TAG_CHANNEL_AND_BANDWIDTH, "CHANNEL_AND_BANDWIDTH", BYTE_ARRAY, 0),
    IC_KEY_PROPERTY(II_KEY_COEXIST_CHANNEL_LIST, II_TAG_COEXIST_CHANNEL_LIST, "COEXIST_CHANNEL_LIST", INT_ARRAY, 0),
    IC_KEY_PROPERTY(II_KEY_HML_LINK_COUNT, II_TAG_HML_LINK_COUNT, "HML_LINK_COUNT", INT, 0),
    IC_KEY_PROPERTY(II_KEY_ISLAND_DEVICE_COUNT, II_TAG_ISLAND_DEVICE_COUNT, "ISLAND_DEVICE_COUNT", INT, 0),
    IC_KEY_PROPERTY(II_KEY_COEXIST_VAP_COUNT, II_TAG_COEXIST_VAP_COUNT, "COEXIST_VAP_COUNT", INT, 0),
    IC_KEY_PROPERTY(II_KEY_IPV4, II_TAG_IPV4, "IPV4", IPV4_INFO, 0),
    IC_KEY_PROPERTY(II_KEY_CHANNEL_5G_LIST, II_TAG_CHANNEL_5G_LIST, "CHANNEL_5G_LIST", INT_ARRAY, 0),
    IC_KEY_PROPERTY(II_KEY_SSID, II_TAG_SSID, "SSID", STRING, 0),
    IC_KEY_PROPERTY(II_KEY_PORT, II_TAG_PORT, "PORT", INT, 0),
    IC_KEY_PROPERTY(II_KEY_IS_WIDE_BAND_SUPPORT, II_TAG_IS_WIDE_BAND_SUPPORT, "IS_WIDE_BAND_SUPPORT", BOOLEAN, 0),
    IC_KEY_PROPERTY(II_KEY_CENTER_20M, II_TAG_CENTER_20M, "CENTER_20M", INT, DUMP_FLAG),
    IC_KEY_PROPERTY(II_KEY_CENTER_FREQUENCY1, II_TAG_CENTER_FREQUENCY1, "CENTER_FREQUENCY1", INT, 0),
    IC_KEY_PROPERTY(II_KEY_CENTER_FREQUENCY2, II_TAG_CENTER_FREQUENCY2, "CENTER_FREQUENCY2", INT, 0),
    IC_KEY_PROPERTY(II_KEY_BANDWIDTH, II_TAG_BANDWIDTH, "BANDWIDTH", INT, 0),
    IC_KEY_PROPERTY(II_KEY_WIFI_CFG_INFO, II_TAG_WIFI_CFG_INFO, "WIFI_CFG_INFO", BYTE_ARRAY, 0),
    IC_KEY_PROPERTY(II_KEY_IS_ENABLE, II_TAG_IS_ENABLE, "IS_ENABLE", BOOLEAN, DUMP_FLAG),
    IC_KEY_PROPERTY(II_KEY_CONNECTED_DEVICE_COUNT, II_TAG_CONNECTED_DEVICE_COUNT, "CONNECTED_DEVICE_COUNT", INT,
                    DUMP_FLAG),
    IC_KEY_PROPERTY(II_KEY_PSK, II_TAG_PSK, "PSK", STRING, 0),
    IC_KEY_PROPERTY(II_KEY_REUSE_COUNT, II_TAG_REUSE_COUNT, "REUSE_COUNT", INT, DUMP_FLAG),
    IC_KEY_PROPERTY(II_KEY_IS_AVAILABLE, II_TAG_IS_AVAILABLE, "IS_AVAILABLE", BOOLEAN, 0),
    IC_KEY_PROPERTY(II_KEY_COEXIST_RULE, II_TAG_COEXIST_RULE, "COEXIST_RULE", COEXIST_SET, 0),
};

/* private method forward declare */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty);
static bool MarshallingMacAddress(struct InterfaceInfo *self, struct WifiDirectProtocol *protocol,
                                  enum InterfaceInfoKey key);
static bool UnmarshallingMacAddress(struct InterfaceInfo *self, enum InterfaceInfoKey key, uint8_t *data, size_t size);

/* public interface */
static size_t GetKeySize(void)
{
    return II_KEY_MAX;
}

static const char *GetContainerName(void)
{
    return "InterfaceInfo";
}

static bool MarshallingString(struct WifiDirectProtocol *protocol,
    struct InfoContainerKeyProperty *keyProperty, size_t key, uint8_t *value, size_t size)
{
    bool ret = false;
    if (key == II_KEY_DYNAMIC_MAC || key == II_KEY_BASE_MAC) {
        uint8_t mac[MAC_ADDR_ARRAY_SIZE];
        size_t macSize = sizeof(mac);
        (void)memset_s(mac, macSize, 0, macSize);
        if (GetWifiDirectNetWorkUtils()->macStringToArray((char *)value, mac, &macSize) != SOFTBUS_OK) {
            CONN_LOGW(CONN_WIFI_DIRECT, "mac string to bytes failed");
            return false;
        }
        ret = protocol->writeData(protocol, keyProperty, mac, macSize);
    } else {
        ret = protocol->writeData(protocol, keyProperty, value, size >= 1 ? size - 1 : 0);
    }

    return ret;
}

static bool UnmarshallingString(struct InterfaceInfo *self, size_t key, uint8_t *data, size_t size)
{
    if (key == II_KEY_DYNAMIC_MAC || key == II_KEY_BASE_MAC) {
        char macStr[MAC_ADDR_STR_LEN];
        (void)memset_s(macStr, sizeof(macStr), 0, sizeof(macStr));
        if (GetWifiDirectNetWorkUtils()->macArrayToString(data, size, macStr, sizeof(macStr)) != SOFTBUS_OK) {
            CONN_LOGW(CONN_WIFI_DIRECT, "mac bytes to string failed");
            return false;
        }
        self->putString(self, key, macStr);
    } else {
        char *string = SoftBusCalloc(size + 1);
        CONN_CHECK_AND_RETURN_RET_LOGE(string, false, CONN_WIFI_DIRECT, "alloc failed");
        if (memcpy_s(string, size + 1, data, size) != EOK) {
            CONN_LOGE(CONN_WIFI_DIRECT, "memcpy data failed");
            SoftBusFree(string);
            return false;
        }
        self->putString(self, key, string);
        SoftBusFree(string);
    }

    return true;
}

static bool Marshalling(struct InterfaceInfo *self, struct WifiDirectProtocol *protocol)
{
    enum WifiDirectProtocolType protocolType = protocol->getType();

    for (size_t key = 0; key < II_KEY_MAX; key++) {
        size_t size = 0;
        uint8_t *value = self->get(self, key, &size, NULL);
        if (!value || !size) {
            continue;
        }

        bool ret = false;
        struct InfoContainerKeyProperty *keyProperty = self->keyProperties + key;
        if (protocolType == WIFI_DIRECT_PROTOCOL_TLV && (key == II_KEY_BASE_MAC || key == II_KEY_DYNAMIC_MAC)) {
            ret = MarshallingMacAddress(self, protocol, key);
            CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT,
                "mac address marshalling failed, key=%{public}zu", key);
            continue;
        }

        switch (keyProperty->type) {
            case BOOLEAN: {
                    uint8_t boolValue = (uint8_t)!!*(bool *)value;
                    ret = protocol->writeData(protocol, keyProperty, &boolValue, 1);
                    break;
                }
            case INT:{
                uint8_t bytes[sizeof(uint32_t)] = {0};
                GetWifiDirectUtils()->intToBytes(*(uint32_t*)value, sizeof(uint32_t), bytes, sizeof(bytes));
                ret = protocol->writeData(protocol, keyProperty, bytes, sizeof(bytes));
            }
                break;
            case BYTE:
            case INT_ARRAY:
            case BYTE_ARRAY:
                ret = protocol->writeData(protocol, keyProperty, value, size);
                break;
            case STRING:
                ret = MarshallingString(protocol, keyProperty, key, value, size);
                break;
            default:
                ret = true;
                break;
        }

        CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "marshalling failed, key=%{public}zu", key);
    }

    return true;
}

static bool Unmarshalling(struct InterfaceInfo *self, struct WifiDirectProtocol *protocol)
{
    size_t size = 0;
    uint8_t *data = NULL;
    struct InfoContainerKeyProperty keyProperty;
    (void)memset_s(&keyProperty, sizeof(keyProperty), 0, sizeof(keyProperty));
    enum WifiDirectProtocolType protocolType = protocol->getType();

    while (protocol->readData(protocol, &keyProperty, &data, &size)) {
        bool ret = false;
        enum InterfaceInfoKey key = GetKeyFromKeyProperty(&keyProperty);
        CONN_CHECK_AND_RETURN_RET_LOGW(key < II_KEY_MAX, false, CONN_WIFI_DIRECT, "key out of range, tag=%{public}d",
            keyProperty.tag);
        if (!data || !size) {
            continue;
        }

        if (protocolType == WIFI_DIRECT_PROTOCOL_TLV && (key == II_KEY_BASE_MAC || key == II_KEY_DYNAMIC_MAC)) {
            ret = UnmarshallingMacAddress(self, key, data, size);
            CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT,
                "mac address unmarshalling failed key=%{public}d", key);
            continue;
        }

        switch (keyProperty.type) {
            case BOOLEAN:
                self->putBoolean(self, key, (bool)data[0]);
                ret = true;
                break;
            case INT:
                self->putInt(self, key, (int32_t)GetWifiDirectUtils()->bytesToInt(data, size));
                ret = true;
                break;
            case BYTE:
            case INT_ARRAY:
            case BYTE_ARRAY:
                self->putRawData(self, key, data, size);
                ret = true;
                break;
            case STRING:
                ret = UnmarshallingString(self, key, data, size);
                break;
            default:
                continue;
        }

        data = NULL;
        size = 0;
        CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "unmarshalling failed key=%{public}d", key);
    }

    return true;
}

static char *GetName(struct InterfaceInfo *self)
{
    return self->getString(self, II_KEY_INTERFACE_NAME, "");
}

static void PutName(struct InterfaceInfo *self, const char *name)
{
    self->putString(self, II_KEY_INTERFACE_NAME, name);
}

static int32_t GetIpString(struct InterfaceInfo *self, char *ipString, int32_t ipStringSize)
{
    struct WifiDirectIpv4Info *ipv4 = self->getRawData(self, II_KEY_IPV4, NULL, NULL);
    return WifiDirectIpv4ToString(ipv4, ipString, ipStringSize);
}

static void PutIpString(struct InterfaceInfo *self, const char *ipString)
{
    struct WifiDirectIpv4Info ipv4;
    int32_t ret = WifiDirectIpStringToIpv4(ipString, &ipv4);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "ip to ipv4 failed");
    self->putRawData(self, II_KEY_IPV4, &ipv4, sizeof(ipv4));
}

static int32_t GetP2pGroupConfig(struct InterfaceInfo *self, char *buffer, size_t bufferSize)
{
    int32_t ret = sprintf_s(buffer, bufferSize, "%s\n%s\n%s\n%d",
                            self->getString(self, II_KEY_SSID, ""),
                            self->getString(self, II_KEY_DYNAMIC_MAC, ""),
                            self->getString(self, II_KEY_PSK, ""),
                            self->getInt(self, II_KEY_CENTER_20M, 0));
    if (ret < 0) {
        CONN_LOGE(CONN_WIFI_DIRECT, "format group config failed");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t SetP2pGroupConfig(struct InterfaceInfo *self, char *groupConfig)
{
    char *configs[P2P_GROUP_CONFIG_INDEX_MAX] = {0};
    size_t configsSize = P2P_GROUP_CONFIG_INDEX_MAX;
    int32_t ret = GetWifiDirectNetWorkUtils()->splitString(groupConfig, "\n", configs, &configsSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK && configsSize > P2P_GROUP_CONFIG_INDEX_FREQ, SOFTBUS_ERR,
        CONN_WIFI_DIRECT, "split group config failed");

    self->putString(self, II_KEY_SSID, configs[P2P_GROUP_CONFIG_INDEX_SSID]);
    if (!self->get(self, II_KEY_DYNAMIC_MAC, NULL, NULL)) {
        self->putString(self, II_KEY_DYNAMIC_MAC, configs[P2P_GROUP_CONFIG_INDEX_BSSID]);
    }
    self->putString(self, II_KEY_PSK, configs[P2P_GROUP_CONFIG_INDEX_SHARE_KEY]);
    self->putInt(self, II_KEY_CENTER_20M, atoi(configs[P2P_GROUP_CONFIG_INDEX_FREQ]));

    return SOFTBUS_OK;
}

static void IncreaseRefCount(struct InterfaceInfo *self)
{
    int32_t count = self->getInt(self, II_KEY_REUSE_COUNT, 0);
    count++;
    self->putInt(self, II_KEY_REUSE_COUNT, count);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", count);
}

static void DecreaseRefCount(struct InterfaceInfo *self)
{
    int32_t count = self->getInt(self, II_KEY_REUSE_COUNT, 0);
    --count;
    self->putInt(self, II_KEY_REUSE_COUNT, count);
    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", count);
}

/* private method implement */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty)
{
    struct InfoContainerKeyProperty *predefineKeyProperty = NULL;
    for (size_t key = 0; key < II_KEY_MAX; key++) {
        predefineKeyProperty = InterfaceInfoKeyProperties + key;
        if ((keyProperty->content && strcmp(keyProperty->content, predefineKeyProperty->content) == 0) ||
            (keyProperty->tag == predefineKeyProperty->tag)) {
            *keyProperty = *predefineKeyProperty;
            return key;
        }
    }

    return II_KEY_MAX;
}

static bool MarshallingMacAddress(struct InterfaceInfo *self, struct WifiDirectProtocol *protocol,
                                  enum InterfaceInfoKey key)
{
    char *addressString = self->getString(self, key, "");
    if (strlen(addressString) == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "empty address string");
        return true;
    }

    size_t addressSize = MAC_ADDR_ARRAY_SIZE;
    uint8_t address[MAC_ADDR_ARRAY_SIZE];
    int32_t ret = GetWifiDirectNetWorkUtils()->macStringToArray(addressString, address, &addressSize);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "mac string to array failed");

    protocol->writeData(protocol, &InterfaceInfoKeyProperties[key], address, addressSize);
    return true;
}

static bool UnmarshallingMacAddress(struct InterfaceInfo *self, enum InterfaceInfoKey key, uint8_t *data, size_t size)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(size == MAC_ADDR_ARRAY_SIZE, false, CONN_WIFI_DIRECT,
        "size is invalid. size=%{public}zu", size);
    char address[MAC_ADDR_STR_LEN] = {0};
    int32_t ret = GetWifiDirectNetWorkUtils()->macArrayToString(data, size, address, sizeof(address));
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "mac array to string failed");
    self->putString(self, key, address);
    return true;
}

/* constructor and destructor */
void InterfaceInfoConstructor(struct InterfaceInfo *self)
{
    InfoContainerConstructor((struct InfoContainer *)self, InterfaceInfoKeyProperties, II_KEY_MAX);

    self->getKeySize = GetKeySize;
    self->getContainerName = GetContainerName;
    self->marshalling = Marshalling;
    self->unmarshalling = Unmarshalling;
    self->destructor = InterfaceInfoDestructor;

    self->getName = GetName;
    self->putName = PutName;
    self->getIpString = GetIpString;
    self->putIpString = PutIpString;
    self->getP2pGroupConfig = GetP2pGroupConfig;
    self->setP2pGroupConfig = SetP2pGroupConfig;
    self->increaseRefCount = IncreaseRefCount;
    self->decreaseRefCount = DecreaseRefCount;

    ListInit(&self->node);
    self->dumpFilter = false;
}

void InterfaceInfoConstructorWithName(struct InterfaceInfo *self, const char *name)
{
    InterfaceInfoConstructor(self);
    self->putName(self, name);
}

void InterfaceInfoDestructor(struct InterfaceInfo *self)
{
    InfoContainerDestructor((struct InfoContainer *)self, II_KEY_MAX);
}

/* new and delete */
struct InterfaceInfo *InterfaceInfoNew(void)
{
    struct InterfaceInfo *self = (struct InterfaceInfo *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "self is null");
    InterfaceInfoConstructor(self);

    return self;
}

void InterfaceInfoDelete(struct InterfaceInfo *self)
{
    InterfaceInfoDestructor(self);
    SoftBusFree(self);
}

struct InterfaceInfo *InterfaceInfoNewArray(size_t size)
{
    struct InterfaceInfo *self = (struct InterfaceInfo *)SoftBusCalloc(sizeof(*self) * size);
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "self is null");
    for (size_t i = 0; i < size; i++) {
        InterfaceInfoConstructor(self + i);
    }

    return self;
}

void InterfaceInfoDeleteArray(struct InterfaceInfo *self, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        InterfaceInfoDestructor(self + i);
    }
    SoftBusFree(self);
}