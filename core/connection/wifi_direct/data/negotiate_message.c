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

#include "negotiate_message.h"
#include <securec.h>
#include <string.h>
#include "conn_log.h"
#include "data/link_info.h"
#include "data/interface_info.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "utils/wifi_direct_utils.h"

#define NM_TAG_MSG_TYPE 0
#define NM_TAG_SESSION_ID 1
#define NM_TAG_WIFI_CFG_INFO 2
#define NM_TAG_IPV4_LIST 3
#define NM_TAG_PREFER_LINK_MODE 4
#define NM_TAG_IS_MODE_STRICT 5
#define NM_TAG_PREFER_LINK_BANDWIDTH 6
#define NM_TAG_IS_BRIDGE_SUPPORTED 7
#define NM_TAG_LINK_INFO 8
#define NM_TAG_RESULT_CODE 9
#define NM_TAG_INTERFACE_INFO_ARRAY 10
#define NM_TAG_REMOTE_DEVICE_ID 11
#define NM_TAG_AUTH_CONNECTION 12
#define NM_TAG_EXTRA_DATA_ARRAY 13
#define NM_TAG_INNER_LINK 14
#define NM_TAG_WIFI_CFG_TYPE 15
#define NM_TAG_IS_PROXY_ENABLE 16
#define NM_TAG_CHANNEL_5G_LIST 17
#define NM_TAG_CHANNEL_5G_SCORE 18

/* old p2p */
#define NM_TAG_GC_CHANNEL_LIST 200
#define NM_TAG_STATION_FREQUENCY 201
#define NM_TAG_ROLE 202
#define NM_TAG_EXPECTED_ROLE 203
#define NM_TAG_VERSION 204
#define NM_TAG_GC_IP 205
#define NM_TAG_WIDE_BAND_SUPPORTED 206
#define NM_TAG_GROUP_CONFIG 207
#define NM_TAG_MAC 208
#define NM_TAG_BRIDGE_SUPPORTED 209
#define NM_TAG_GO_IP 210
#define NM_TAG_GO_MAC 211
#define NM_TAG_GO_PORT 212
#define NM_TAG_IP 213
#define NM_TAG_RESULT 214
#define NM_TAG_CONTENT_TYPE 215
#define NM_TAG_GC_MAC 216
#define NM_TAG_SELF_WIFI_CONFIG 217
#define NM_TAG_GC_CHANNEL_SCORE 218
#define NM_TAG_COMMAND_TYPE 219
#define NM_TAG_INTERFACE_NAME 220

IC_DECLARE_KEY_PROPERTIES(NegotiateMessage, NM_KEY_MAX) = {
    IC_KEY_PROPERTY(NM_KEY_MSG_TYPE, NM_TAG_MSG_TYPE, "MSG_TYPE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_SESSION_ID, NM_TAG_SESSION_ID, "SESSION_ID", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_WIFI_CFG_TYPE, NM_TAG_WIFI_CFG_TYPE, "WIFI_CFG_TYPE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_WIFI_CFG_INFO, NM_TAG_WIFI_CFG_INFO, "WIFI_CFG_INFO", BYTE_ARRAY, 0),
    IC_KEY_PROPERTY(NM_KEY_IPV4_LIST, NM_TAG_IPV4_LIST, "IPV4_LIST", IPV4_INFO_ARRAY, 0),
    IC_KEY_PROPERTY(NM_KEY_PREFER_LINK_MODE, NM_TAG_PREFER_LINK_MODE, "PREFER_LINK_MODE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_IS_MODE_STRICT, NM_TAG_IS_MODE_STRICT, "IS_MODE_STRICT", BOOLEAN, 0),
    IC_KEY_PROPERTY(NM_KEY_PREFER_LINK_BANDWIDTH, NM_TAG_PREFER_LINK_BANDWIDTH, "PREFER_LINK_BANDWIDTH", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_IS_BRIDGE_SUPPORTED, NM_TAG_IS_BRIDGE_SUPPORTED, "IS_BRIDGE_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(NM_KEY_LINK_INFO, NM_TAG_LINK_INFO, "LINK_INFO", LINK_INFO, CONTAINER_FLAG),
    IC_KEY_PROPERTY(NM_KEY_RESULT_CODE, NM_TAG_RESULT_CODE, "RESULT_CODE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_INTERFACE_INFO_ARRAY, NM_TAG_INTERFACE_INFO_ARRAY,
                                "INTERFACE_INFO_ARRAY", INTERFACE_INFO_ARRAY, CONTAINER_ARRAY_FLAG),
    IC_KEY_PROPERTY(NM_KEY_REMOTE_DEVICE_ID, NM_TAG_REMOTE_DEVICE_ID, "REMOTE_DEVICE_ID", STRING, 0),
    IC_KEY_PROPERTY(NM_KEY_NEGO_CHANNEL, NM_TAG_AUTH_CONNECTION, "AUTH_CONNECTION", AUTH_CONNECTION, 0),
    IC_KEY_PROPERTY(NM_KEY_EXTRA_DATA_ARRAY, NM_TAG_EXTRA_DATA_ARRAY, "EXTRA_DATA_ARRAY", EXTRA_DATA_ARRAY, 0),
    IC_KEY_PROPERTY(NM_KEY_INNER_LINK, NM_TAG_INNER_LINK, "INNER_LINK", INNER_LINK, CONTAINER_FLAG),
    IC_KEY_PROPERTY(NM_KEY_IS_PROXY_ENABLE, NM_TAG_IS_PROXY_ENABLE, "IS_PROXY_ENABLE", BOOLEAN, 0),
    IC_KEY_PROPERTY(NM_KEY_CHANNEL_5G_LIST, NM_TAG_CHANNEL_5G_LIST, "CHANNEL_5G_LIST", STRING, 0),
    IC_KEY_PROPERTY(NM_KEY_CHANNEL_5G_SCORE, NM_TAG_CHANNEL_5G_SCORE, "CHANNEL_5G_SCORE", STRING, 0),

    /* old p2p */
    IC_KEY_PROPERTY(NM_KEY_GC_CHANNEL_LIST, NM_TAG_GC_CHANNEL_LIST, "KEY_GC_CHANNEL_LIST", STRING, 0),
    IC_KEY_PROPERTY(NM_KEY_STATION_FREQUENCY, NM_TAG_STATION_FREQUENCY, "KEY_STATION_FREQUENCY", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_ROLE, NM_TAG_ROLE, "KEY_ROLE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_EXPECTED_ROLE, NM_TAG_EXPECTED_ROLE, "KEY_EXPECTED_ROLE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_VERSION, NM_TAG_VERSION, "KEY_VERSION", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_GC_IP, NM_TAG_GC_IP, "KEY_GC_IP", STRING, IP_ADDR_FLAG),
    IC_KEY_PROPERTY(NM_KEY_WIDE_BAND_SUPPORTED, NM_TAG_WIDE_BAND_SUPPORTED, "KEY_WIDE_BAND_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(NM_KEY_GROUP_CONFIG, NM_TAG_GROUP_CONFIG, "KEY_GROUP_CONFIG", STRING, 0),
    IC_KEY_PROPERTY(NM_KEY_MAC, NM_TAG_MAC, "KEY_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(NM_KEY_BRIDGE_SUPPORTED, NM_TAG_BRIDGE_SUPPORTED, "KEY_BRIDGE_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(NM_KEY_GO_IP, NM_TAG_GO_IP, "KEY_GO_IP", STRING, IP_ADDR_FLAG),
    IC_KEY_PROPERTY(NM_KEY_GO_MAC, NM_TAG_GO_MAC, "KEY_GO_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(NM_KEY_GO_PORT, NM_TAG_GO_PORT, "KEY_GO_PORT", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_IP, NM_TAG_IP, "KEY_IP", STRING, IP_ADDR_FLAG),
    IC_KEY_PROPERTY(NM_KEY_RESULT, NM_TAG_RESULT, "KEY_RESULT", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_CONTENT_TYPE, NM_TAG_CONTENT_TYPE, "KEY_CONTENT_TYPE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_GC_MAC, NM_TAG_GC_MAC, "KEY_GC_MAC", STRING, MAC_ADDR_FLAG),
    IC_KEY_PROPERTY(NM_KEY_SELF_WIFI_CONFIG, NM_TAG_SELF_WIFI_CONFIG, "KEY_SELF_WIFI_CONFIG", STRING, 0),
    IC_KEY_PROPERTY(NM_KEY_GC_CHANNEL_SCORE, NM_TAG_GC_CHANNEL_SCORE, "KEY_GC_CHANNEL_SCORE", STRING, 0),
    IC_KEY_PROPERTY(NM_KEY_COMMAND_TYPE, NM_TAG_COMMAND_TYPE, "KEY_COMMAND_TYPE", INT, 0),
    IC_KEY_PROPERTY(NM_KEY_INTERFACE_NAME, NM_TAG_INTERFACE_NAME, "KEY_INTERFACE_NAME", STRING, 0),
};

/* private method forward declare */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty);
static bool MarshallingLinkInfo(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                enum NegotiateMessageKey key);
static bool UnmarshallingLinkInfo(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                  enum NegotiateMessageKey key, uint8_t *data, size_t size);

static bool MarshallingInterfaceInfoArray(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                          enum NegotiateMessageKey key);
static bool UnmarshallingInterfaceInfoArray(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                            size_t key, uint8_t *data, size_t size);
/* public interface */
static size_t GetKeySize(void)
{
    return NM_KEY_MAX;
}

static const char *GetContainerName(void)
{
    return "NegotiateMessage";
}

static bool Marshalling(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol)
{
    for (size_t key = 0; key < NM_KEY_MAX; key++) {
        if (key == NM_KEY_REMOTE_DEVICE_ID) {
            continue;
        }
        size_t size = 0;
        uint8_t *value = self->get(self, key, &size, NULL);
        if ((value == NULL) || (size == 0)) {
            continue;
        }

        bool ret = false;
        struct InfoContainerKeyProperty *keyProperty = self->keyProperties + key;
        switch (keyProperty->type) {
            case BOOLEAN:{
                    uint8_t boolValue = (uint8_t)!!*(bool *)value;
                    ret = protocol->writeData(protocol, keyProperty, &boolValue, 1);
                    break;
                }
            case INT: {
                uint8_t bytes[sizeof(uint32_t)] = {0};
                GetWifiDirectUtils()->intToBytes(*(uint32_t*)value, sizeof(uint32_t), bytes, sizeof(bytes));
                ret = protocol->writeData(protocol, keyProperty, bytes, sizeof(bytes));
            }
                break;
            case STRING:
                ret = protocol->writeData(protocol, keyProperty, value, size >= 1 ? size - 1 : 0);
                break;
            case INT_ARRAY:
            case BYTE_ARRAY:
            case IPV4_INFO:
            case IPV4_INFO_ARRAY:
                ret = protocol->writeData(protocol, keyProperty, value, size);
                break;
            case LINK_INFO:
                ret = MarshallingLinkInfo(self, protocol, key);
                break;
            case INTERFACE_INFO_ARRAY:
                ret = MarshallingInterfaceInfoArray(self, protocol, key);
                break;
            default:
                continue;
        }

        CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "marshalling nego message failed");
    }

    return true;
}

static bool Unmarshalling(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol)
{
    size_t size = 0;
    uint8_t *data = NULL;
    struct InfoContainerKeyProperty keyProperty;

    while (protocol->readData(protocol, &keyProperty, &data, &size)) {
        bool ret = false;
        enum NegotiateMessageKey key = GetKeyFromKeyProperty(&keyProperty);
        if (key == NM_KEY_MAX) {
            CONN_LOGW(CONN_WIFI_DIRECT, "not support key, tag=%{public}d, context=%{public}s", keyProperty.tag,
                keyProperty.content);
            continue;
        }

        switch (keyProperty.type) {
            case BOOLEAN:
                self->putBoolean(self, key, (bool)data[0]);
                ret = true;
                break;
            case INT: {
                int32_t value = (int32_t)GetWifiDirectUtils()->bytesToInt(data, size);
                self->putInt(self, key, value);
            }
                ret = true;
                break;
            case INT_ARRAY:
            case BYTE_ARRAY:
            case IPV4_INFO:
            case IPV4_INFO_ARRAY:
                self->putRawData(self, key, data, size);
                ret = true;
                break;
            case STRING: {
                char *string = SoftBusCalloc(size + 1);
                CONN_CHECK_AND_RETURN_RET_LOGE(string, false, CONN_WIFI_DIRECT, "alloc failed");
                if (memcpy_s(string, size + 1, data, size) != EOK) {
                    CONN_LOGW(CONN_WIFI_DIRECT, "string memcpy fail");
                    SoftBusFree(string);
                    return false;
                }
                self->putString(self, key, string);
                ret = true;
                SoftBusFree(string);
            }
                break;
            case INTERFACE_INFO_ARRAY:
                ret = UnmarshallingInterfaceInfoArray(self, protocol, key, data, size);
                break;
            case LINK_INFO:
                ret = UnmarshallingLinkInfo(self, protocol, key, data, size);
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
    for (size_t key = 0; key < NM_KEY_MAX; key++) {
        predefineKeyProperty = NegotiateMessageKeyProperties + key;
        if ((keyProperty->content && strcmp(keyProperty->content, predefineKeyProperty->content) == 0) ||
            (keyProperty->tag == predefineKeyProperty->tag)) {
            *keyProperty = *predefineKeyProperty;
            return key;
        }
    }

    return NM_KEY_MAX;
}

static bool MarshallingInterfaceInfoArray(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                          enum NegotiateMessageKey key)
{
    size_t arraySize = 0;
    struct InterfaceInfo *interfaceArray = self->getContainerArray(self, key, &arraySize);
    for (size_t i = 0; i < arraySize; i++) {
        struct WifiDirectProtocol *subProtocol = GetWifiDirectProtocolFactory()->createProtocol(protocol->getType());
        CONN_CHECK_AND_RETURN_RET_LOGW(subProtocol, false, CONN_WIFI_DIRECT, "create sub protocol failed");

        struct ProtocolFormat format = {TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
        subProtocol->setFormat(subProtocol, &format);

        struct InterfaceInfo *interface = &interfaceArray[i];
        uint8_t *outData = NULL;
        size_t outDataSize = 0;
        bool ret = subProtocol->pack(subProtocol, (struct InfoContainer *)interface, &outData, &outDataSize);
        if (!ret) {
            GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
            return false;
        }
        struct InfoContainerKeyProperty *keyProperty = self->getKeyProperty(self, key);
        ret = protocol->writeData(protocol, keyProperty, outData, outDataSize);
        GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
        CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "pack failed");
    }
    return true;
}

static bool UnmarshallingInterfaceInfoArray(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                            size_t key, uint8_t *data, size_t size)
{
    size_t currentInterfaceArraySize = 0;
    struct InterfaceInfo *currentInterfaceArray = self->getContainerArray(self, key, &currentInterfaceArraySize);
    size_t newInterfaceArraySize = currentInterfaceArraySize + 1;
    struct InterfaceInfo *newInterfaceArray = InterfaceInfoNewArray(newInterfaceArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(newInterfaceArray, false, CONN_WIFI_DIRECT, "new interface array failed");
    for (size_t i = 0; i < currentInterfaceArraySize; i++) {
        newInterfaceArray[i].deepCopy(newInterfaceArray + i, currentInterfaceArray + i);
    }

    struct WifiDirectProtocol *subProtocol = GetWifiDirectProtocolFactory()->createProtocol(protocol->getType());
    CONN_CHECK_AND_RETURN_RET_LOGW(subProtocol, false, CONN_WIFI_DIRECT, "create sub protocol failed");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    subProtocol->setFormat(subProtocol, &format);

    subProtocol->setDataSource(subProtocol, data, size);
    subProtocol->unpack(subProtocol, (struct InfoContainer *)&newInterfaceArray[newInterfaceArraySize - 1]);
    self->putContainerArray(self, key, (struct InfoContainer *)newInterfaceArray, newInterfaceArraySize,
                            sizeof(struct InterfaceInfo));
    GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
    InterfaceInfoDeleteArray(newInterfaceArray, newInterfaceArraySize);

    return true;
}

static bool MarshallingLinkInfo(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                enum NegotiateMessageKey key)
{
    struct LinkInfo *linkInfo = self->getContainer(self, key);
    struct InfoContainerKeyProperty *keyProperty = self->getKeyProperty(self, key);
    struct WifiDirectProtocol *subProtocol = GetWifiDirectProtocolFactory()->createProtocol(protocol->getType());
    CONN_CHECK_AND_RETURN_RET_LOGW(subProtocol, false, CONN_WIFI_DIRECT, "create sub protocol failed");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    subProtocol->setFormat(subProtocol, &format);

    uint8_t *outData = NULL;
    size_t outDataSize = 0;
    bool ret = false;
    ret = subProtocol->pack(subProtocol, (struct InfoContainer *) linkInfo, &outData, &outDataSize);
    if (!ret) {
        GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
        return false;
    }
    ret = protocol->writeData(protocol, keyProperty, outData, outDataSize);
    GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "pack failed");
    return true;
}

static bool UnmarshallingLinkInfo(struct NegotiateMessage *self, struct WifiDirectProtocol *protocol,
                                  enum NegotiateMessageKey key, uint8_t *data, size_t size)
{
    struct LinkInfo *linkInfo = LinkInfoNew();
    CONN_CHECK_AND_RETURN_RET_LOGW(linkInfo, false, CONN_WIFI_DIRECT, "new link info failed");

    struct WifiDirectProtocol *subProtocol = GetWifiDirectProtocolFactory()->createProtocol(protocol->getType());
    CONN_CHECK_AND_RETURN_RET_LOGW(subProtocol, false, CONN_WIFI_DIRECT, "create sub protocol failed");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE2 };
    subProtocol->setFormat(subProtocol, &format);

    bool ret = subProtocol->setDataSource(subProtocol, data, size);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "set data source failed");
    ret = subProtocol->unpack(subProtocol, (struct InfoContainer *)linkInfo);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret, false, CONN_WIFI_DIRECT, "unpack failed");

    self->putContainer(self, key, (struct InfoContainer *)linkInfo, sizeof(*linkInfo));
    GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
    LinkInfoDelete(linkInfo);

    return true;
}

/* constructor and destructor */
void NegotiateMessageConstructor(struct NegotiateMessage *self)
{
    InfoContainerConstructor((struct InfoContainer *)self, NegotiateMessageKeyProperties, NM_KEY_MAX);
    self->dumpFilter = false;

    /* virtual method */
    self->getKeySize = GetKeySize;
    self->getContainerName = GetContainerName;
    self->marshalling = Marshalling;
    self->unmarshalling = Unmarshalling;
    self->destructor = NegotiateMessageDestructor;
}

void NegotiateMessageDestructor(struct NegotiateMessage *self)
{
    InfoContainerDestructor((struct InfoContainer *)self, NM_KEY_MAX);
}

/* new and delete */
struct NegotiateMessage *NegotiateMessageNew(void)
{
    struct NegotiateMessage *self = (struct NegotiateMessage *)SoftBusCalloc(sizeof(*self));
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "self is null");
    NegotiateMessageConstructor(self);

    return self;
}

void NegotiateMessageDelete(struct NegotiateMessage *self)
{
    NegotiateMessageDestructor(self);
    SoftBusFree(self);
}

struct NegotiateMessage *NegotiateMessageNewArray(size_t size)
{
    struct NegotiateMessage *self = (struct NegotiateMessage *)SoftBusCalloc(sizeof(*self) * size);
    CONN_CHECK_AND_RETURN_RET_LOGE(self != NULL, NULL, CONN_WIFI_DIRECT, "self is null");
    for (size_t i = 0; i < size; i++) {
        NegotiateMessageConstructor(self + i);
    }

    return self;
}

void NegotiateMessageDeleteArray(struct NegotiateMessage *self, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        NegotiateMessageDestructor(self + i);
    }
    SoftBusFree(self);
}