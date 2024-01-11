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

#include "wifi_config_info.h"
#include <securec.h>
#include <string.h>
#include "conn_log.h"
#include "softbus_error_code.h"
#include "data/interface_info.h"
#include "protocol/wifi_direct_protocol.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "utils/wifi_direct_utils.h"
#include "utils/wifi_direct_network_utils.h"

#define WC_TAG_INVALID 0
#define WC_TAG_VERSION 1
#define WC_TAG_IS_P2P_CHANNEL_OPTIMIZE_ENABLE 2
#define WC_TAG_IS_DBDC_SUPPORTED 3
#define WC_TAG_IS_CSA_SUPPORTED 4
#define WC_TAG_IS_RADAR_DETECTION_SUPPORTED 5
#define WC_TAG_IS_DFS_P2P_SUPPORTED 6
#define WC_TAG_IS_INDOOR_P2P_SUPPORTED 7
#define WC_TAG_STA_CHANNEL 8
#define WC_TAG_STA_PORTAL_STATE 9
#define WC_TAG_STA_SSID 10
#define WC_TAG_STA_BSSID 11
#define WC_TAG_STA_INTERNET_STATE 12
#define WC_TAG_P2P_CHANNEL_LIST 13
#define WC_TAG_STA_PWD 14
#define WC_TAG_STA_ENCRYPT_MODE 15
#define WC_TAG_IS_CONNECTED_TO_HUAWEI_ROUTER 16
#define WC_TAG_DEVICE_TYPE 17
#define WC_TAG_IGNORE 18
#define WC_TAG_DEVICE_ID 19
#define WC_TAG_INTERFACE_INFO_ARRAY 20

IC_DECLARE_KEY_PROPERTIES(WifiConfigInfo, WC_KEY_MAX) = {
    IC_KEY_PROPERTY(WC_KEY_INVALID, WC_TAG_INVALID, "INVALID", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_VERSION, WC_TAG_VERSION, "VERSION", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_P2P_CHANNEL_OPTIMIZE_ENABLE, WC_TAG_IS_P2P_CHANNEL_OPTIMIZE_ENABLE,
                    "IS_P2P_CHANNEL_OPTIMIZE_ENABLE", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_DBDC_SUPPORTED, WC_TAG_IS_DBDC_SUPPORTED, "IS_DBDC_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_CSA_SUPPORTED, WC_TAG_IS_CSA_SUPPORTED, "IS_CSA_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_RADAR_DETECTION_SUPPORTED, WC_TAG_IS_RADAR_DETECTION_SUPPORTED,
                    "IS_RADAR_DETECTION_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_DFS_P2P_SUPPORTED, WC_TAG_IS_DFS_P2P_SUPPORTED, "IS_DFS_P2P_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_INDOOR_P2P_SUPPORTED, WC_TAG_IS_INDOOR_P2P_SUPPORTED,
                    "IS_INDOOR_P2P_SUPPORTED", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_CHANNEL, WC_TAG_STA_CHANNEL, "STA_CHANNEL", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_PORTAL_STATE, WC_TAG_STA_PORTAL_STATE, "STA_PORTAL_STATE", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_SSID, WC_TAG_STA_SSID, "STA_SSID", STRING, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_BSSID, WC_TAG_STA_BSSID, "STA_BSSID", STRING, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_INTERNET_STATE, WC_TAG_STA_INTERNET_STATE, "STA_INTERNET_STATE", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_P2P_CHANNEL_LIST, WC_TAG_P2P_CHANNEL_LIST, "P2P_CHANNEL_LIST", INT_ARRAY, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_PWD, WC_TAG_STA_PWD, "STA_PWD", STRING, 0),
    IC_KEY_PROPERTY(WC_KEY_STA_ENCRYPT_MODE, WC_TAG_STA_ENCRYPT_MODE, "STA_ENCRYPT_MODE", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_IS_CONNECTED_TO_HUAWEI_ROUTER, WC_TAG_IS_CONNECTED_TO_HUAWEI_ROUTER,
                    "IS_CONNECTED_TO_HUAWEI_ROUTER", BOOLEAN, 0),
    IC_KEY_PROPERTY(WC_KEY_IGNORE, WC_TAG_IGNORE, "IGNORE", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_DEVICE_TYPE, WC_TAG_DEVICE_TYPE, "DEVICE_TYPE", INT, 0),
    IC_KEY_PROPERTY(WC_KEY_DEVICE_ID, WC_TAG_DEVICE_ID, "DEVICE_ID", STRING, 0),
    IC_KEY_PROPERTY(WC_KEY_INTERFACE_INFO_ARRAY, WC_TAG_INTERFACE_INFO_ARRAY, "INTERFACE_INFO_ARRAY",
                    INTERFACE_INFO_ARRAY, CONTAINER_ARRAY_FLAG),
};

/* private method forward declare */
static size_t GetKeyFromKeyProperty(struct InfoContainerKeyProperty *keyProperty);
static bool UnmarshallingInterfaceInfoArray(struct WifiConfigInfo *self, struct WifiDirectProtocol *protocol,
                                            size_t key, uint8_t *data, size_t size);

/* public interface */
static size_t GetKeySize(void)
{
    return WC_KEY_MAX;
}

static const char* GetContainerName(void)
{
    return "WifiConfigInfo";
}

static bool Unmarshalling(struct WifiConfigInfo *self, struct WifiDirectProtocol *protocol)
{
    size_t size = 0;
    uint8_t *data = NULL;
    struct InfoContainerKeyProperty keyProperty;
    enum WifiDirectProtocolType protocolType = protocol->getType();

    while (protocol->readData(protocol, &keyProperty, &data, &size)) {
        bool ret = false;
        enum WifiConfigInfoKey key = GetKeyFromKeyProperty(&keyProperty);
        CONN_CHECK_AND_RETURN_RET_LOGW(key < WC_KEY_MAX, false, CONN_WIFI_DIRECT, "key out of range, tag=%{public}d",
            keyProperty.tag);
        if ((data == NULL) || (size == 0)) {
            continue;
        }
        if (key == WC_KEY_IGNORE) {
            continue;
        }

        switch (keyProperty.type) {
            case BOOLEAN:
            case INT: {
                int32_t value = (int32_t)GetWifiDirectUtils()->bytesToInt(data, size);
                self->putInt(self, key, value);
                ret = true;
            }
                break;
            case INT_ARRAY:
                ret = true;
                self->putRawData(self, key, data, size);
                break;
            case STRING:
                if (protocolType == WIFI_DIRECT_PROTOCOL_TLV && (key == WC_KEY_DEVICE_ID || key == WC_KEY_STA_BSSID)) {
                    char macString[MAC_ADDR_STR_LEN] = {0};
                    if (GetWifiDirectNetWorkUtils()->macArrayToString(data, size, macString, sizeof(macString))
                        != SOFTBUS_OK) {
                        CONN_LOGW(CONN_WIFI_DIRECT, "mac array to string failed");
                        ret = false;
                    } else {
                        self->putString(self, key, macString);
                        ret = true;
                    }
                } else {
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
    for (size_t key = 0; key < WC_KEY_MAX; key++) {
        predefineKeyProperty = WifiConfigInfoKeyProperties + key;
        if ((keyProperty->content && strcmp(keyProperty->content, predefineKeyProperty->content) == 0) ||
            (keyProperty->tag == predefineKeyProperty->tag)) {
            *keyProperty = *predefineKeyProperty;
            return key;
        }
    }

    return WC_KEY_MAX;
}

static bool UnmarshallingInterfaceInfoArray(struct WifiConfigInfo *self, struct WifiDirectProtocol *protocol,
                                            size_t key, uint8_t *data, size_t size)
{
    size_t currentInterfaceArraySize = 0;
    struct InterfaceInfo *currentInterfaceArray = self->getContainerArray(self, key, &currentInterfaceArraySize);
    size_t newInterfaceArraySize = currentInterfaceArraySize + 1;
    struct InterfaceInfo *newInterfaceArray = InterfaceInfoNewArray(newInterfaceArraySize);
    CONN_CHECK_AND_RETURN_RET_LOGW(newInterfaceArray, false, CONN_WIFI_DIRECT, "new interface array failed");
    for (size_t i = 0; i < currentInterfaceArraySize; i++) {
        newInterfaceArray[i].deepCopy(&newInterfaceArray[i], &currentInterfaceArray[i]);
    }

    struct WifiDirectProtocol *subProtocol = GetWifiDirectProtocolFactory()->createProtocol(protocol->getType());
    CONN_CHECK_AND_RETURN_RET_LOGW(subProtocol, false, CONN_WIFI_DIRECT, "create sub protocol failed");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE1 };
    subProtocol->setFormat(subProtocol, &format);

    subProtocol->setDataSource(subProtocol, data, size);
    subProtocol->unpack(subProtocol, (struct InfoContainer *)&newInterfaceArray[currentInterfaceArraySize]);
    self->putContainerArray(self, key, (struct InfoContainer *)newInterfaceArray, newInterfaceArraySize,
                            sizeof(struct InterfaceInfo));
    GetWifiDirectProtocolFactory()->destroyProtocol(subProtocol);
    InterfaceInfoDeleteArray(newInterfaceArray, newInterfaceArraySize);

    return true;
}

/* constructor and destructor */
int32_t WifiConfigInfoConstruct(struct WifiConfigInfo *self, uint8_t *cfg, size_t size)
{
    InfoContainerConstructor((struct InfoContainer *)self, WifiConfigInfoKeyProperties, WC_KEY_MAX);

    self->getKeySize = GetKeySize;
    self->getContainerName = GetContainerName;
    self->unmarshalling = Unmarshalling;
    self->destructor = WifiConfigInfoDestruct;

    struct WifiDirectProtocol *protocol = GetWifiDirectProtocolFactory()->createProtocol(WIFI_DIRECT_PROTOCOL_TLV);
    CONN_CHECK_AND_RETURN_RET_LOGW(protocol, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "create tlv protocol failed");

    struct ProtocolFormat format = { TLV_TAG_SIZE, TLV_LENGTH_SIZE1 };
    protocol->setFormat(protocol, &format);
    protocol->setDataSource(protocol, cfg, size);

    if (!protocol->unpack(protocol, (struct InfoContainer *)self)) {
        CONN_LOGE(CONN_WIFI_DIRECT, "unmarshalling failed");
        GetWifiDirectProtocolFactory()->destroyProtocol(protocol);
        return SOFTBUS_ERR;
    }

    GetWifiDirectProtocolFactory()->destroyProtocol(protocol);
    return SOFTBUS_OK;
}

void WifiConfigInfoDestruct(struct WifiConfigInfo *self)
{
    InfoContainerDestructor((struct InfoContainer *)self, WC_KEY_MAX);
}