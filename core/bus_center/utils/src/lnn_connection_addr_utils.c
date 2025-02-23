/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_connection_addr_utils.h"

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "lnn_log.h"
#include "softbus_def.h"

#define LNN_MAX_PRINT_ADDR_LEN 100
#define SHORT_UDID_HASH_LEN    8

static __thread char g_printAddr[LNN_MAX_PRINT_ADDR_LEN] = { 0 };

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    if (addr1 == NULL || addr2 == NULL) {
        LNN_LOGD(LNN_STATE, "addr1 or addr2 is null");
        return false;
    }
    if (addr1->type != addr2->type) {
        LNN_LOGD(LNN_STATE, "addr1 type not equal addr2 type");
        return false;
    }
    if (addr1->type == CONNECTION_ADDR_BR) {
        return strncmp(addr1->info.br.brMac, addr2->info.br.brMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_BLE) {
        if (isShort) {
            return memcmp(addr1->info.ble.udidHash, addr2->info.ble.udidHash, SHORT_UDID_HASH_LEN) == 0 ||
                strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
        } else {
            return memcmp(addr1->info.ble.udidHash, addr2->info.ble.udidHash, UDID_HASH_LEN) == 0 ||
                strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
        }
    }
    if (addr1->type == CONNECTION_ADDR_WLAN || addr1->type == CONNECTION_ADDR_ETH) {
        return (strncmp(addr1->info.ip.ip, addr2->info.ip.ip, IP_STR_MAX_LEN) == 0) &&
        (addr1->info.ip.port == addr2->info.ip.port);
    }
    if (addr1->type == CONNECTION_ADDR_SESSION) {
        return ((addr1->info.session.sessionId == addr2->info.session.sessionId) &&
            (addr1->info.session.channelId == addr2->info.session.channelId) &&
            (addr1->info.session.type == addr2->info.session.type));
    }
    return false;
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    if (addr == NULL || option == NULL) {
        LNN_LOGW(LNN_STATE, "addr or option is null");
        return false;
    }
    if (addr->type == CONNECTION_ADDR_BR) {
        option->type = CONNECT_BR;
        if (strncpy_s(option->brOption.brMac, BT_MAC_LEN, addr->info.br.brMac,
            strlen(addr->info.br.brMac)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy br mac to addr fail");
            return false;
        }
        return true;
    }
    if (addr->type == CONNECTION_ADDR_BLE) {
        option->type = CONNECT_BLE;
        if (strncpy_s(option->bleOption.bleMac, BT_MAC_LEN, addr->info.ble.bleMac,
            strlen(addr->info.ble.bleMac)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ble mac to addr fail");
            return false;
        }
        if (memcpy_s((int8_t *)option->bleOption.deviceIdHash, UDID_HASH_LEN, addr->info.ble.udidHash,
            UDID_HASH_LEN) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ble deviceIdHash to addr fail");
            return false;
        }
        return true;
    }
    if (addr->type == CONNECTION_ADDR_ETH || addr->type == CONNECTION_ADDR_WLAN) {
        option->type = CONNECT_TCP;
        if (strncpy_s(option->socketOption.addr, sizeof(option->socketOption.addr), addr->info.ip.ip,
            strlen(addr->info.ip.ip)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ip to addr fail");
            return false;
        }
        option->socketOption.port = addr->info.ip.port;
        option->socketOption.protocol = LNN_PROTOCOL_IP;
        option->socketOption.moduleId = AUTH;
        return true;
    }
    LNN_LOGE(LNN_STATE, "not supported type=%{public}d", addr->type);
    return false;
}

bool LnnConvertOptionToAddr(ConnectionAddr *addr, const ConnectOption *option,
    ConnectionAddrType hintType)
{
    if (addr == NULL || option == NULL) {
        LNN_LOGW(LNN_STATE, "addr or option is null");
        return false;
    }
    if (option->type == CONNECT_BR) {
        addr->type = CONNECTION_ADDR_BR;
        if (strncpy_s(addr->info.br.brMac, BT_MAC_LEN, option->brOption.brMac,
            strlen(option->brOption.brMac)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy br mac to addr fail");
            return false;
        }
        return true;
    }
    if (option->type == CONNECT_BLE) {
        addr->type = CONNECTION_ADDR_BLE;
        if (strncpy_s(addr->info.ble.bleMac, BT_MAC_LEN, option->bleOption.bleMac,
            strlen(option->bleOption.bleMac)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ble mac to addr fail");
            return false;
        }
        if (memcpy_s(addr->info.ble.udidHash, UDID_HASH_LEN, (int8_t *)option->bleOption.deviceIdHash,
            UDID_HASH_LEN) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ble deviceIdHash to udidHash fail");
            return false;
        }
        return true;
    }
    if (option->type == CONNECT_TCP) {
        if (option->socketOption.protocol != LNN_PROTOCOL_IP) {
            LNN_LOGE(LNN_STATE, "only ip is supportted");
            return false;
        }
        addr->type = hintType;
        if (strncpy_s(addr->info.ip.ip, IP_LEN, option->socketOption.addr,
            strlen(option->socketOption.addr)) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ip to addr fail");
            return false;
        }
        addr->info.ip.port = (uint16_t)option->socketOption.port;
        return true;
    }
    LNN_LOGE(LNN_STATE, "not supported type=%{public}d", option->type);
    return false;
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN || type == CONNECTION_ADDR_ETH) {
        return DISCOVERY_TYPE_WIFI;
    } else if (type == CONNECTION_ADDR_BR) {
        return DISCOVERY_TYPE_BR;
    } else if (type == CONNECTION_ADDR_BLE) {
        return DISCOVERY_TYPE_BLE;
    } else if (type == CONNECTION_ADDR_SESSION) {
        return DISCOVERY_TYPE_BLE;
    } else {
        return DISCOVERY_TYPE_COUNT;
    }
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    switch (type) {
        case DISCOVERY_TYPE_WIFI:
            return CONNECTION_ADDR_WLAN;
        case DISCOVERY_TYPE_BLE:
            return CONNECTION_ADDR_BLE;
        case DISCOVERY_TYPE_BR:
            return CONNECTION_ADDR_BR;
        default:
            break;
    }
    return CONNECTION_ADDR_MAX;
}

bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo)
{
    if (addr == NULL || connInfo == NULL) {
        LNN_LOGW(LNN_STATE, "addr or connInfo is null");
        return false;
    }
    if (addr->type == CONNECTION_ADDR_BR) {
        connInfo->type = AUTH_LINK_TYPE_BR;
        if (strcpy_s(connInfo->info.brInfo.brMac, BT_MAC_LEN, addr->info.br.brMac) != EOK) {
            LNN_LOGE(LNN_STATE, "copy br mac to connInfo fail");
            return false;
        }
        return true;
    }
    if (addr->type == CONNECTION_ADDR_BLE) {
        connInfo->type = AUTH_LINK_TYPE_BLE;
        if (strcpy_s(connInfo->info.bleInfo.bleMac, BT_MAC_LEN, addr->info.ble.bleMac) != EOK ||
            memcpy_s(connInfo->info.bleInfo.deviceIdHash, UDID_HASH_LEN, addr->info.ble.udidHash,
                UDID_HASH_LEN) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ble mac to connInfo fail");
            return false;
        }
        connInfo->info.bleInfo.protocol = addr->info.ble.protocol;
        connInfo->info.bleInfo.psm = addr->info.ble.psm;
        return true;
    }
    if (addr->type == CONNECTION_ADDR_ETH || addr->type == CONNECTION_ADDR_WLAN) {
        connInfo->type = AUTH_LINK_TYPE_WIFI;
        if (strcpy_s(connInfo->info.ipInfo.ip, IP_LEN, addr->info.ip.ip) != EOK ||
            memcpy_s(connInfo->info.ipInfo.deviceIdHash, UDID_HASH_LEN, addr->info.ip.udidHash, UDID_HASH_LEN) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ip to connInfo fail");
            return false;
        }
        connInfo->info.ipInfo.port = addr->info.ip.port;
        return true;
    }
    LNN_LOGE(LNN_STATE, "not supported type=%{public}d", addr->type);
    return false;
}

bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo,
    ConnectionAddrType hintType)
{
    if (addr == NULL || connInfo == NULL) {
        LNN_LOGW(LNN_STATE, "addr or connInfo is null");
        return false;
    }
    if (connInfo->type == AUTH_LINK_TYPE_BR) {
        addr->type = CONNECTION_ADDR_BR;
        if (strcpy_s(addr->info.br.brMac, BT_MAC_LEN, connInfo->info.brInfo.brMac) != EOK) {
            LNN_LOGE(LNN_STATE, "copy br mac to addr fail");
            return false;
        }
        return true;
    }
    if (connInfo->type == AUTH_LINK_TYPE_BLE) {
        addr->type = CONNECTION_ADDR_BLE;
        if (strcpy_s(addr->info.ble.bleMac, BT_MAC_LEN, connInfo->info.bleInfo.bleMac) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ble mac to addr fail");
            return false;
        }
        addr->info.ble.protocol = connInfo->info.bleInfo.protocol;
        addr->info.ble.psm = connInfo->info.bleInfo.psm;
        return true;
    }
    if (connInfo->type == AUTH_LINK_TYPE_WIFI) {
        addr->type = hintType;
        if (strcpy_s(addr->info.ip.ip, IP_LEN, connInfo->info.ipInfo.ip) != EOK) {
            LNN_LOGE(LNN_STATE, "copy ip to addr fail");
            return false;
        }
        addr->info.ip.port = (uint16_t)connInfo->info.ipInfo.port;
        return true;
    }
    LNN_LOGE(LNN_STATE, "not supported type=%{public}d", connInfo->type);
    return false;
}

bool LnnIsConnectionAddrInvalid(const ConnectionAddr *addr)
{
    if (addr == NULL) {
        LNN_LOGE(LNN_STATE, "connection addr get invalid param");
        return true;
    }
    switch (addr->type) {
        case CONNECTION_ADDR_WLAN:
        /* fall-through */
        case CONNECTION_ADDR_ETH:
            if (strnlen(addr->info.ip.ip, IP_STR_MAX_LEN) == 0 ||
                strnlen(addr->info.ip.ip, IP_STR_MAX_LEN) == IP_STR_MAX_LEN) {
                LNN_LOGE(LNN_STATE, "get invalid ip info");
                return true;
            }
            break;
        case CONNECTION_ADDR_BR:
            if (strnlen(addr->info.br.brMac, BT_MAC_LEN) == 0 ||
                strnlen(addr->info.br.brMac, BT_MAC_LEN) == BT_MAC_LEN) {
                LNN_LOGE(LNN_STATE, "get invalid brMac info");
                return true;
            }
            break;
        case CONNECTION_ADDR_BLE:
            if (strnlen(addr->info.ble.bleMac, BT_MAC_LEN) == 0 ||
                strnlen(addr->info.ble.bleMac, BT_MAC_LEN) == BT_MAC_LEN) {
                LNN_LOGE(LNN_STATE, "get invalid bleMac info");
                return true;
            }
            break;
        case CONNECTION_ADDR_SESSION:
            break;
        default:
            LNN_LOGW(LNN_STATE, "invalid connection addr type");
            return true;
    }
    return false;
}

const char *LnnPrintConnectionAddr(const ConnectionAddr *addr)
{
    int32_t ret = 0;
    char *anonyIp = NULL;
    char *anonyMac = NULL;

    if (LnnIsConnectionAddrInvalid(addr)) {
        LNN_LOGW(LNN_STATE, "print connection addr get invalid param");
        return "Addr=";
    }
    switch (addr->type) {
        case CONNECTION_ADDR_WLAN:
        /* fall-through */
        case CONNECTION_ADDR_ETH:
            Anonymize(addr->info.ip.ip, &anonyIp);
            ret = sprintf_s(g_printAddr, sizeof(g_printAddr),
                "Ip=%s", AnonymizeWrapper(anonyIp));
            AnonymizeFree(anonyIp);
            break;
        case CONNECTION_ADDR_BR:
            Anonymize(addr->info.br.brMac, &anonyMac);
            ret = sprintf_s(g_printAddr, sizeof(g_printAddr),
                "BrMac=%s", AnonymizeWrapper(anonyMac));
            AnonymizeFree(anonyMac);
            break;
        case CONNECTION_ADDR_BLE:
            Anonymize(addr->info.ble.bleMac, &anonyMac);
            ret = sprintf_s(g_printAddr, sizeof(g_printAddr),
                "BleMac=%s", AnonymizeWrapper(anonyMac));
            AnonymizeFree(anonyMac);
            break;
        default:
            LNN_LOGW(LNN_STATE, "print invalid connection addr type");
            return "Addr=";
    }
    if (ret < 0) {
        LNN_LOGE(LNN_STATE, "sprintf_s connection addr failed");
        return "Addr=";
    }
    return g_printAddr;
}