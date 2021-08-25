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

#include "softbus_log.h"

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2)
{
    if (addr1->type != addr2->type) {
        return false;
    }
    if (addr1->type == CONNECTION_ADDR_BR) {
        return strncmp(addr1->info.br.brMac, addr2->info.br.brMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_BLE) {
        return strncmp(addr1->info.ble.bleMac, addr2->info.ble.bleMac, BT_MAC_LEN) == 0;
    }
    if (addr1->type == CONNECTION_ADDR_WLAN || addr1->type == CONNECTION_ADDR_ETH) {
        return (strncmp(addr1->info.ip.ip, addr2->info.ip.ip, strlen(addr1->info.ip.ip)) == 0)
            && (addr1->info.ip.port == addr2->info.ip.port);
    }
    return false;
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    if (addr == NULL || option == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "addr or option is null");
        return false;
    }
    if (addr->type == CONNECTION_ADDR_BR) {
        option->type = CONNECT_BR;
        if (strncpy_s(option->info.brOption.brMac, BT_MAC_LEN, addr->info.br.brMac,
            strlen(addr->info.br.brMac)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy br mac to addr fail");
            return false;
        }
        return true;
    }
    if (addr->type == CONNECTION_ADDR_BLE) {
        option->type = CONNECT_BLE;
        if (strncpy_s(option->info.bleOption.bleMac, BT_MAC_LEN, addr->info.ble.bleMac,
            strlen(addr->info.ble.bleMac)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ble mac to addr fail");
            return false;
        }
        return true;
    }
    if (addr->type == CONNECTION_ADDR_ETH || addr->type == CONNECTION_ADDR_WLAN) {
        option->type = CONNECT_TCP;
        if (strncpy_s(option->info.ipOption.ip, IP_LEN, addr->info.ip.ip,
            strlen(addr->info.ip.ip)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ip  to addr fail");
            return false;
        }
        option->info.ipOption.port = addr->info.ip.port;
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not supported type: %d", addr->type);
    return false;
}

bool LnnConvertOptionToAddr(ConnectionAddr *addr, const ConnectOption *option, ConnectionAddrType hintType)
{
    if (addr == NULL || option == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "addr or option is null");
        return false;
    }
    if (option->type == CONNECT_BR) {
        addr->type = CONNECTION_ADDR_BR;
        if (strncpy_s(addr->info.br.brMac, BT_MAC_LEN, option->info.brOption.brMac,
            strlen(option->info.brOption.brMac)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy br mac to addr fail");
            return false;
        }
        return true;
    }
    if (option->type == CONNECT_BLE) {
        addr->type = CONNECTION_ADDR_BLE;
        if (strncpy_s(addr->info.ble.bleMac, BT_MAC_LEN, option->info.bleOption.bleMac,
            strlen(option->info.bleOption.bleMac)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ble mac to addr fail");
            return false;
        }
        return true;
    }
    if (option->type == CONNECT_TCP) {
        addr->type = hintType;
        if (strncpy_s(addr->info.ip.ip, IP_LEN, option->info.ipOption.ip,
            strlen(option->info.ipOption.ip)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ip to addr fail");
            return false;
        }
        addr->info.ip.port = (uint16_t)option->info.ipOption.port;
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "not supported type: %d", option->type);
    return false;
}
