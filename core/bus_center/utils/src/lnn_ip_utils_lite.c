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

#include "lnn_ip_utils.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <net/if.h>
#include <securec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "softbus_errcode.h"
#include "softbus_log.h"
#include "netif.h"

#define WLAN "wlan0"

static const char *GetIfNamePrefix(ConnectionAddrType type)
{
    if (type == CONNECTION_ADDR_WLAN) {
        return LNN_WLAN_IF_NAME_PREFIX;
    } else if (type == CONNECTION_ADDR_ETH) {
        return LNN_ETH_IF_NAME_PREFIX;
    } else {
        return NULL;
    }
}

int32_t LnnGetLocalIp(char *ip, uint32_t len, char *ifName, uint32_t ifNameLen, ConnectionAddrType type)
{
    struct netif *netif = NULL;
    char *ipStr = NULL;
    ip4_addr_t ipAddr;
    ip4_addr_t netMask;
    ip4_addr_t gw;

    if (ip == NULL || ifName == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ip or ifName buffer is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }
    const char *prefix = GetIfNamePrefix(type);
    if (prefix == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get ifname prefix failed!");
        return SOFTBUS_INVALID_PARAM;
    }

    if (prefix == LNN_WLAN_IF_NAME_PREFIX) {
        netif = netif_find(WLAN);
        if (netif == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "netif is NULL!");
            return SOFTBUS_ERR;
        }
        netifapi_netif_get_addr(netif, &ipAddr, &netMask, &gw);
        if (strncpy_s(ifName, ifNameLen, WLAN, IFNAMSIZ) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ifname failed!");
        }
        ipStr = ip4addr_ntoa(&ipAddr);
        if (strncpy_s(ip, len, ipStr, strlen(ipStr)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy ip failed!");
        }

        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnGetLocalIp success. ip = %s", ip);
        return SOFTBUS_OK;
    } else {
        return SOFTBUS_ERR;
    }
}
