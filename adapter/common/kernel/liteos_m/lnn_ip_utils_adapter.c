/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "lnn_ip_utils_adapter.h"

#include "comm_log.h"
#include "lwip/netif.h"

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len)
{
    if (ifName == NULL || ip == NULL) {
        COMM_LOGE(COMM_ADAPTER, "ifName or ip buffer is NULL!");
        return SOFTBUS_INVALID_PARAM;
    }

    struct netif *netif = NULL;
    char *ipStr = NULL;
    char *netMaskStr = NULL;
    ip4_addr_t *ipAddr = NULL;
    ip4_addr_t *netMask = NULL;

    netif = netif_find(ifName);
    if (netif == NULL) {
        COMM_LOGE(COMM_ADAPTER, "netif is NULL!");
        return SOFTBUS_NETWORK_NETIF_NOT_FOUND;
    }
#ifdef HISPARK_PEGASUS_USE_NETIF_GET_ADDR
    netifapi_netif_get_addr(netif, ipAddr, netMask, NULL);
#else
    ipAddr = (ip4_addr_t *)netif_ip4_addr(netif);
    netMask = (ip4_addr_t *)netif_ip4_netmask(netif);
#endif
    if (ipAddr == NULL || netMask == NULL) {
        COMM_LOGE(COMM_ADAPTER, "ipAddr or netMask is NULL!");
        return SOFTBUS_NETWORK_NETIF_IP4_INFO_NULL;
    }
    ipStr = ip4addr_ntoa(ipAddr);
    if (strncpy_s(ip, len, ipStr, strlen(ipStr)) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "copy ip failed!");
        return SOFTBUS_STRCPY_ERR;
    }
    if (netmask != NULL) {
        netMaskStr = ip4addr_ntoa(netMask);
        if (strncpy_s(netmask, len, netMaskStr, strlen(netMaskStr)) != EOK) {
            COMM_LOGE(COMM_ADAPTER, "copy netmask failed!");
            return SOFTBUS_STRCPY_ERR;
        }
    }
    return SOFTBUS_OK;
}
