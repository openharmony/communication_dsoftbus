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

#include "lnn_event_monitor_impl.h"

#include "bus_center_event.h"
#include "lwip/netif.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define LWIP_NSC_IPSTATUS_CHANGE 0xf0

char* lwip_if_indextoname(unsigned int ifindex, char *ifname);
static int32_t NetifStatusCallback(
    struct netif *netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t *args)
{
    (void)args;
    if (netif == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "input netif is NULL!");
        return SOFTBUS_ERR;
    }

    if (reason == LWIP_NSC_IPSTATUS_CHANGE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ip monitor start success");
        char ifnameBuffer[NET_IF_NAME_LEN];
        char *ifName = lwip_if_indextoname(netif->num, ifnameBuffer);
        if (ifName == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "%s:bad netif! Cannot found ifName", __func__);
        } else {
            LnnNotifyAddressChangedEvent(ifName);
        }
    }
    return SOFTBUS_OK;
}

int32_t LnnInitLwipMonitorImpl(void)
{
    NETIF_DECLARE_EXT_CALLBACK(NetifCallback);
    netif_add_ext_callback(&NetifCallback, NetifStatusCallback);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "LnnInitLwipMonitorImpl start success...");
    return SOFTBUS_OK;
}
