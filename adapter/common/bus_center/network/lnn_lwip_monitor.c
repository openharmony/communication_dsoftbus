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
#include "lnn_log.h"
#include "lwip/netif.h"
#include "softbus_error_code.h"

#define LWIP_NSC_IPSTATUS_CHANGE 0xf0

char* lwip_if_indextoname(unsigned int ifindex, char *ifname);
static int32_t NetifStatusCallback(
    struct netif *netif, netif_nsc_reason_t reason, const netif_ext_callback_args_t *args)
{
    (void)args;
    if (netif == NULL) {
        LNN_LOGE(LNN_BUILDER, "input netif is NULL");
        return SOFTBUS_INVALID_PARAM;
    }

    if (reason == LWIP_NSC_IPSTATUS_CHANGE) {
        LNN_LOGI(LNN_BUILDER, "ip monitor start success");
        char ifnameBuffer[NET_IF_NAME_LEN] = {0};
        char *ifName = lwip_if_indextoname(netif->num, ifnameBuffer);
        if (ifName == NULL) {
            LNN_LOGE(LNN_BUILDER, "Cannot find ifName");
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
    LNN_LOGI(LNN_INIT, "start success");
    return SOFTBUS_OK;
}
