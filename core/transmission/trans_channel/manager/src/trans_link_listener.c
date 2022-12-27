/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "trans_link_listener.h"

#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "p2plink_interface.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_p2p.h"

static void FreeMem(const NodeBasicInfo *info)
{
    if (info != NULL) {
        SoftBusFree((NodeBasicInfo *)info);
    }
}

static int32_t GetNetworkIdByP2pMac(const char *peerMac, char *networkId, int32_t len)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GetNetworkIdByP2pMac");
    NodeBasicInfo *info = NULL;
    int32_t num = 0;

    if (LnnGetAllOnlineAndMetaNodeInfo(&info, &num) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "get online node fail");
        return SOFTBUS_ERR;
    }

    if (info == NULL || num == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "no online node");
        return SOFTBUS_NOT_FIND;
    }

    for (int32_t i = 0; i < num; i++) {
        char p2pMac[MAC_LEN] = {0};
        char *tmpNetworkId = info[i].networkId;
        if (LnnGetRemoteStrInfo(tmpNetworkId, STRING_KEY_P2P_MAC, p2pMac, sizeof(p2pMac)) != SOFTBUS_OK) {
            continue;
        }
        if (strcmp(peerMac, p2pMac) == 0) {
            if (strcpy_s(networkId, len, tmpNetworkId) != EOK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "str cpy fail");
                FreeMem(info);
                return SOFTBUS_MEM_ERR;
            }
            FreeMem(info);
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GetNetworkIdByP2pMac end");
            return SOFTBUS_OK;
        }
    }

    FreeMem(info);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GetNetworkIdByP2pMac no find");
    return SOFTBUS_NOT_FIND;
}

static void OnP2pLinkDisconnected(const char *peerMac)
{
    if (peerMac == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnP2pLinkDisconnected");

    char networkId[NETWORK_ID_BUF_LEN] = {0};
    if (GetNetworkIdByP2pMac(peerMac, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "GetNetworkIdByP2pMac fail");
        return;
    }

    TransOnLinkDown(networkId, WIFI_P2P);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "OnP2pLinkDisconnected end");
    return;
}

static void OnP2pRoleChange(P2pLinkRole myRole)
{
    if (myRole == ROLE_NONE) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "p2p role is none");
        StopP2pSessionListener();
    }
}

void ReqLinkListener(void)
{
    P2pLinkPeerDevStateCb cb = {0};
    cb.onMyRoleChange = OnP2pRoleChange;
    cb.onDevOffline = OnP2pLinkDisconnected;
    P2pLinkRegPeerDevStateChange(&cb);
    return;
}

