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

#include "trans_tcp_direct_wifi.h"

#include <securec.h>

#include "auth_interface.h"
#include "lnn_network_manager.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_socket.h"
#include "trans_log.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_p2p.h"
#include "wifi_direct_manager.h"

#define ID_OFFSET (1)
#define HML_IP_PREFIX "172.30."
#define NETWORK_ID_LEN 7

static int32_t AddTcpConnAndSessionInfo(int32_t newchannelId, int32_t fd, SessionConn *newConn,
    ListenerModule module)
{
    if (TransSrvAddDataBufNode(newchannelId, fd) != SOFTBUS_OK) {
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "OpenTcpDirectChannel create databuf fail");
        return SOFTBUS_MALLOC_ERR;
    }

    if (TransTdcAddSessionConn(newConn) != SOFTBUS_OK) {
        TransSrvDelDataBufNode(newchannelId);
        SoftBusFree(newConn);
        return SOFTBUS_TRANS_ADD_SESSION_CONN_FAILED;
    }
    if (AddTrigger(module, newConn->appInfo.fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenTcpDirectChannel add trigger fail");
        TransDelSessionConnById(newConn->channelId);
        TransSrvDelDataBufNode(newchannelId);
        return SOFTBUS_TRANS_ADD_TRIGGER_FAILED;
    }
    return SOFTBUS_OK;
}

static ListenerModule GetMoudleType(ConnectType type, const char *peerIp)
{
    ListenerModule module = UNUSE_BUTT;
    if (type == CONNECT_P2P_REUSE) {
        char myIp[IP_LEN] = {0};
        if (GetWifiDirectManager()->getLocalIpByRemoteIp(peerIp, myIp, sizeof(myIp)) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get p2p ip fail.");
            return module;
        }
        if (strncmp(myIp, HML_IP_PREFIX, NETWORK_ID_LEN) == 0) {
            module = GetMoudleByHmlIp(myIp);
        } else {
            module = DIRECT_CHANNEL_SERVER_P2P;
        }
    } else {
        module = DIRECT_CHANNEL_SERVER_WIFI;
    }
    return module;
}

int32_t OpenTcpDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo,
    int32_t *channelId)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    ListenerModule module = GetMoudleType(connInfo->type, connInfo->socketOption.addr);
    TRANS_LOGI(TRANS_CTRL, "get listener module=%{public}d!", module);
    if (module == DIRECT_CHANNEL_SERVER_WIFI) {
        module = LnnGetProtocolListenerModule(connInfo->socketOption.protocol, LNN_LISTENER_MODE_DIRECT);
    }
    if (module == UNUSE_BUTT) {
        return SOFTBUS_TRANS_TCP_UNUSE_LISTENER_MODE;
    }

    SessionConn *newConn = CreateNewSessinConn(module, false);
    if (newConn == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(newConn->channelId + ID_OFFSET));
    TRANS_LOGI(TRANS_CTRL,
        "SoftbusHitraceChainBegin: set HitraceId=%{public}" PRIu64, (uint64_t)(newConn->channelId + ID_OFFSET));
    int32_t newchannelId = newConn->channelId;
    (void)memcpy_s(&newConn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo));

    newConn->authId = AuthGetLatestIdByUuid(newConn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_WIFI, false);
    if ((newConn->authId == AUTH_INVALID_ID) && (connInfo->type == CONNECT_P2P_REUSE)) {
        newConn->authId = AuthGetLatestIdByUuid(newConn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_BR, false);
    }

    if (newConn->authId == AUTH_INVALID_ID) {
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "get authId fail");
        return SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED;
    }

    int32_t fd = ConnOpenClientSocket(connInfo, BIND_ADDR_ALL, true);
    if (fd < 0) {
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "connect fail");
        return fd;
    }
    newConn->appInfo.fd = fd;

    int32_t ret = AddTcpConnAndSessionInfo(newchannelId, fd, newConn, module);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    *channelId = newchannelId;
    TRANS_LOGI(TRANS_CTRL, "ok: channelId=%{public}d", newchannelId);
    return SOFTBUS_OK;
}
