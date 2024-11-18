/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "trans_log.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_p2p.h"
#include "wifi_direct_manager.h"

#define ID_OFFSET (1)

static void FreeFastTransData(AppInfo *appInfo)
{
    if (appInfo != NULL && appInfo->fastTransData != NULL) {
        SoftBusFree((void *)(appInfo->fastTransData));
    }
}

static int32_t AddTcpConnAndSessionInfo(int32_t newchannelId, int32_t fd, SessionConn *newConn,
    ListenerModule module)
{
    if (TransSrvAddDataBufNode(newchannelId, fd) != SOFTBUS_OK) {
        FreeFastTransData(&(newConn->appInfo));
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "OpenTcpDirectChannel create databuf fail");
        return SOFTBUS_MALLOC_ERR;
    }

    if (TransTdcAddSessionConn(newConn) != SOFTBUS_OK) {
        TransSrvDelDataBufNode(newchannelId);
        FreeFastTransData(&(newConn->appInfo));
        SoftBusFree(newConn);
        return SOFTBUS_TRANS_ADD_SESSION_CONN_FAILED;
    }
    if (AddTrigger(module, fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "OpenTcpDirectChannel add trigger fail");
        TransDelSessionConnById(newchannelId);
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
        struct WifiDirectManager *mgr = GetWifiDirectManager();
        if (mgr == NULL || mgr->getLocalIpByRemoteIp == NULL) {
            TRANS_LOGE(TRANS_CTRL, "GetWifiDirectManager failed");
            return SOFTBUS_WIFI_DIRECT_INIT_FAILED;
        }

        int32_t ret = mgr->getLocalIpByRemoteIp(peerIp, myIp, sizeof(myIp));
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "get Local Ip fail, ret = %{public}d", ret);
            return module;
        }

        if (IsHmlIpAddr(myIp)) {
            module = GetModuleByHmlIp(myIp);
        } else {
            module = DIRECT_CHANNEL_SERVER_P2P;
        }
    } else {
        module = DIRECT_CHANNEL_SERVER_WIFI;
    }
    return module;
}

static int32_t CopyAppInfoFastTransData(SessionConn *conn, const AppInfo *appInfo)
{
    if (appInfo->fastTransData != NULL && appInfo->fastTransDataSize > 0) {
        uint8_t *fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize);
        if (fastTransData == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s((char *)fastTransData, appInfo->fastTransDataSize, (const char *)appInfo->fastTransData,
            appInfo->fastTransDataSize) != EOK) {
            SoftBusFree(fastTransData);
            TRANS_LOGE(TRANS_CTRL, "memcpy fastTransData fail");
            return SOFTBUS_MEM_ERR;
        }
        conn->appInfo.fastTransData = fastTransData;
    }
    return SOFTBUS_OK;
}

int32_t OpenTcpDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
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
    if (memcpy_s(&newConn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy appInfo fail");
        SoftBusFree(newConn);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = CopyAppInfoFastTransData(newConn, appInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "copy appinfo fast trans data fail");
        return ret;
    }
    AuthGetLatestIdByUuid(newConn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_WIFI, false, &newConn->authHandle);
    if ((newConn->authHandle.authId == AUTH_INVALID_ID) && (connInfo->type == CONNECT_P2P_REUSE)) {
        AuthGetLatestIdByUuid(newConn->appInfo.peerData.deviceId, AUTH_LINK_TYPE_BR, false, &newConn->authHandle);
    }

    if (newConn->authHandle.authId == AUTH_INVALID_ID) {
        FreeFastTransData(&(newConn->appInfo));
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "get authId fail");
        return SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED;
    }

    int32_t fd = ConnOpenClientSocket(connInfo, newConn->appInfo.myData.addr, true);
    if (fd < 0) {
        FreeFastTransData(&(newConn->appInfo));
        SoftBusFree(newConn);
        TRANS_LOGE(TRANS_CTRL, "connect failed. fd=%{public}d", fd);
        return fd;
    }
    newConn->appInfo.fd = fd;

    ret = AddTcpConnAndSessionInfo(newchannelId, fd, newConn, module);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    *channelId = newchannelId;
    TRANS_LOGI(TRANS_CTRL,
        "ok: channelId=%{public}d, module=%{public}d, fd=%{public}d",
        newchannelId, (int32_t)module, fd);
    return SOFTBUS_OK;
}
