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
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_socket.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"

int32_t OpenTcpDirectChannel(const AppInfo *appInfo, const ConnectOption *connInfo, int32_t *channelId)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenTcpDirectChannel");
    if (appInfo == NULL || connInfo == NULL || channelId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    ListenerModule module = DIRECT_CHANNEL_SERVER_WIFI;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "%s:get listener module %d!", __func__, module);

    SessionConn *newConn = CreateNewSessinConn(module, false);
    if (newConn == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t newchannelId = newConn->channelId;
    (void)memcpy_s(&newConn->appInfo, sizeof(AppInfo), appInfo, sizeof(AppInfo));

    newConn->authId = AuthGetLatestIdByUuid(newConn->appInfo.peerData.deviceId, true, false);
    if (newConn->authId == AUTH_INVALID_ID) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenTcpDirectChannel get authId fail");
        return SOFTBUS_ERR;
    }

    int32_t fd = ConnOpenClientSocket(connInfo, BIND_ADDR_ALL, false);
    if (fd < 0) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenTcpDirectChannel connect fail");
        return SOFTBUS_CONN_FAIL;
    }
    newConn->appInfo.fd = fd;

    if (TransSrvAddDataBufNode(newchannelId, fd) != SOFTBUS_OK) {
        SoftBusFree(newConn);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenTcpDirectChannel create databuf fail");
        return SOFTBUS_MALLOC_ERR;
    }

    if (TransTdcAddSessionConn(newConn) != SOFTBUS_OK) {
        TransSrvDelDataBufNode(newchannelId);
        SoftBusFree(newConn);
        return SOFTBUS_ERR;
    }
    if (AddTrigger(module, newConn->appInfo.fd, WRITE_TRIGGER) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "OpenTcpDirectChannel add trigger fail");
        TransDelSessionConnById(newConn->channelId);
        TransSrvDelDataBufNode(newchannelId);
        return SOFTBUS_ERR;
    }
    *channelId = newchannelId;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "OpenTcpDirectChannel end: channelId=%d", newchannelId);
    return SOFTBUS_OK;
}