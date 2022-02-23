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

#include "auth_p2p.h"

#include <securec.h>

#include "auth_common.h"
#include "lnn_exchange_device_info.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static void AuthP2pOnKeyGenerated(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onKeyGenerated, authId = %lld.", authId);
    AuthManager *auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found.");
        return;
    }

    int32_t side;
    uint32_t bufSize = 0;
    uint8_t *buf = LnnGetExchangeNodeInfo((int32_t)authId, AUTH_BT, SOFT_BUS_NEW_V1, &bufSize, &side);
    if (buf == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "pack device info fail.");
        return;
    }

    AuthDataHead head;
    head.flag = auth->side;
    head.dataType = DATA_TYPE_SYNC;
    head.module = HICHAIN_SYNC;
    head.authId = authId;
    head.seq = authId;
    if (AuthPostData(&head, buf, bufSize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "send device info fail.");
        SoftBusFree(buf);
        return;
    }
    SoftBusFree(buf);
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "send device info succ, authId = %lld.", authId);
}

static void AuthP2pOnRecvSyncDeviceInfo(int64_t authId, AuthSideFlag side, const char *peerUuid,
    uint8_t *data, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onRecvSyncDeviceInfo, authId = %lld.", authId);
    AuthManager *auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found.");
        return;
    }

    ParseBuf parseBuf = {0};
    parseBuf.buf = data;
    parseBuf.len = len;
    NodeInfo *nodeInfo = SoftBusCalloc(sizeof(NodeInfo));
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "malloc node info fail");
        return;
    }
    if (LnnParsePeerNodeInfo(&auth->option, AUTH_BT, nodeInfo, &parseBuf, side, auth->peerVersion) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "unpack peer device info fail");
        return;
    }
    /* device info not used... */
    SoftBusFree(nodeInfo);
}

static void AuthP2pOnDeviceVerifyPass(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onDeviceVerifyPass, authId = %lld.", authId);
}

static void AuthP2pOnDeviceVerifyFail(int64_t authId, int32_t reason)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onDeviceVerifyFail, authId = %lld.", authId);
}

static void AuthP2pOnDisconnect(int64_t authId)
{
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onDisconnect, authId = %lld.", authId);
    AuthManager *auth = AuthGetManagerByAuthId(authId);
    if (auth == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "auth manager not found.");
        return;
    }
    if (auth->status < AUTH_PASSED && auth->connCb.onConnOpenFailed != NULL) {
        auth->connCb.onConnOpenFailed(auth->requestId, SOFTBUS_CONNECTION_ERR_CLOSED);
        auth->connCb.onConnOpenFailed = NULL;
    }
}

static void AuthP2pOnDeviceNotTrusted(const char *peerUdid)
{
    (void)peerUdid;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onDeviceNotTrusted.");
}

static void AuthP2pOnGroupCreated(const char *groupId)
{
    (void)groupId;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onGroupCreated.");
}

static void AuthP2pOnGroupDeleted(const char *groupId)
{
    (void)groupId;
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "auth p2p onGroupDeleted.");
}

int32_t AuthP2pInit(void)
{
    VerifyCallback p2pVerifyCb = {
        .onKeyGenerated = AuthP2pOnKeyGenerated,
        .onRecvSyncDeviceInfo = AuthP2pOnRecvSyncDeviceInfo,
        .onDeviceVerifyPass = AuthP2pOnDeviceVerifyPass,
        .onDeviceVerifyFail = AuthP2pOnDeviceVerifyFail,
        .onDisconnect = AuthP2pOnDisconnect,
        .onDeviceNotTrusted = AuthP2pOnDeviceNotTrusted,
        .onGroupCreated = AuthP2pOnGroupCreated,
        .onGroupDeleted = AuthP2pOnGroupDeleted
    };
    return AuthRegCallback(VERIFY_P2P_DEVICE, &p2pVerifyCb);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo)
{
    if (uuid == NULL || connInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    if (GetActiveAuthConnInfo(uuid, CONNECT_TCP, connInfo) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "select wifi auth.");
        return SOFTBUS_OK;
    }
    if (GetActiveAuthConnInfo(uuid, CONNECT_BR, connInfo) == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "select br auth.");
        return SOFTBUS_OK;
    }
    if (GetActiveAuthConnInfo(uuid, CONNECT_BLE, connInfo) == SOFTBUS_OK) {
        ConnectOption option = {0};
        if (ConvertAuthConnInfoToOption(connInfo, &option) == SOFTBUS_OK &&
            CheckActiveConnection(&option)) {
            SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "select ble auth.");
            return SOFTBUS_OK;
        }
    }
    SoftBusLog(SOFTBUS_LOG_AUTH, SOFTBUS_LOG_INFO, "active auth not found by uuid.");
    return SOFTBUS_ERR;
}

bool IsWiFiLink(const AuthManager *auth)
{
    if (auth == NULL) {
        return false;
    }
    if (auth->option.type == CONNECT_TCP && !auth->isAuthP2p) {
        return true;
    }
    return false;
}

bool IsP2PLink(const AuthManager *auth)
{
    if (auth == NULL) {
        return false;
    }
    if (auth->option.type == CONNECT_TCP && auth->isAuthP2p) {
        return true;
    }
    return false;
}