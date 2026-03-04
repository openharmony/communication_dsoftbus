/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "auth_interface.h"
#include "auth_manager.h"
#include "wifi_direct_manager.h"
#include "lnn_distributed_net_ledger.h"

int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen)
{
    (void)srcId;
    (void)srcIdType;
    (void)dstIdType;
    if (dstIdBuf != NULL && dstIdBufLen > 1) {
        dstIdBuf[0] = 'n';
        dstIdBuf[1] = '\0';
    }
    return 0;
}

void AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle)
{
    (void)uuid;
    (void)type;
    if (authHandle != NULL) {
        authHandle->authId = 1;
    }
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    (void)authHandle;
    (void)dataInfo;
    return 0;
}

static AuthManager g_testAuthMgr;
AuthManager *GetAuthManagerByAuthId(int64_t authId)
{
    (void)authId;
    g_testAuthMgr.udid[0] = 'd';
    return &g_testAuthMgr;
}

void DelAuthManager(AuthManager *auth, int32_t type)
{
    (void)auth;
    (void)type;
}

void DelDupAuthManager(AuthManager *auth)
{
    (void)auth;
}

static AuthTransListener g_authTransListenerMock;
int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    if (listener == NULL) {
        return -1;
    }
    g_authTransListenerMock = *listener;
    return 0;
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    (void)udid;
    if (buf != NULL && len > 1) {
        buf[0] = 'n';
        buf[1] = '\0';
    }
    return 0;
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    (void)uuid;
    if (buf != NULL && len > 1) {
        buf[0] = 'n';
        buf[1] = '\0';
    }
    return 0;
}

static struct WifiDirectStatusListener g_wifiDirectStatusListenerMock;
static void RegisterStatusListenerMock(struct WifiDirectStatusListener *listener)
{
    if (listener == NULL) {
        return;
    }
    g_wifiDirectStatusListenerMock = *listener;
}

static struct WifiDirectManager g_managerMock = {
    .registerStatusListener = RegisterStatusListenerMock,
};

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return &g_managerMock;
}

void VirlinkTestRecv(uint8_t *data, uint32_t dataLen)
{
    if (g_authTransListenerMock.onDataReceived != NULL) {
        AuthHandle h = { .authId = 1, };
        AuthTransData d = { .data = data, .len = dataLen };
        g_authTransListenerMock.onDataReceived(h, &d);
    }
}

void VirlinkTestAuthClose(void)
{
    if (g_authTransListenerMock.onDisconnected != NULL) {
        AuthHandle h = { .authId = 1, };
        g_authTransListenerMock.onDisconnected(h);
    }
}

void VirlinkTestDeviceOnline(const char *remoteMac, const char *remoteIp,
    const char *remoteUuid, bool isSource)
{
    if (g_wifiDirectStatusListenerMock.onDeviceOnLine != NULL) {
        g_wifiDirectStatusListenerMock.onDeviceOnLine(remoteMac, remoteIp, remoteUuid, isSource);
    }
}

void VirlinkTestDeviceOffline(const char *remoteMac, const char *remoteIp,
    const char *remoteUuid, const char *localIp)
{
    if (g_wifiDirectStatusListenerMock.onDeviceOffLine != NULL) {
        g_wifiDirectStatusListenerMock.onDeviceOffLine(remoteMac, remoteIp, remoteUuid, localIp);
    }
}