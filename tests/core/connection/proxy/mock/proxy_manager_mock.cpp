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
#include "proxy_manager_mock.h"

#include <string>
#include <sstream>
#include <thread>
#include "securec.h"
#include "conn_log.h"

static SoftBusBtStateListener *g_btStateListener = nullptr;
static ProxyListener g_hfpListener = { 0 };

extern "C" {
int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId)
{
    return ProxyChannelMock::GetMock()->SoftBusAddBtStateListener(listener, listenerId);
}

SppSocketDriver *InitSppSocketDriver(void)
{
    return ProxyChannelMock::GetMock()->InitSppSocketDriver();
}

int32_t RegisterHfpListener(const ProxyListener listener)
{
    return ProxyChannelMock::GetMock()->RegisterHfpListener(listener);
}

void InitProxyChannelManagerWrapper(void)
{
    return ProxyChannelMock::GetMock()->InitProxyChannelManagerWrapper();
}

bool IsPairedDevice(const char *addr, bool isRealMac, bool *isSupportHfp)
{
    return ProxyChannelMock::GetMock()->IsPairedDevice(addr, isRealMac, isSupportHfp);
}

int32_t GetRealMac(char *realAddr, uint32_t realAddrLen, const char *hashAddr)
{
    return ProxyChannelMock::GetMock()->GetRealMac(realAddr, realAddrLen, hashAddr);
}
}

/* definition for class ProxyChannelMock */
ProxyChannelMock::ProxyChannelMock()
{
    mock.store(this);
}

ProxyChannelMock::~ProxyChannelMock()
{
    mock.store(nullptr);
}

int32_t ProxyChannelMock::ActionOfAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId)
{
    *listenerId = 1;
    g_btStateListener = (SoftBusBtStateListener *)listener;
    return SOFTBUS_OK;
}

int32_t ProxyChannelMock::ActionOfRegisterHfpListener(const ProxyListener listener)
{
    g_hfpListener = listener;
    return SOFTBUS_OK;
}

int32_t ProxyChannelMock::ActionOfRead(int32_t clientFd, uint8_t *buf, const int32_t len)
{
    uint8_t data[] = { 0x02, 0x01, 0x02, 0x15, 0x16 };
    if (memcpy_s(buf, len, data, sizeof(data)) != EOK) {
        CONN_LOGI(CONN_PROXY, "memcpy_s, err");
        return -1;
    }
    sleep(1);
    CONN_LOGI(CONN_PROXY, "read data len=%{public}zu", sizeof(data));
    return static_cast<int32_t>(sizeof(data));
}

int32_t ProxyChannelMock::ActionOfRead1(int32_t clientFd, uint8_t *buf, const int32_t len)
{
    sleep(READ_SLEEP_TIME);
    return BR_READ_SOCKET_CLOSED;
}

int32_t ProxyChannelMock::ActionOfConnect(const char *uuid, const BT_ADDR mac, void *connectCallback)
{
    sleep(1);
    return UNDERLAYER_HANDLE;
}

int32_t ProxyChannelMock::ActionOfConnect1(const char *uuid, const BT_ADDR mac, void *connectCallback)
{
    SoftBusFree(GetProxyChannelManager()->proxyChannelRequestInfo);
    GetProxyChannelManager()->proxyChannelRequestInfo = nullptr;
    sleep(1);
    return UNDERLAYER_HANDLE;
}

int32_t ProxyChannelMock::ActionOfConnect2(const char *uuid, const BT_ADDR mac, void *connectCallback)
{
    SoftBusFree(GetProxyChannelManager()->proxyChannelRequestInfo);
    GetProxyChannelManager()->proxyChannelRequestInfo = nullptr;
    ProxyConnectInfo *connectInfo = (ProxyConnectInfo *)SoftBusCalloc(sizeof(ProxyConnectInfo));
    if (connectInfo == nullptr || strcpy_s(connectInfo->brMac, BT_MAC_LEN, "00:22:33:44:55:66") != EOK) {
        SoftBusFree(connectInfo);
    }
    GetProxyChannelManager()->proxyChannelRequestInfo = connectInfo;
    sleep(1);
    return UNDERLAYER_HANDLE;
}

bool ProxyChannelMock::ActionOfIsPairedDevice(const char *addr,  bool isRealMac, bool *isSupportHfp)
{
    if (isSupportHfp != nullptr) {
        *isSupportHfp = true;
    }
    return true;
}

int32_t SoftBusGetBrState(void)
{
    return BR_ENABLE;
}

void ProxyChannelMock::InjectHfpConnectionChanged(std::string addr, int32_t state)
{
    if (g_hfpListener != nullptr) {
        g_hfpListener(addr.c_str(), state);
    }
}

void ProxyChannelMock::InjectBtAclStateChanged(
    int32_t listenerId, const SoftBusBtAddr *btAddr, int32_t aclState, int32_t hciReason)
{
    if (g_btStateListener->OnBtAclStateChanged != nullptr) {
        g_btStateListener->OnBtAclStateChanged(listenerId, btAddr, aclState, hciReason);
    }
}

void ProxyChannelMock::InjectBtStateChanged(int listenerId, int state)
{
    if (g_btStateListener->OnBtStateChanged != nullptr) {
        g_btStateListener->OnBtStateChanged(listenerId, state);
    }
}

static int32_t Connect(const char *uuid, const BT_ADDR mac, void *connectCallback)
{
    return ProxyChannelMock::GetMock()->Connect(uuid, mac, connectCallback);
}

static int32_t DisConnect(int32_t clientFd)
{
    CONN_LOGI(CONN_PROXY, "[DisConnect, and clientFd=%{public}d]", clientFd);
    return SOFTBUS_OK;
}

static int32_t Write(int32_t clientFd, const uint8_t *buf, const int32_t len)
{
    return ProxyChannelMock::GetMock()->Write(clientFd, buf, len);
}

static int32_t Read(int32_t clientFd, uint8_t *buf, const int32_t len)
{
    return ProxyChannelMock::GetMock()->Read(clientFd, buf, len);
}

static SppSocketDriver g_sppSocketDriver = {
    .Connect = Connect,
    .DisConnect = DisConnect,
    .Write = Write,
    .Read = Read,
};

SppSocketDriver *ProxyChannelMock::ActionOfInitSppSocketDriver(void)
{
    return &g_sppSocketDriver;
}

int32_t SoftBusRemoveBtStateListener(int32_t listenerId)
{
    (void)listenerId;
    return SOFTBUS_OK;
}