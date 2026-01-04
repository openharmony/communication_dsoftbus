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

#ifndef PROXY_CHANNEL_MOCK_H
#define PROXY_CHANNEL_MOCK_H

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <gmock/gmock.h>

#include "common_list.h"
#include "conn_log.h"
#include "message_handler.h"
#include "proxy_manager.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_utils.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_conn_common.h"
#include "proxy_connection.h"
#include "proxy_observer.h"
#include "wrapper_br_interface.h"

#define READ_SLEEP_TIME 5
#define UNDERLAYER_HANDLE 1
#define CONNECT_TIMEOUT 1000
#define CONNECT_TIMEOUT1 500
#define CONNECT_SLEEP_TIME 2

#define CONNECT_SLEEP_TIME_MS 500
#define CONNECT_SLEEP_TIME_MS1 1000

class ProxyChannelInterface {
public:
    virtual int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId) = 0;
    virtual int32_t RegisterHfpListener(const ProxyListener listener) = 0;
    virtual void InitProxyChannelManagerWrapper(void) = 0;
    virtual SppSocketDriver *InitSppSocketDriver(void) = 0;
    virtual int32_t Connect(const char *uuid, const BT_ADDR mac, void *connectCallback) = 0;
    virtual int32_t Write(int32_t clientFd, const uint8_t *buf, const int32_t len) = 0;
    virtual int32_t Read(int32_t clientFd, uint8_t *buf, const int32_t len) = 0;
    virtual bool IsPairedDevice(const char *addr, bool isRealMac, bool *isSupportHfp) = 0;
    virtual int32_t GetRealMac(char *realAddr, uint32_t realAddrLen, const char *hashAddr) = 0;
};
class ProxyChannelMock : public ProxyChannelInterface {
public:
    static ProxyChannelMock *GetMock()
    {
        return mock.load();
    }

    ProxyChannelMock();
    ~ProxyChannelMock();
    MOCK_METHOD(int, SoftBusAddBtStateListener, (const SoftBusBtStateListener * listener, int *listenerId), (override));
    MOCK_METHOD(int32_t, RegisterHfpListener, (const ProxyListener listener), (override));
    MOCK_METHOD(void, InitProxyChannelManagerWrapper, (), (override));

    MOCK_METHOD(int32_t, Connect, (const char *uuid, const BT_ADDR mac, void *connectCallback), (override));
    MOCK_METHOD(int32_t, Write, (int32_t clientFd, const uint8_t *buf, const int32_t len), (override));
    MOCK_METHOD(int32_t, Read, (int32_t clientFd, uint8_t *buf, const int32_t len), (override));
    MOCK_METHOD(bool, IsPairedDevice, (const char *addr,  bool isRealMac, bool *isSupportHfp), (override));
    MOCK_METHOD(int32_t, GetRealMac, (char *realAddr, uint32_t realAddrLen, const char *hashAddr), (override));

    static int32_t ActionOfAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId);
    static int32_t ActionOfRegisterHfpListener(const ProxyListener listener);
    MOCK_METHOD(SppSocketDriver *, InitSppSocketDriver, (), (override));
    static SppSocketDriver *ActionOfInitSppSocketDriver();
    static int32_t ActionOfRead(int32_t clientFd, uint8_t *buf, const int32_t len);
    static int32_t ActionOfRead1(int32_t clientFd, uint8_t *buf, const int32_t len);
    static int32_t ActionOfConnect(const char *uuid, const BT_ADDR mac, void *connectCallback);
    static int32_t ActionOfConnect1(const char *uuid, const BT_ADDR mac, void *connectCallback);
    static int32_t ActionOfConnect2(const char *uuid, const BT_ADDR mac, void *connectCallback);
    static bool ActionOfIsPairedDevice(const char *addr, bool isRealMac, bool *isSupportHfp);
    static void InjectHfpConnectionChanged(std::string addr, int32_t state);
    static void InjectBtAclStateChanged(
        int32_t listenerId, const SoftBusBtAddr *btAddr, int32_t aclState, int32_t hciReason);
    static void InjectBtStateChanged(int listenerId, int state);
    int32_t SoftBusRemoveBtStateListener(int32_t listenerId);
private:
    static inline std::atomic<ProxyChannelMock *> mock = nullptr;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::mutex scanMutex_;
    std::condition_variable scanCv_;
};
#endif