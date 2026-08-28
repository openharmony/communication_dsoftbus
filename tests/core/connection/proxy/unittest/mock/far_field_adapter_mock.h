/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FAR_FIELD_ADAPTER_MOCK_H
#define FAR_FIELD_ADAPTER_MOCK_H

#include <atomic>
#include <gmock/gmock.h>

#include "far_field_proxy_adapter.h"
#include "far_field_proxy_manager.h"
#include "conn_log.h"
#include "softbus_error_code.h"

class FarFieldAdapterInterface {
public:
    virtual int32_t Init(void) = 0;
    virtual void Deinit(void) = 0;
    virtual bool IsDeviceSupport(const P2PDeviceInfo *device) = 0;
    virtual int32_t RegisterCallback(const FarFieldCallbackSt *callback) = 0;
    virtual int32_t OpenP2P(const P2PDeviceInfo *device) = 0;
    virtual int32_t CloseP2P(const P2PDeviceInfo *device) = 0;
    virtual P2PState GetP2PState(const P2PDeviceInfo *device) = 0;
    virtual int32_t SendMsg(const P2PDeviceInfo *device, const uint8_t *data, uint32_t len) = 0;
    virtual int32_t Refresh(const P2PDeviceInfo *device) = 0;
    virtual int32_t ManagerInit(const FarFieldCallbackSt *callback) = 0;
    virtual void ManagerDeinit(void) = 0;
};

class FarFieldAdapterMock : public FarFieldAdapterInterface {
public:
    static FarFieldAdapterMock *GetMock()
    {
        return mock.load();
    }

    FarFieldAdapterMock();
    ~FarFieldAdapterMock();

    MOCK_METHOD(int32_t, Init, (), (override));
    MOCK_METHOD(void, Deinit, (), (override));
    MOCK_METHOD(bool, IsDeviceSupport, (const P2PDeviceInfo * device), (override));
    MOCK_METHOD(int32_t, RegisterCallback, (const FarFieldCallbackSt * callback), (override));
    MOCK_METHOD(int32_t, OpenP2P, (const P2PDeviceInfo * device), (override));
    MOCK_METHOD(int32_t, CloseP2P, (const P2PDeviceInfo * device), (override));
    MOCK_METHOD(P2PState, GetP2PState, (const P2PDeviceInfo * device), (override));
    MOCK_METHOD(int32_t, SendMsg,
        (const P2PDeviceInfo * device, const uint8_t *data, uint32_t len), (override));
    MOCK_METHOD(int32_t, Refresh, (const P2PDeviceInfo * device), (override));
    MOCK_METHOD(int32_t, ManagerInit, (const FarFieldCallbackSt * callback), (override));
    MOCK_METHOD(void, ManagerDeinit, (), (override));

    static int32_t ActionOfManagerInit(const FarFieldCallbackSt *callback);
    static void InjectP2PStateChanged(const P2PDeviceInfo *device, P2PState state, int32_t reason);
    static void InjectRemoteEvent(const P2PDeviceInfo *device, RemoteEvent event);
    static void InjectRecvP2PMsg(const P2PDeviceInfo *device, const uint8_t *msgBody, uint32_t len);

private:
    static inline std::atomic<FarFieldAdapterMock *> mock = nullptr;
    static inline FarFieldCallbackSt g_capturedCallback = {0};
};

#endif // FAR_FIELD_ADAPTER_MOCK_H
