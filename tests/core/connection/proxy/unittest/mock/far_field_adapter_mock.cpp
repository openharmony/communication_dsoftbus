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

#include "far_field_adapter_mock.h"

extern "C" {
int32_t FarFieldAdapterInit(void)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return FAR_FIELD_ADAPTER_NOT_INITIALIZED;
    }
    return mocker->Init();
}

void FarFieldAdapterDeinit(void)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return;
    }
    mocker->Deinit();
}

bool FarFieldAdapterIsDeviceSupport(const P2PDeviceInfo *device)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return false;
    }
    return mocker->IsDeviceSupport(device);
}

int32_t FarFieldAdapterRegisterCallback(const FarFieldCallbackSt *callback)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return SOFTBUS_ERR;
    }
    return mocker->RegisterCallback(callback);
}

int32_t FarFieldAdapterOpenP2P(const P2PDeviceInfo *device)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return SOFTBUS_ERR;
    }
    return mocker->OpenP2P(device);
}

int32_t FarFieldAdapterCloseP2P(const P2PDeviceInfo *device)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return SOFTBUS_ERR;
    }
    return mocker->CloseP2P(device);
}

P2PState FarFieldAdapterGetP2PState(const P2PDeviceInfo *device)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return P2P_STATE_INVALID;
    }
    return mocker->GetP2PState(device);
}

int32_t FarFieldAdapterSendMsg(const P2PDeviceInfo *device, const uint8_t *data, uint32_t len)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return SOFTBUS_ERR;
    }
    return mocker->SendMsg(device, data, len);
}

int32_t FarFieldAdapterRefresh(const P2PDeviceInfo *device)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return SOFTBUS_ERR;
    }
    return mocker->Refresh(device);
}

int32_t FarFieldAdapterManagerInit(const FarFieldCallbackSt *callback)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return SOFTBUS_ERR;
    }
    return mocker->ManagerInit(callback);
}

void FarFieldAdapterManagerDeinit(void)
{
    auto mocker = FarFieldAdapterMock::GetMock();
    if (mocker == nullptr) {
        return;
    }
    mocker->ManagerDeinit();
}
}

FarFieldAdapterMock::FarFieldAdapterMock()
{
    mock.store(this);
}

FarFieldAdapterMock::~FarFieldAdapterMock()
{
    mock.store(nullptr);
}

int32_t FarFieldAdapterMock::ActionOfManagerInit(const FarFieldCallbackSt *callback)
{
    if (callback != nullptr) {
        g_capturedCallback = *callback;
    }
    return SOFTBUS_OK;
}

void FarFieldAdapterMock::InjectP2PStateChanged(const P2PDeviceInfo *device, P2PState state, int32_t reason)
{
    if (g_capturedCallback.p2pStateCallback != nullptr) {
        g_capturedCallback.p2pStateCallback(device, state, reason);
    }
}

void FarFieldAdapterMock::InjectRemoteEvent(const P2PDeviceInfo *device, RemoteEvent event)
{
    if (g_capturedCallback.remoteEventCallback != nullptr) {
        g_capturedCallback.remoteEventCallback(device, event);
    }
}

void FarFieldAdapterMock::InjectRecvP2PMsg(const P2PDeviceInfo *device, const uint8_t *msgBody, uint32_t len)
{
    if (g_capturedCallback.recvP2PMsgCallback != nullptr) {
        g_capturedCallback.recvP2PMsgCallback(device, msgBody, len);
    }
}
