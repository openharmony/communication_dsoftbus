/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_MOCK_H
#define SOFTBUS_ADAPTER_MOCK_H

#include <cstdint>
#include <gmock/gmock.h>
#include "softbus_adapter_define.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_adapter_thread.h"

class SoftbusAdapterInterface {
public:
    virtual int32_t SoftBusSocketSetOpt(
            int32_t socketFd, int32_t level, int32_t optName,  const void *optVal, int32_t optLen) = 0;
    virtual int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr) = 0;
    virtual int32_t SoftBusGetTime(SoftBusSysTime *sysTime) = 0;
    virtual int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time) = 0;
};

class SoftbusAdapterMock : public SoftbusAdapterInterface {
public:
    static SoftbusAdapterMock *GetMock()
    {
        return gmock_.load();
    }

    SoftbusAdapterMock();
    ~SoftbusAdapterMock();

    MOCK_METHOD(int32_t, SoftBusSocketGetPeerName, (int32_t socketFd, SoftBusSockAddr *addr), (override));
    MOCK_METHOD(int32_t, SoftBusSocketSetOpt,
        (int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen), (override));
    MOCK_METHOD(int32_t, SoftBusGetTime, (SoftBusSysTime *sysTime), (override));
    MOCK_METHOD(int32_t, SoftBusCondWait, (SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time), (override));

    static int32_t ActionOfSoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr);
   
private:
    static inline std::atomic<SoftbusAdapterMock *> gmock_ = nullptr;
};
#endif