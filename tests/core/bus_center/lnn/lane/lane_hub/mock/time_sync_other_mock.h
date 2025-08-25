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

#ifndef TIME_SYNC_OTHER_MOCK_H
#define TIME_SYNC_OTHER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event_struct.h"
#include "bus_center_manager_struct.h"
#include "lnn_map_struct.h"
#include "lnn_time_sync_impl_struct.h"
#include "message_handler.h"
#include "softbus_bus_center.h"

namespace OHOS {
class TimeSyncOtherDepsInterface {
public:
    TimeSyncOtherDepsInterface() {};
    virtual ~TimeSyncOtherDepsInterface() {};

    virtual int32_t LnnStartTimeSyncImplPacked(const char *targetNetworkId, TimeSyncAccuracy accuracy,
        TimeSyncPeriod period, const TimeSyncImplCallback *callback) = 0;
    virtual int32_t LnnStopTimeSyncImplPacked(const char *targetNetworkId) = 0;
    virtual SoftBusLooper *GetLooper(int32_t looper) = 0;
    virtual void LnnNotifyTimeSyncResult(const char *pkgName, int32_t pid,
        const TimeSyncResultInfo *info, int32_t retCode) = 0;
    virtual int32_t LnnTimeSyncImplInitPacked(void) = 0;
    virtual void LnnTimeSyncImplDeinitPacked(void) = 0;
    virtual void *LnnMapGet(const Map *map, const char *key) = 0;
};

class TimeSyncOtherDepsInterfaceMock : public TimeSyncOtherDepsInterface {
public:
    TimeSyncOtherDepsInterfaceMock();
    ~TimeSyncOtherDepsInterfaceMock() override;

    MOCK_METHOD4(LnnStartTimeSyncImplPacked, int32_t (const char*, TimeSyncAccuracy, TimeSyncPeriod,
        const TimeSyncImplCallback *));
    MOCK_METHOD1(LnnStopTimeSyncImplPacked, int32_t (const char *));
    MOCK_METHOD1(GetLooper, SoftBusLooper * (int));
    MOCK_METHOD4(LnnNotifyTimeSyncResult, void(const char *, int32_t, const TimeSyncResultInfo *, int32_t));
    MOCK_METHOD0(LnnTimeSyncImplInitPacked, int32_t (void));
    MOCK_METHOD0(LnnTimeSyncImplDeinitPacked, void (void));
    MOCK_METHOD2(LnnMapGet, void * (const Map *map, const char *key));
};

extern "C" {
    int32_t LnnStartTimeSyncImplPacked(const char *targetNetworkId, TimeSyncAccuracy accuracy,
        TimeSyncPeriod period, const TimeSyncImplCallback *callback);
    int32_t LnnStopTimeSyncImplPacked(const char *targetNetworkId);
    SoftBusLooper *GetLooper(int32_t looper);
    void LnnNotifyTimeSyncResult(const char *pkgName, int32_t pid,
        const TimeSyncResultInfo *info, int32_t retCode);
    int32_t LnnTimeSyncImplInitPacked(void);
    void LnnTimeSyncImplDeinitPacked(void);
    void *LnnMapGet(const Map *map, const char *key);
}
} // namespace OHOS
#endif // TIME_SYNC_OTHER_MOCK_H