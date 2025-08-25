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

#ifndef LNN_SA_STATUS_MONITER_MOCK_H
#define LNN_SA_STATUS_MONITER_MOCK_H

#include "lnn_sa_status_monitor.h"
#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "lnn_network_info.h"
#include "message_handler.h"
#include "refbase.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
class LnnSaStatusMonitorInterface {
public:
    LnnSaStatusMonitorInterface() { };
    virtual ~LnnSaStatusMonitorInterface() { };

public:
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
};

class LnnSaStatusMonitorInterfaceMock : public LnnSaStatusMonitorInterface {
public:
    LnnSaStatusMonitorInterfaceMock();
    ~LnnSaStatusMonitorInterfaceMock() override;

    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
};
} // namespace OHOS
#endif