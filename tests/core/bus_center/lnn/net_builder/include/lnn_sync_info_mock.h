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

#ifndef LNN_SYNC_INFO_MOCK_H
#define LNN_SYNC_INFO_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_sync_info_manager.h"

namespace OHOS {
class LnnSyncInfoInterface {
public:
    LnnSyncInfoInterface() {};
    virtual ~LnnSyncInfoInterface() {};
    virtual int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId,
    const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete) = 0;
};

class LnnSyncInfoInterfaceMock : public LnnSyncInfoInterface {
public:
    LnnSyncInfoInterfaceMock();
    ~LnnSyncInfoInterfaceMock() override;
    MOCK_METHOD5(LnnSendSyncInfoMsg, int32_t (LnnSyncInfoType, const char *, const uint8_t *,
        uint32_t, LnnSyncInfoMsgComplete));
};
} // namespace OHOS
#endif // LNN_SYNC_INFO_MOCK_H