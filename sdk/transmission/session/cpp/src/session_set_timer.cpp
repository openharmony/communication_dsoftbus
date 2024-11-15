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

#include <string>

#include "session_set_timer.h"
#include "xcollie/xcollie.h"

constexpr int INVALID_ID = -1;

int SetTimer(const char *name, unsigned int timeout)
{
    if (name == nullptr) {
        return INVALID_ID;
    }
    std::string timerName = std::string(name);
    int id = OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(timerName, timeout, nullptr, nullptr,
        OHOS::HiviewDFX::XCOLLIE_FLAG_LOG);
    return id;
}

void CancelTimer(int id)
{
    if (id == INVALID_ID) {
        return;
    }
    OHOS::HiviewDFX::XCollie::GetInstance().CancelTimer(id);
}
