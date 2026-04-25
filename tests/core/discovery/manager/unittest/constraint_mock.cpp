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

#include "constraint_mock.h"
#include "bus_center_event_struct.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_error_code.h"

using testing::Return;

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return ConstraintMock::Get()->LnnRegisterEventHandler(event, handler);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    ConstraintMock::Get()->LnnUnregisterEventHandler(event, handler);
}

bool LnnIsOsAccountConstraint(void)
{
    return ConstraintMock::Get()->LnnIsOsAccountConstraint();
}

ConstraintMock *ConstraintMock::Get()
{
    return instance_;
}

ConstraintMock::ConstraintMock()
{
    previousInstance_ = instance_;
    instance_ = this;
}

ConstraintMock::~ConstraintMock()
{
    instance_ = previousInstance_;
    previousInstance_ = nullptr;
}

void ConstraintMock::TriggerConstraintEvent(bool isConstraint)
{
    if (registeredHandler_ != nullptr) {
        LnnConstraintChangeEvent event;
        event.basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
        event.isConstraint = isConstraint;
        registeredHandler_((const LnnEventBasicInfo *)&event);
    }
}

void ConstraintMock::SetupStub()
{
    EXPECT_CALL(*this, LnnRegisterEventHandler(testing::_, testing::_))
        .WillRepeatedly([](LnnEventType event, LnnEventHandler handler) {
            (void)event;
            registeredHandler_ = handler;
            return SOFTBUS_OK;
        });
    EXPECT_CALL(*this, LnnUnregisterEventHandler(testing::_, testing::_)).WillRepeatedly([]() {
        registeredHandler_ = nullptr;
    });
    EXPECT_CALL(*this, LnnIsOsAccountConstraint()).WillRepeatedly(Return(false));
}
