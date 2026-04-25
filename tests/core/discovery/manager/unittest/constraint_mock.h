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

#ifndef DSOFTBUS_CONSTRAINT_MOCK_H
#define DSOFTBUS_CONSTRAINT_MOCK_H

#include "gmock/gmock.h"
#include "bus_center_event.h"

class ConstraintMockInterface {
public:
    virtual ~ConstraintMockInterface() = default;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual bool LnnIsOsAccountConstraint(void) = 0;
};

class ConstraintMock : ConstraintMockInterface {
public:
    static ConstraintMock *Get();
    static void TriggerConstraintEvent(bool isConstraint);

    ConstraintMock();
    ~ConstraintMock() override;
    void SetupStub();

    MOCK_METHOD(int32_t, LnnRegisterEventHandler, (LnnEventType event, LnnEventHandler handler), (override));
    MOCK_METHOD(void, LnnUnregisterEventHandler, (LnnEventType event, LnnEventHandler handler), (override));
    MOCK_METHOD(bool, LnnIsOsAccountConstraint, (), (override));

private:
    static inline ConstraintMock *instance_;
    static inline ConstraintMock *previousInstance_ = nullptr;
    static inline LnnEventHandler registeredHandler_ = nullptr;
};

#endif
