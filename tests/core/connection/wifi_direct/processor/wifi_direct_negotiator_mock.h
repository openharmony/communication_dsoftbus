/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef WIFI_DIRECT_NEGOTIATOR_MOCK_H
#define WIFI_DIRECT_NEGOTIATOR_MOCK_H
#include <gmock/gmock.h>

#include "negotiate_state/negotiate_state.h"

class WifiDirectNegotiatorInterface {
    virtual int32_t HandleMessageFromProcessor(struct NegotiateMessage *msg, enum NegotiateStateType nextState) = 0;
    virtual int32_t PostData(struct NegotiateMessage *msg) = 0;
    virtual void HandleSuccess(struct NegotiateMessage *msg) = 0;
};

class WifiDirectNegotiatorMock : public WifiDirectNegotiatorInterface {
public:
    static WifiDirectNegotiatorMock* GetMock()
    {
        return mock;
    }

    WifiDirectNegotiatorMock();
    ~WifiDirectNegotiatorMock();
    MOCK_METHOD(int32_t, HandleMessageFromProcessor, (struct NegotiateMessage *msg, 
                                    enum NegotiateStateType nextState), (override));
    MOCK_METHOD(int32_t, PostData, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(void, HandleSuccess, (struct NegotiateMessage *msg), (override));

private:
    static WifiDirectNegotiatorMock *mock;
};

#endif