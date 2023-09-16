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
#include "wifi_direct_negotiator.h"

#include "securec.h"
#include "wifi_direct_negotiator_mock.h"
#include "softbus_error_code.h"
static void HandleSuccess(struct NegotiateMessage *msg)
{
    return WifiDirectNegotiatorMock::GetMock()->HandleSuccess(msg);
}

static int32_t PostData(struct NegotiateMessage *msg)
{
    return WifiDirectNegotiatorMock::GetMock()->PostData(msg);
}

static int32_t HandleMessageFromProcessor(struct NegotiateMessage *msg, enum NegotiateStateType nextState)
{
    return WifiDirectNegotiatorMock::GetMock()->HandleMessageFromProcessor(msg, nextState);
}

static struct WifiDirectNegotiator g_negotiator = {
    .handleMessageFromProcessor = HandleMessageFromProcessor,
    .postData = PostData,
    .handleSuccess = HandleSuccess,
};

struct WifiDirectNegotiator* GetWifiDirectNegotiator(void)
{
    return &g_negotiator;
}

WifiDirectNegotiatorMock* WifiDirectNegotiatorMock::mock = nullptr;

WifiDirectNegotiatorMock::WifiDirectNegotiatorMock()
{
    mock = this;
}

WifiDirectNegotiatorMock::~WifiDirectNegotiatorMock()
{
    mock = nullptr;
}