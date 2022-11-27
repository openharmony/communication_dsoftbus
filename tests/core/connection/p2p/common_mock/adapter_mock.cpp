/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "adapter_mock.h"
#include <atomic>
#include "softbus_error_code.h"
#include "p2plink_device.h"

/* implement related global function of Adapter */
int32_t P2pLinkGetBaseMacAddress(char *mac, int32_t len)
{
    return AdapterMock::GetMock()->P2pLinkGetBaseMacAddress(mac, len);
}

/* definition for class AdapterMock */
AdapterMock::AdapterMock()
{
    mock.store(this);
}

AdapterMock::~AdapterMock()
{
    mock.store(nullptr);
}

int32_t AdapterMock::ActionOfP2pLinkGetBaseMacAddress(char *mac, int32_t len)
{
    mac[0] = 't';
    mac[1] = '\0';
    return SOFTBUS_OK;
}

void AdapterMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, P2pLinkGetBaseMacAddress).WillRepeatedly(AdapterMock::ActionOfP2pLinkGetBaseMacAddress);
}