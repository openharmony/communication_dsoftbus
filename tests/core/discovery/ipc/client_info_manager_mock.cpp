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

#include "client_info_manager_mock.h"
#include "remote_object_mock.h"

namespace OHOS {
SoftbusClientInfoManager &SoftbusClientInfoManager::GetInstance()
{
    static SoftbusClientInfoManager instance;
    return instance;
}

sptr<IRemoteObject> SoftbusClientInfoManager::GetSoftbusClientProxy(const std::string &pkgName)
{
    return ClientInfoManagerMock::Get()->GetSoftbusClientProxy(pkgName);
}

ClientInfoManagerMock* ClientInfoManagerMock::Get()
{
    return instance_;
}

ClientInfoManagerMock::ClientInfoManagerMock()
{
    instance_ = this;
}

ClientInfoManagerMock::~ClientInfoManagerMock()
{
    instance_ = nullptr;
}

void ClientInfoManagerMock::SetupStub()
{
    EXPECT_CALL(*this, GetSoftbusClientProxy).WillRepeatedly(ActionOfGetSoftBusClientProxy);
}

sptr<IRemoteObject> ClientInfoManagerMock::ActionOfGetSoftBusClientProxy(const std::string &pkgName)
{
    return RemoteObjectMock::Get();
}
}