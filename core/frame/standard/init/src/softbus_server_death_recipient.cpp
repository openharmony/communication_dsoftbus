/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_server_death_recipient.h"

#include "comm_log.h"
#include "softbus_client_info_manager.h"
#include "softbus_server_frame.h"

namespace OHOS {
void SoftBusDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    std::string pkgName;
    int32_t pid = 0;
    SoftbusClientInfoManager::GetInstance().SoftbusRemoveService(remote.promote(), pkgName, &pid);
    COMM_LOGI(COMM_SVC, "client service died, remove it from softbus server. pkgName=%{public}s", pkgName.c_str());
    ClientDeathCallback(pkgName.c_str(), pid);
}
}  // namespace OHOS