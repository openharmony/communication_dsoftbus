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

#include "softbus_log.h"
#include "softbus_server.h"

namespace OHOS {
void SoftBusDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    LOG_INFO("service died, remove the proxy object");
    SoftBusServer::GetInstance()->SoftbusRemoveService(remote.promote());
    LOG_INFO("recv death notice success");
}
}  // namespace OHOS