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

#include "trans_client_proxy.h"

#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_server_data.h"
#include "trans_client_proxy_standard.h"

using namespace OHOS;

static sptr<TransClientProxy> GetClientProxy(const char *pkgName)
{
    sptr<IRemoteObject> clientObject = SoftBusServerData::GetInstance().GetSoftbusClientProxy(pkgName);
    sptr<TransClientProxy> clientProxy = new (std::nothrow) TransClientProxy(clientObject);
    return clientProxy;
}

int32_t ClientIpcOnChannelOpened(const char *pkgName, const char *sessionName, const ChannelInfo *channel)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    int ret = clientProxy->OnChannelOpened(sessionName, channel);
    return ret;
}

int32_t ClientIpcOnChannelOpenFailed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelOpenFailed(channelId, channelType);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelClosed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelClosed(channelId, channelType);
    return SOFTBUS_OK;
}

int32_t ClientIpcOnChannelMsgReceived(const char *pkgName, int32_t channelId, int32_t channelType, const void *data,
                                      unsigned int len, int32_t type)
{
    sptr<TransClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "softbus client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    clientProxy->OnChannelMsgReceived(channelId, channelType, data, len, type);
    return SOFTBUS_OK;
}