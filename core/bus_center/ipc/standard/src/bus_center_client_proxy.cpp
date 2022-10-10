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

#include "bus_center_client_proxy.h"

#include "bus_center_client_proxy_standard.h"
#include "softbus_client_info_manager.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_permission.h"

using namespace OHOS;

static sptr<BusCenterClientProxy> GetClientProxy(const char *pkgName)
{
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName);
    sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(clientObject);
    return clientProxy;
}

int32_t ClientOnJoinLNNResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnJoinLNNResult(addr, addrTypeLen, networkId, retCode);
}

int32_t ClientOnJoinMetaNodeResult(const char *pkgName, void *addr, uint32_t addrTypeLen,
    const char *networkId, int32_t retCode)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnJoinMetaNodeResult(addr, addrTypeLen, networkId, retCode);
}

int32_t ClientOnLeaveLNNResult(const char *pkgName, const char *networkId, int32_t retCode)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnLeaveLNNResult(networkId, retCode);
}

int32_t ClientOnLeaveMetaNodeResult(const char *pkgName, const char *networkId, int32_t retCode)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!\n");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnLeaveMetaNodeResult(networkId, retCode);
}

int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    std::map<std::string, sptr<IRemoteObject>> proxyMap;
    SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxyMap(proxyMap);
    for (auto proxy : proxyMap) {
        sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);
        clientProxy->OnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
    }
    return SOFTBUS_OK;
}

int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    std::map<std::string, sptr<IRemoteObject>> proxyMap;
    SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxyMap(proxyMap);
    for (auto proxy : proxyMap) {
        sptr<BusCenterClientProxy> clientProxy = new (std::nothrow) BusCenterClientProxy(proxy.second);
        clientProxy->OnNodeBasicInfoChanged(info, infoTypeLen, type);
    }
    return SOFTBUS_OK;
}

int32_t ClientOnTimeSyncResult(const char *pkgName, const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    return clientProxy->OnTimeSyncResult(info, infoTypeLen, retCode);
}

int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t publishId, int32_t reason)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnPublishLNNResult(publishId, reason);
    return SOFTBUS_OK;
}

int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t refreshId, int32_t reason)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnRefreshLNNResult(refreshId, reason);
    return SOFTBUS_OK;
}

int32_t ClientOnRefreshDeviceFound(const char *pkgName, const void *device, uint32_t deviceLen)
{
    if (pkgName == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "pkgName is null");
        return SOFTBUS_ERR;
    }
    sptr<BusCenterClientProxy> clientProxy = GetClientProxy(pkgName);
    if (clientProxy == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bus center client proxy is nullptr!");
        return SOFTBUS_ERR;
    }
    clientProxy->OnRefreshDeviceFound(device, deviceLen);
    return SOFTBUS_OK;
}