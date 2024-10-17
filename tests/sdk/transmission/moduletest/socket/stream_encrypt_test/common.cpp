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

#include <chrono>
#include <thread>

#include "common.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "softbus_bus_center.h"
#include "token_setproc.h"

namespace OHOS {
static char g_networkId[NETWORK_ID_BUF_LEN] = { 0 };

static void OnDefNodeOnline(NodeBasicInfo *info)
{
    if (info == nullptr) {
        LOGI("Online: info is null...");
        return;
    }
    (void)strncpy_s(g_networkId, NETWORK_ID_BUF_LEN, info->networkId, NETWORK_ID_BUF_LEN);
    LOGI("Online {networkId=%s, deviceName=%s, device type=%d}", info->networkId, info->deviceName, info->deviceTypeId);
}

static void OnDefNodeOffline(NodeBasicInfo *info)
{
    if (info == nullptr) {
        LOGI("Offline: info is null...");
        return;
    }
    LOGI(
        "Offline {networkId=%s, deviceName=%s, device type=%d}", info->networkId, info->deviceName, info->deviceTypeId);
}

static void OnDefNodeBasicInfoChanged(NodeBasicInfoType type, NodeBasicInfo *info)
{
    if (info == nullptr) {
        LOGI("InfoChanged: info is null, type=%d", type);
        return;
    }
    LOGI("InfoChanged {networkId=%s, deviceName=%s}", info->networkId, info->deviceName);
}

static void onDefNodeStatusChanged(NodeStatusType type, NodeStatus *status)
{
    if (status == nullptr) {
        LOGI("StatusChanged: info is null, type=%d", type);
        return;
    }
    LOGI("InfoChanged {networkId=%s, authStatus=%d", status->basicInfo.networkId, status->authStatus);
}

static INodeStateCb g_defNodeStateCallback = {
    .events = EVENT_NODE_STATE_MASK,
    .onNodeOnline = OnDefNodeOnline,
    .onNodeOffline = OnDefNodeOffline,
    .onNodeBasicInfoChanged = OnDefNodeBasicInfoChanged,
    .onNodeStatusChanged = onDefNodeStatusChanged,
};

void AddPermission()
{
    uint64_t tokenId;
    const char *perms[] = {
        OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER,
        OHOS_PERMISSION_DISTRIBUTED_DATASYNC,
    };
    uint32_t permsSize = sizeof(perms) / sizeof(perms[0]);
    NativeTokenInfoParams infoTnstance = {
        .dcapsNum = 0,
        .permsNum = permsSize,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "dsoftbus_service",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoTnstance);
    SetSelfTokenID(tokenId);
}

static int32_t CheckRemoteDeviceIsNull(bool isSetNetId)
{
    int32_t nodeNum = 0;
    NodeBasicInfo *nodeInfo = nullptr;
    int32_t ret = GetAllNodeDeviceInfo(PKG_NAME, &nodeInfo, &nodeNum);
    LOGI("[check]get node number=%d, ret=%d", nodeNum, ret);
    if (nodeInfo != nullptr && nodeNum > 0) {
        LOGI("[check]get netid is=%s", nodeInfo->networkId);
        if (isSetNetId) {
            (void)strncpy_s(g_networkId, NETWORK_ID_BUF_LEN, nodeInfo->networkId, NETWORK_ID_BUF_LEN);
        }
        FreeNodeInfo(nodeInfo);
        return SOFTBUS_OK;
    } else {
        LOGI("[check]get nodeInfo is null");
        return ret;
    }
}

int32_t TestInit()
{
    AddPermission();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    int32_t ret = RegNodeDeviceStateCb(PKG_NAME, &g_defNodeStateCallback);
    if (ret != SOFTBUS_OK) {
        LOGE("call reg node state callback fail, ret=%d", ret);
        return ret;
    }

    ret = CheckRemoteDeviceIsNull(true);
    if (ret != SOFTBUS_OK) {
        LOGE("get node fail,please check network, ret=%d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t TestDeInit()
{
    UnregNodeDeviceStateCb(&g_defNodeStateCallback);
    return SOFTBUS_OK;
}

char *WaitOnLineAndGetNetWorkId()
{
    while (g_networkId[0] == '\0') {
        LOGI("wait online...");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    LOGI("JoinLnn, networkId:%s", g_networkId);
    return g_networkId;
}
} // namespace OHOS