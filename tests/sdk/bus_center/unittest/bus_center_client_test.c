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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <securec.h>

#include "discovery_service.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"

#define BUS_CENTER_TEST "bus_center_test"
#define INDEX_NUM 10
#define DEFAULT_NODE_STATE_CB_NUM 10
#define DEFAULT_LOCAL_DEVICE_TYPE_ID 0

static bool g_joinLnnDone = false;
static bool g_leaveLnnDone = false;
static bool g_joinOnLine = false;
static bool g_discfound = false;
static int index = 0;
static int g_subscribeId = 0;
static char g_networkId[INDEX_NUM][NETWORK_ID_BUF_LEN];
static ConnectionAddr addr = {
    .type = CONNECTION_ADDR_ETH,
};

static void DeviceFound(const DeviceInfo *device)
{
    if (device == NULL) {
        printf("device para is null");
        return;
    }
    printf("DeviceFound enter, type = %d, %s", device->addr[0].type, device->addr[0].info.ip.ip);
    if (device->addr[0].info.ip.port == 0) {
        printf("disc get port is 0 !");
    }
    if (memcpy_s(&addr, sizeof(addr), device->addr, sizeof(addr)) != 0) {
        printf("memcpy key error.");
        return;
    }
    g_discfound = true;
}
static void DiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    printf("[client]TestDiscoverFailed\n");
}

static void DiscoverySuccess(int subscribeId)
{
    printf("[client]TestDiscoverySuccess\n");
}

static IDiscoveryCallback g_discCb = {
    .OnDeviceFound = DeviceFound,
    .OnDiscoverFailed = DiscoverFailed,
    .OnDiscoverySuccess = DiscoverySuccess,
};

static void OnJoinLNNDone(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL) {
        printf("OnJoinLNNDone error\n");
        return;
    }
    if (retCode == 0) {
        printf("OnJoinLNNDone enter networdid = %s, retCode = %d\n", networkId, retCode);
    } else {
        printf("OnJoinLNNDone failed! networdid = %s, retCode = %d\n", networkId, retCode);
    }
    g_joinLnnDone = true;
}

static void OnLeaveLNNDone(const char *networkId, int32_t retCode)
{
    if (retCode == 0) {
        printf("OnLeaveLNNDone enter networdid = %s, retCode = %d\n", networkId, retCode);
    } else {
        printf("OnLeaveLNNDone failed! networdid = %s, retCode = %d\n", networkId, retCode);
    }
    g_leaveLnnDone = true;
}

static void OnNodeOnline(NodeBasicInfo *info)
{
    if (info == NULL) {
        return;
    }
    g_joinOnLine = true;
    printf("node online, network id: %s\n", info->networkId);
    if (index < 10) {
        strcpy(g_networkId[index++], info->networkId);
    }
}

static void OnNodeOffline(NodeBasicInfo *info)
{
    if (info == NULL) {
        return;
    }
    g_joinOnLine = false;
    printf("node offline, network id: %s\n", info->networkId);
}

static INodeStateCb g_nodeStateCallback = {
    .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE,
    .onNodeOnline = OnNodeOnline,
    .onNodeOffline = OnNodeOffline,
};
    
static int32_t TestGetNodeInfo()
{
    NodeBasicInfo *info = NULL;
    NodeBasicInfo *info1 = NULL;
    int32_t infoNum = 0;
    int32_t ret = GetAllNodeDeviceInfo(BUS_CENTER_TEST, &info, &infoNum);
    printf("GetAllNodeDeviceInfo ret = %d, infoNum = %d\n", ret, infoNum);
    if (ret != 0) {
        printf("GetAllNodeDeviceInfo error!\n");
        return -1;
    }
    info1 = info;
    for (int32_t i = 0; i < infoNum; i++) {
        printf("GetAllNodeDeviceInfo networkId = %s, typeId = %d, name = %s\n", info->networkId, info->deviceTypeId,
            info->deviceName);
        info++;
    }
    char uuid[UUID_BUF_LEN] = {0};
    ret = GetNodeKeyInfo(BUS_CENTER_TEST, info1->networkId, NODE_KEY_UUID, (uint8_t *)uuid, UUID_BUF_LEN);
    if (ret != 0) {
        printf("GetNodeKeyInfo error!\n");
        return -1;
    }
    printf("GetNodeKeyInfo uuid = %s\n", uuid);
    char udid[UDID_BUF_LEN] = {0};
    ret = GetNodeKeyInfo(BUS_CENTER_TEST, info1->networkId, NODE_KEY_UDID, (uint8_t *)udid, UDID_BUF_LEN);
    if (ret != 0) {
        printf("GetNodeKeyInfo error!\n");
        return -1;
    }
    printf("GetNodeKeyInfo udid = %s\n", udid);
    FreeNodeInfo(info1);

    NodeBasicInfo info2;
    ret = GetLocalNodeDeviceInfo(BUS_CENTER_TEST, &info2);
    if (ret != 0) {
        printf("GetLocalNodeDeviceInfo error!\n");
        return -1;
    }
    printf("GetLocalNodeDeviceInfo networkId = %s, typeId = %d, name = %s\n", info2.networkId, info2.deviceTypeId,
        info2.deviceName);

    ret = GetNodeKeyInfo(BUS_CENTER_TEST, info2.networkId, NODE_KEY_UUID, (uint8_t *)uuid, UUID_BUF_LEN);
    if (ret != 0) {
        printf("GetNodeKeyInfo error!\n");
        return -1;
    }
    printf("GetNodeKeyInfo uuid = %s\n", uuid);
    ret = GetNodeKeyInfo(BUS_CENTER_TEST, info2.networkId, NODE_KEY_UDID, (uint8_t *)udid, UDID_BUF_LEN);
    if (ret != 0) {
        printf("GetNodeKeyInfo error!\n");
        return -1;
    }
    printf("GetNodeKeyInfo udid = %s\n", udid);
    return 0;
}

/*
* @tc.name: BUS_CENTER_SDK_Join_Lnn_Test_001
* @tc.desc: bus center JoinLNN interface exception test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_Join_Lnn_Test_001()
{
    ConnectionAddr addr;

    if (JoinLNN(NULL, &addr, OnJoinLNNDone) == 0) {
        printf("BUS_CENTER_SDK_Join_Lnn_Test_001 error!\n");
        return;
    }
    if (JoinLNN(BUS_CENTER_TEST, NULL, OnJoinLNNDone) == 0) {
        printf("BUS_CENTER_SDK_Join_Lnn_Test_001 error!\n");
        return;
    }
    if (JoinLNN(BUS_CENTER_TEST, &addr, NULL) == 0) {
        printf("BUS_CENTER_SDK_Join_Lnn_Test_001 error!\n");
        return;
    }
    printf("BUS_CENTER_SDK_Join_Lnn_Test_001 passed!\n");
}

/*
* @tc.name: BUS_CENTER_SDK_Leave_Lnn_Test_001
* @tc.desc: bus center LeaveLNN interface exception test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_Leave_Lnn_Test_001()
{
    char errNetIdLenMore[] = "012345678998765432100123456789987654321001234567899876543210abcde";
    char networkId[] = "0123456789987654321001234567899876543210012345678998765432100123";

    if (LeaveLNN(NULL, OnLeaveLNNDone) == 0) {
        printf("BUS_CENTER_SDK_Leave_Lnn_Test_001 error!\n");
        return;
    }
    if (LeaveLNN(networkId, NULL) == 0) {
        printf("BUS_CENTER_SDK_Leave_Lnn_Test_001 error!\n");
        return;
    }
    if (LeaveLNN(errNetIdLenMore, OnLeaveLNNDone) == 0) {
        printf("BUS_CENTER_SDK_Leave_Lnn_Test_001 error!\n");
        return;
    }
    printf("BUS_CENTER_SDK_Leave_Lnn_Test_001 passed!\n");
}

/*
* @tc.name: BUS_CENTER_SDK_STATE_CB_Test_001
* @tc.desc: bus center node state callback reg and unreg interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_STATE_CB_Test_001()
{
    if (RegNodeDeviceStateCb(BUS_CENTER_TEST, &g_nodeStateCallback) != 0) {
        printf("BUS_CENTER_SDK_STATE_CB_Test_001 error!\n");
        return;
    }
    if (UnregNodeDeviceStateCb(&g_nodeStateCallback) != 0) {
        printf("BUS_CENTER_SDK_STATE_CB_Test_001 error!\n");
        return;
    }
    printf("BUS_CENTER_SDK_STATE_CB_Test_001 passed!\n");
}

/*
* @tc.name: BUS_CENTER_SDK_STATE_CB_Test_002
* @tc.desc: bus center node state callback reg and unreg upper limit interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_STATE_CB_Test_002()
{
    int i;

    for (i = 0; i <= DEFAULT_NODE_STATE_CB_NUM; ++i) {
        if (i < DEFAULT_NODE_STATE_CB_NUM) {
            if (RegNodeDeviceStateCb(BUS_CENTER_TEST, &g_nodeStateCallback) != 0) {
                printf("BUS_CENTER_SDK_STATE_CB_Test_002 error!\n");
                return;
            }
        } else {
            if (RegNodeDeviceStateCb(BUS_CENTER_TEST, &g_nodeStateCallback) == 0) {
                printf("BUS_CENTER_SDK_STATE_CB_Test_002 error!\n");
                return;
            }
        }
    }
    for (i = 0; i < DEFAULT_NODE_STATE_CB_NUM; ++i) {
        if (UnregNodeDeviceStateCb(&g_nodeStateCallback) != 0) {
            printf("BUS_CENTER_SDK_STATE_CB_Test_002 error!\n");
            return;
        }
    }
    printf("BUS_CENTER_SDK_STATE_CB_Test_002 passed!\n");
}

/*
* @tc.name: BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001
* @tc.desc: get all node info interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001()
{
    NodeBasicInfo *info = NULL;
    int infoNum;

    if (GetAllNodeDeviceInfo(BUS_CENTER_TEST, &info, &infoNum) != 0) {
        printf("BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001 error!\n");
        return;
    }
    if (info != NULL) {
        printf("BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001 error!\n");
        return;
    }
    if (infoNum != 0) {
        printf("BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001 error!\n");
        return;
    }
    if (info != NULL) {
        FreeNodeInfo(info);
    }
    printf("BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001 passed!\n");
}

/*
* @tc.name: BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001
* @tc.desc: get local info interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001()
{
    NodeBasicInfo info;

    if (GetLocalNodeDeviceInfo(BUS_CENTER_TEST, &info) != 0) {
        printf("BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001 error!\n");
        return;
    }
    if (strlen(info.networkId) != (NETWORK_ID_BUF_LEN - 1)) {
        printf("BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001 error!\n");
        return;
    }
    if (info.deviceTypeId != DEFAULT_LOCAL_DEVICE_TYPE_ID) {
        printf("BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001 error!\n");
        return;
    }
    printf("BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001 passed!\n");
}

/*
* @tc.name: BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001
* @tc.desc: get node key info interface test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001()
{
    NodeBasicInfo info;
    char uuid[UUID_BUF_LEN] = {0};
    char udid[UDID_BUF_LEN] = {0};

    (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (GetLocalNodeDeviceInfo(BUS_CENTER_TEST, &info) != 0) {
        printf("BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001 error!\n");
        return;
    }
    if (GetNodeKeyInfo(BUS_CENTER_TEST, info.networkId, NODE_KEY_UDID,
        (uint8_t *)udid, UDID_BUF_LEN) != 0) {
        printf("BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001 error!\n");
        return;
    }
    if (GetNodeKeyInfo(BUS_CENTER_TEST, info.networkId, NODE_KEY_UUID,
        (uint8_t *)uuid, UUID_BUF_LEN) != 0) {
        printf("BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001 error!\n");
        return;
    }
    if (strlen(uuid) != (UUID_BUF_LEN - 1)) {
        printf("BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001 error!\n");
        return;
    }
    printf("BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001 passed!\n");
}

static int32_t BUS_CENTER_SDK_JOIN_AND_LEAVE_LNN_Test_001()
{
    SubscribeInfo testInfo = {
        .subscribeId = g_subscribeId,
        .medium = COAP,
        .mode = DISCOVER_MODE_ACTIVE,
        .freq = MID,
        .capability = "ddmpCapability",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3"),
        .isSameAccount = true,
        .isWakeRemote = false,
    };
    if (RegNodeDeviceStateCb(BUS_CENTER_TEST, &g_nodeStateCallback) != 0) {
        printf("RegNodeDeviceStateCb error!\n");
        return -1;
    }
    printf("StartDiscovery...........\n");

    g_discfound = false;
    if (StartDiscovery(BUS_CENTER_TEST, &testInfo, &g_discCb) != 0) {
        printf("StartDiscovery error!\n");
        return -1;        
    }
    while (g_discfound == false) {
        printf("wait disc device Done.........\n");
        sleep(5);
    }
    
    g_joinLnnDone = false;
    if (JoinLNN(BUS_CENTER_TEST, &addr, OnJoinLNNDone) != 0) {
        printf("JoinLNN error!\n");
        return -1;
    }
    while (g_joinLnnDone == false) {
        printf("wait Join LNN Done.........\n");
        sleep(5);
    }
    TestGetNodeInfo();

    for (int i = 0; i < index; i++) {
        g_leaveLnnDone = false;
        if (LeaveLNN(g_networkId[i], OnLeaveLNNDone) != 0) {
            printf("LeaveLNN error!\n");
            return -1;
        }
        while (g_leaveLnnDone == false) {
            printf("wait Leave Lnn Done.........\n");
            sleep(3);
        }
    }
    index = 0;
    if (UnregNodeDeviceStateCb(&g_nodeStateCallback) != 0) {
        printf("UnregNodeDeviceStateCb error!\n");
        return -1;
    }
}

int main(void)
{
    BUS_CENTER_SDK_Join_Lnn_Test_001();
    BUS_CENTER_SDK_Leave_Lnn_Test_001();
    BUS_CENTER_SDK_STATE_CB_Test_001();
    BUS_CENTER_SDK_STATE_CB_Test_002();
    BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001();
    BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001();
    BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001();
    BUS_CENTER_SDK_JOIN_AND_LEAVE_LNN_Test_001();
    return 0;
}