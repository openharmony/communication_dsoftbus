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
static int index = 0;
static char g_networkId[INDEX_NUM][NETWORK_ID_BUF_LEN];
static ConnectionAddr addr = {
    .type = CONNECTION_ADDR_ETH,
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

/*
* @tc.name: BUS_CENTER_SDK_Join_Lnn_Test_001
* @tc.desc: bus center JoinLNN interface exception test
* @tc.type: FUNC
* @tc.require: AR000FK6J4
*/
void BUS_CENTER_SDK_Join_Lnn_Test_001(void)
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
void BUS_CENTER_SDK_Leave_Lnn_Test_001(void)
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
void BUS_CENTER_SDK_STATE_CB_Test_001(void)
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
void BUS_CENTER_SDK_STATE_CB_Test_002(void)
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
void BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001(void)
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
void BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001(void)
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
void BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001(void)
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

int main(void)
{
    BUS_CENTER_SDK_Join_Lnn_Test_001();
    BUS_CENTER_SDK_Leave_Lnn_Test_001();
    BUS_CENTER_SDK_STATE_CB_Test_001();
    BUS_CENTER_SDK_STATE_CB_Test_002();
    BUS_CENTER_SDK_GET_ALL_NODE_INFO_Test_001();
    BUS_CENTER_SDK_GET_LOCAL_NODE_INFO_Test_001();
    BUS_CENTER_SDK_GET_NODE_KEY_INFO_Test_001();
    return 0;
}