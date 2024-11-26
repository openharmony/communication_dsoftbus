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

/**
 * @file join_lnn_demo.c
 *
 * @brief Provides the sample code for device join and leave lnn
 *
 * @since 1.0
 * @version 1.0
 */

#include <stdint.h>

#include "softbus_bus_center.h"
#include "softbus_common.h"

const char g_networkId[NETWORK_ID_BUF_LEN] = { 0 };

// Notify add current device to the LNN result.
static void OnJoinLnnDone(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    if (addr == NULL || networkId == NULL || strlen(networkId) == 0) {
        printf("[demo]OnJoinLnnDone param invalid\n");
        return;
    }
    if (retCode == 0) {
        printf("[demo]OnJoinLnnDone success\n");
        if (strcpy_s(g_networkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
            printf("[demo]OnJoinLnnDone strcpy networkId failed\n");
            return;
        }
    } else {
        printf("[demo]OnJoinLnnDone failed, retCode = %d\n", retCode);
    }
}

// Notify removes current device from the LNN result.
static void OnLeaveLnnDone(const char *networkId, int32_t retCode)
{
    if (retCode == 0) {
        printf("[demo]OnLeaveLnnDone success\n");
    } else {
        printf("[demo]OnLeaveLnnDone failed, retCode = %d\n", retCode);
    }
}

int32_t main(void)
{
    const char *pkgName = "pkgName.demo";
    // Device B is found by coap or ble, we can get it's addr info before join lnn.
    ConnectionAddr addr = {
        .type = CONNECTION_ADDR_WLAN,                                                 // connection type of device B
        .peerUid = "012345678998765432101234567898765432101234567898765432101234567", // uuid of device B
        .info.ip.ip = "192.168.0.1",                                                  // ip info of device B
        .info.ip.port = 1000                                                          // auth port of device B
    };

    /*
     * 1. Device A calls JoinLNN() to Join Lnn with B.
     */
    int32_t ret = JoinLNN(pkgName, &addr, OnJoinLnnDone);
    printf("[demo]join lnn result = %d\n", ret);

    /*
     * 2. When finish join lnn, device A return the lnn result via OnJoinLnnDone().
     */

    /*
     * 3. If OnJoinLnnDone() return ok, g_networkId is returned. device A calls LeaveLNN() to leave.
     */
    ret = LeaveLNN(pkgName, g_networkId, OnLeaveLnnDone);
    printf("[demo]leave lnn result = %d\n", ret);
    if (ret == 0) {
        (void)memset_s(g_networkId, NETWORK_ID_BUF_LEN, 0, NETWORK_ID_BUF_LEN);
    }

    /*
     * 4. When finish leave lnn, device A return the lnn result via OnLeaveLnnDone().
     */
    return ret;
}
