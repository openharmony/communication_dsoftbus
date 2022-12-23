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

#include "p2plink_lnn_sync.h"

#include <stdio.h>
#include "securec.h"
#include "string.h"

#include "bus_center_info_key.h"
#include "bus_center_manager.h"

#include "p2plink_common.h"
#include "p2plink_device.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "softbus_hidumper_conn.h"

#define LNN_MAC_INFO "lnnMacInfo"

static int32_t g_lnnRole = 0;
static char g_lnnMyP2pMac[P2P_MAC_LEN] = {0};
static char g_lnnGoMac[P2P_MAC_LEN] = {0};
static int32_t P2pLnnDump(int fd);
static bool g_p2pDumpFlag = false;
static int32_t P2pLinkLnnSyncSetGoMac()
{
    if (LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, P2pLinkGetGoMac()) == SOFTBUS_OK) {
        if (strcpy_s(g_lnnGoMac, sizeof(g_lnnGoMac), P2pLinkGetGoMac()) != EOK) {
            CLOGI("strcpy fail");
        }
        return SOFTBUS_OK;
    } else {
        CLOGE("set lnn p2p go mac fail");
        return SOFTBUS_ERR;
    }
}

NO_SANITIZE("cfi") void P2pLinkLnnSync(void)
{
    int32_t change = 0;

    int32_t role =  P2pLinkGetRole();
    if (g_lnnRole != role) {
        P2pLinkMyRoleChangeNotify((P2pLinkRole)role);
        CLOGI("sync role %d->%d", g_lnnRole, role);
        if (LnnSetLocalNumInfo(NUM_KEY_P2P_ROLE, role) == SOFTBUS_OK) {
            g_lnnRole = role;
            change = 1;
        } else {
            CLOGE("set lnn p2p role fail");
        }
    }

    if (strcmp(P2pLinkGetMyMac(), g_lnnMyP2pMac) != 0) {
        CLOGI("sync lnn p2p mymac");
        if (LnnSetLocalStrInfo(STRING_KEY_P2P_MAC, P2pLinkGetMyMac()) == SOFTBUS_OK) {
            if (strcpy_s(g_lnnMyP2pMac, sizeof(g_lnnMyP2pMac), P2pLinkGetMyMac()) != EOK) {
                CLOGI("strcpy fail");
            }
            change = 1;
        } else {
            CLOGE("set lnn p2p my mac fail");
        }
    }

    if (role == ROLE_GC) {
        if (strcmp(P2pLinkGetGoMac(), g_lnnGoMac) != 0) {
            CLOGI("sync gomac");
            if (P2pLinkLnnSyncSetGoMac() == SOFTBUS_OK) {
                change = 1;
            }
        }
    } else {
        if (strlen(g_lnnGoMac) != 0) {
            g_lnnGoMac[0] = '\0';
            change = 1;
            if (LnnSetLocalStrInfo(STRING_KEY_P2P_GO_MAC, g_lnnGoMac) != SOFTBUS_OK) {
                CLOGE("clean go mac fail");
            }
        }
    }

    if (g_p2pDumpFlag == false) {
        SoftBusRegConnVarDump(LNN_MAC_INFO, &P2pLnnDump);
        g_p2pDumpFlag = true;
        CLOGI("P2pLnnDump registration success");
    }

    CLOGI("lnn sync flag %d", change);
    if (change == 1) {
        LnnSyncP2pInfo();
    }
}

static int32_t P2pLnnDump(int fd)
{
    char lnnMyP2pMac[P2P_MAC_LEN] = {0};
    char lnnGoP2pMac[P2P_MAC_LEN] = {0};
    SOFTBUS_DPRINTF(fd, "\n-----------------P2pLnnMacInfo-------------------\n");
    DataMasking(g_lnnMyP2pMac, P2P_MAC_LEN, MAC_DELIMITER, lnnMyP2pMac);
    SOFTBUS_DPRINTF(fd, "lnnMyP2pMac               :%s\n", lnnMyP2pMac);
    DataMasking(g_lnnGoMac, P2P_MAC_LEN, MAC_DELIMITER, lnnGoP2pMac);
    SOFTBUS_DPRINTF(fd, "lnnGoP2pMac               :%s\n", lnnGoP2pMac);

    return SOFTBUS_OK;
}
