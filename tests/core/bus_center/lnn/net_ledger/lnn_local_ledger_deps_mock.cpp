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

#include <cstdint>
#include <securec.h>

#include "lnn_local_ledger_deps_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_localLedgerDepsInterface;
constexpr char DEFAULT_DEVICE_NAME[] = "OpenHarmony";
constexpr char DEFAULT_DEVICE_UDID[] = "aaabbbcccdddeeefffggghhh";
constexpr char DEFAULT_DEVICE_TYPE[] = "default_type";
constexpr int32_t SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO_FD = -1;

LocalLedgerDepsInterfaceMock::LocalLedgerDepsInterfaceMock()
{
    g_localLedgerDepsInterface = reinterpret_cast<void *>(this);
}

LocalLedgerDepsInterfaceMock::~LocalLedgerDepsInterfaceMock()
{
    g_localLedgerDepsInterface = nullptr;
}

static LocalLedgerDepsInterfaceMock *GetLocalLedgerDepsInterface()
{
    return reinterpret_cast<LocalLedgerDepsInterfaceMock *>(g_localLedgerDepsInterface);
}

int32_t LocalLedgerDepsInterfaceMock::LedgerGetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len)
{
    if (value == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            if (strncpy_s(value, len, DEFAULT_DEVICE_NAME, strlen(DEFAULT_DEVICE_NAME)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_UDID:
            if (strncpy_s(value, len, DEFAULT_DEVICE_UDID, UDID_BUF_LEN) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_DEVTYPE:
            if (strncpy_s(value, len, DEFAULT_DEVICE_TYPE, strlen(DEFAULT_DEVICE_TYPE)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}

int32_t LocalLedgerDepsInterfaceMock::LedgerSoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb)
{
    int32_t ret = SOFTBUS_INVALID_PARAM;
    if (cb != nullptr) {
        ret = cb(SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO_FD);
    }
    return ret;
}

extern "C" {
uint32_t LnnGetNetCapabilty(void)
{
    return GetLocalLedgerDepsInterface()->LnnGetNetCapabilty();
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->SoftBusGenerateRandomArray(randStr, len);
}

int32_t GetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetCommonDevInfo(key, value, len);
}

int32_t LnnInitLocalP2pInfo(NodeInfo *info)
{
    return GetLocalLedgerDepsInterface()->LnnInitLocalP2pInfo(info);
}

int32_t SoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb)
{
    return GetLocalLedgerDepsInterface()->SoftBusRegBusCenterVarDump(dumpVar, cb);
}

int32_t LnnInitOhosAccount(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitOhosAccount();
}

uint64_t LnnGetFeatureCapabilty(void)
{
    return GetLocalLedgerDepsInterface()->LnnGetFeatureCapabilty();
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetLocalLedgerDepsInterface()->IsFeatureSupport(feature, capaBit);
}

int32_t GetCommonOsType(int32_t *value)
{
    return GetLocalLedgerDepsInterface()->GetCommonOsType(value);
}

int32_t GetCommonOsVersion(char *value, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetCommonOsVersion(value, len);
}

int32_t GetCommonDeviceVersion(char *value, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetCommonDeviceVersion(value, len);
}

int32_t GetDeviceSecurityLevel(int32_t *level)
{
    return GetLocalLedgerDepsInterface()->GetDeviceSecurityLevel(level);
}

int32_t SoftBusGetBtState(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetBtMacAddr(mac);
}
} // extern "C"
} // namespace OHOS
