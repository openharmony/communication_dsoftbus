/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "hb_heartbeat_utils_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbHeartbeatUtilsInterface = nullptr;
HbHeartbeatUtilsInterfaceMock::HbHeartbeatUtilsInterfaceMock()
{
    g_hbHeartbeatUtilsInterface = reinterpret_cast<void *>(this);
}

HbHeartbeatUtilsInterfaceMock::~HbHeartbeatUtilsInterfaceMock()
{
    g_hbHeartbeatUtilsInterface = nullptr;
}

static HbHeartbeatUtilsInterface *HbHeartbeatUtilsInterface()
{
    return reinterpret_cast<HbHeartbeatUtilsInterfaceMock *>(g_hbHeartbeatUtilsInterface);
}

extern "C" {
int32_t ConvertBtMacToStrNoColon(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    return HbHeartbeatUtilsInterface()->ConvertBtMacToStrNoColon(strMac, strMacLen, binMac, binMacLen);
}

int32_t StringToUpperCase(const char *str, char *buf, int32_t size)
{
    return HbHeartbeatUtilsInterface()->StringToUpperCase(str, buf, size);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return HbHeartbeatUtilsInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return HbHeartbeatUtilsInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return HbHeartbeatUtilsInterface()->LnnGetRemoteNumU32Info(networkId, key, info);
}

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return HbHeartbeatUtilsInterface()->GetWifiDirectManager();
}
}
} // namespace OHOS
