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

#include <securec.h>

#include "lnn_lane_link_conflict_deps_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneLinkConflictDepsInterface;
LaneLinkConflictDepsInterfaceMock::LaneLinkConflictDepsInterfaceMock()
{
    g_laneLinkConflictDepsInterface = reinterpret_cast<void *>(this);
}

LaneLinkConflictDepsInterfaceMock::~LaneLinkConflictDepsInterfaceMock()
{
    g_laneLinkConflictDepsInterface = nullptr;
}

static LaneLinkConflictDepsInterface *GetLaneLinkConflictDepsInterface()
{
    return reinterpret_cast<LaneLinkConflictDepsInterface *>(g_laneLinkConflictDepsInterface);
}

int32_t LaneLinkConflictDepsInterfaceMock::ActionOfConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    (void)inBuf;
    (void)inLen;
    if (strcpy_s(outBuf, outBufLen, PEER_UDID_HASH_STR) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
int32_t InitLinkWifiDirect(void)
{
    return GetLaneLinkConflictDepsInterface()->InitLinkWifiDirect();
}

void DeInitLinkWifiDirect(void)
{
    GetLaneLinkConflictDepsInterface()->DeInitLinkWifiDirect();
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetLaneLinkConflictDepsInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetLaneLinkConflictDepsInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    return GetLaneLinkConflictDepsInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}
}
} // namespace OHOS
