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

#include "trans_common_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

void *g_commonInterface = nullptr;

TransCommInterfaceMock::TransCommInterfaceMock()
{
    g_commonInterface = reinterpret_cast<void *>(this);
}

TransCommInterfaceMock::~TransCommInterfaceMock()
{
    g_commonInterface = nullptr;
}

static TransCommInterface *GetCommonInterface()
{
    return reinterpret_cast<TransCommInterface *>(g_commonInterface);
}

int TransCommInterfaceMock::ActionOfSoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    (void)type;
    (void)len;
    *val = 1;
    return SOFTBUS_OK;
}

#ifdef __cplusplus
extern "C" {
#endif

int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetCommonInterface()->SoftbusGetConfig(type, val, len);
}

ClientEnhanceFuncList *ClientEnhanceFuncListGet(void)
{
    return GetCommonInterface()->ClientEnhanceFuncListGet();
}

int32_t WriteInt32ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t data)
{
    return GetCommonInterface()->WriteInt32ToBuf(buf, dataLen, offSet, data);
}

int32_t WriteUint64ToBuf(uint8_t *buf, uint32_t bufLen, int32_t *offSet, uint64_t data)
{
    return GetCommonInterface()->WriteUint64ToBuf(buf, bufLen, offSet, data);
}

int32_t WriteStringToBuf(uint8_t *buf, uint32_t bufLen, int32_t *offSet, char *data, uint32_t dataLen)
{
    return GetCommonInterface()->WriteStringToBuf(buf, bufLen, offSet, data, dataLen);
}

int32_t ServerIpcProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    return GetCommonInterface()->ServerIpcProcessInnerEvent(eventType, buf, len);
}

SoftBusList *CreateSoftBusList(void)
{
    return GetCommonInterface()->CreateSoftBusList();
}

int32_t TransServerProxyInit(void)
{
    return GetCommonInterface()->TransServerProxyInit();
}

int32_t ClientTransChannelInit(void)
{
    return GetCommonInterface()->ClientTransChannelInit();
}

int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback)
{
    return GetCommonInterface()->RegisterTimeoutCallback(timerFunId, callback);
}

int32_t RegNodeDeviceStateCbInner(const char *pkgName, INodeStateCb *callback)
{
    return GetCommonInterface()->RegNodeDeviceStateCbInner(pkgName, callback);
}

int32_t SoftBusCondSignal(SoftBusCond *cond)
{
    return GetCommonInterface()->SoftBusCondSignal(cond);
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    return GetCommonInterface()->SoftBusGetTime(sysTime);
}

int32_t SoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, SoftBusSysTime *time)
{
    return GetCommonInterface()->SoftBusCondWait(cond, mutex, time);
}
#ifdef __cplusplus
}
#endif
}
