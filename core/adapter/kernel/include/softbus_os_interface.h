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

#ifndef SOFTBUS_OS_INTERFACE_H
#define SOFTBUS_OS_INTERFACE_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* Timer */
void *SoftBusCreateTimer(void **timerId, void *timerFunc, unsigned int type);
int SoftBusStartTimer(void *timerId, unsigned int tickets);
int SoftBusDeleteTimer(void *timerId);

/* Sleep */
int SoftBusSleepMs(unsigned int ms);

/* File operation */
int SoftBusReadFile(const char *fileName, char *readBuf, int maxLen);
int SoftBusWriteFile(const char *fileName, const char *writeBuf, int len);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif