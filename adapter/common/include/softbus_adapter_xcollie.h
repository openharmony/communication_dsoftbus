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

#ifndef SOFTBUS_ADAPTER_XCOLLIE_H
#define SOFTBUS_ADAPTER_XCOLLIE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
* @brief Called when set timer for service watchdog.
* @param name Indicates the point to the name of the timer.
* @param timeout Indicates the timeout.
* @param func Indicates the point to the callback function.
* @param args Indicates the point to the timer timeout operation.
*
* @return Return the timer id.
*
* @since 1.0
* @version 1.0
*/
int32_t SoftBusSetWatchdogTimer(const char *name, uint32_t timeout, void(*func)(void*), void *args);

/**
* @brief Called when cancel timer of service watchdog.
* @param id Indicates the id of the timer.
*
* @since 1.0
* @version 1.0
*/
void SoftBusCancelWatchdogTimer(int32_t id);

/**
* @brief Called when run a onshot task in shared watchdog thread, the submitted task should never be time consuming.
* @param name Indicates the point to the name of the task.
* @param task Indicates the point to a short function name.
* @param delay Indicates delay a few millisecond to run the task.
*
* @since 1.0
* @version 1.0
*/
void SoftBusRunOneShotTask(const char *name, void(*task)(void), uint64_t delay);

/**
* @brief Called when run a periodical task in shared watchdog thread.
* @param name Indicates the point to the name of the task.
* @param task Indicates the point to a short function name.
* @param interval Indicates the millisecond interval of the periodical task.
* @param delay Indicates delay a few millisecond to first run the task.
*
* @since 1.0
* @version 1.0
*/
void SoftBusRunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SOFTBUS_ADAPTER_XCOLLIE_H
