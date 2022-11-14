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

#ifndef XCOLLIE_HELPER_H
#define XCOLLIE_HELPER_H
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
* @param args Indicates the point to the timer timeout operation.The value can be
		XCOLLIE_FLAG_DEFAULT : do all callback function.
		XCOLLIE_FLAG_NOOP : do nothing but the caller defined function.
		XCOLLIE_FLAG_LOG : generate log file.
		XCOLLIE_FLAG_RECOVERY : die when timeout.
*
* @return Return the timer id.
* 
* @since 1.0
* @version 1.0
*/
int SetTimer(const char *name, unsigned int timeout, void(*func)(void*), void *args);

/**
* @brief Called when cancel timer of service watchdog.
* @param id Indicates the id of the timer.
*
* @since 1.0
* @version 1.0
*/
void CancelTimer(int id);

/**
* @brief Called when run a onshot task in shared watchdog thread, the submitted task should never be time consuming.
* @param name Indicates the point to the name of the task.
* @param task Indicates the point to a short function name.
* @param delay Indicates delay a few millisecond to run the task.
*
* @since 1.0
* @version 1.0
*/
void RunOneShotTask(const char *name, void(*task)(void), uint64_t delay);

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
void RunPeriodicalTask(const char *name, void(*task)(void), uint64_t interval, uint64_t delay);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
