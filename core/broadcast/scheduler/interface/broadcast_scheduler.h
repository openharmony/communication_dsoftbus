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

#ifndef BROADCAST_SCHEDULER_H
#define BROADCAST_SCHEDULER_H

#include "broadcast_scheduler_type.h"
#include "softbus_broadcast_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Init broadcast scheduler.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the broadcast scheduler initialize succ;
 * returns any other value if initialize failed.
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerInitBroadcast(void);

/**
 * @brief Deinit broadcast scheduler.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the broadcast scheduler deinitialize succ;
 * returns any other value if deinitialize failed.
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerDeinitBroadcast(void);

/**
 * @brief Register the service to the broadcast scheduler.
 *
 * @param type Indicates the service type {@link BaseServiceType}.
 * @param bcId Indicates the service broadcast ID.
 * @param cb Indicates the service broadcast callback {@link BroadcastCallback}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service register succ.
 * returns any other value if the service register failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerRegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb);

/**
 * @brief Unregister the service to the broadcast scheduler.
 *
 * @param bcId Indicates the service broadcast ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister succ.
 * returns any other value if the service unregister failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerUnregisterBroadcaster(int32_t bcId);

/**
 * @brief Register the service listener to the broadcast scheduler.
 *
 * @param type Indicates the service type {@link BaseServiceType}.
 * @param listenerId Indicates the service listener ID.
 * @param cb Indicates the service listener callback {@link ScanCallback}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service register succ.
 * returns any other value if the service register failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerRegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);

/**
 * @brief Unregister the service listener to the broadcast scheduler.
 *
 * @param listenerId Indicates the service listener ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister succ.
 * returns any other value if the service unregister failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerUnregisterListener(int32_t listenerId);

/**
 * @brief The service start send broadcast by scheduler.
 *
 * @param bcId Indicates the service broadcast ID.
 * @param param Indicates the pointer to the service parameter information. For details, see {@link BroadcastParam}.
 * @param packet Indicates the pointer to the service advertising data. For details, see {@link BroadcastPacket}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service start send broadcast succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerStartBroadcast(int32_t bcId, BroadcastContentType contentType, const BroadcastParam *param,
    const BroadcastPacket *packet);

/**
 * @brief The service update broadcast data and parameters.
 * The broadcast will be stopped and then started if the broadcast info is updated.
 *
 * @param bcId Indicates the service broadcast ID.
 * @param param Indicates the pointer to the service parameter info. For details, see {@link BroadcastParam}.
 * @param bcData Indicates the pointer to the service advertising data. For details, see {@link BroadcastPacket}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service update broadcast info succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerUpdateBroadcast(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);

/**
 * @brief The service set broadcast data. Set broadcast data when broadcast is enabled.
 *
 * @param bcId Indicates the service broadcast ID.
 * @param packet Indicates the pointer to the service advertising data. For details, see {@link BroadcastPacket}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service starts the broadcast successfully.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerSetBroadcastData(int32_t bcId, const BroadcastPacket *packet);

/**
 * @brief The service stop broadcast.
 *
 * @param bcId Indicates the service broadcast ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service stop the broadcast successfully.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerStopBroadcast(int32_t bcId);

/**
 * @brief The service enable broadcast scanning
 *
 * @param listenerId Indicates the service listener ID.
 * @param param Indicates the broadcast scan parameter {@link BcScanParams}
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service start to scan succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerStartScan(int32_t listenerId, const BcScanParams *param);

/**
 * @brief The service stop broadcast scanning
 *
 * @param listenerId Indicates the service listener ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service stop scan succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerStopScan(int32_t listenerId);

/**
 * @brief Set the scan filter object
 *
 * @param listenerId Indicates the service listener ID.
 * @param scanFilter Indicates the broadcast scan filter parameter {@link BcScanFilter}
 * @param filterNum Indicates the number of the filter parameter
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service set the scan filter succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerSetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);

/**
 * @brief Get the scan filter object
 *
 * @param listenerId Indicates the service listener ID.
 * @param scanFilter Indicates the broadcast scan filter parameter {@link BcScanFilter}
 * @param filterNum Indicates the number of the filter parameter
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service get the scan filter succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerGetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum);

/**
 * @brief Check whether available resources are available by using the bcid
 *
 * @param bcId Indicates the service broadcast ID, when the service register successfully
 * @param status Indicates the status of available broadcast resources
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service query status succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerQueryBroadcastStatus(int32_t bcId, int32_t *status);

/**
 * @brief Check whether the device is a low-power device.
 *
 * @return Returns <b>true</b> if the device is a low-power device.
 * @return Returns false for not.
 *
 * @since 5.0
 * @version 1.0
 */
bool SchedulerIsLpDeviceAvailable(void);

/**
 * @brief Set low-power chip broadcast parameters, scanning parameters, scanning filters, and broadcast data.
 *
 * @param bcParam Indicates low-power chip broadcast parameters and broadcast data.
 * @param scanParam Indicates low power chip scan parameters and filters.
 *
 * @return Returns <b>true</b> if the service set parameters succ.
 * @return Returns false for failed.
 *
 * @since 5.0
 * @version 1.0
 */
bool SchedulerSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam);

/**
 * @brief Obtain the advHandle by advId.
 *
 * @param bcId Indicates the service broadcast ID, when the service register successfully
 * @param bcHandle Indicates Convert to bcHandle via advId.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service get the handle succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerGetBroadcastHandle(int32_t bcId, int32_t *bcHandle);

/**
 * @brief Enables data synchronization to a low-power chip.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service enable SyncData succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerEnableSyncDataToLpDevice(void);

/**
 * @brief Disables data synchronization to a low-power chip.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service disable syncData succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerDisableSyncDataToLpDevice(void);

/**
 * @brief set scanReport channel to a low-power chip.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service set scanReport channel succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerSetScanReportChannelToLpDevice(int32_t listenerId, bool enable);

/**
 * @brief set low-power broadcast channel parameters.
 *
 * @param duration Indicates broadcast duration.
 * @param maxExtAdvEvents Indicates maximum number of extended broadcast events.
 * @param window Indicates work window.
 * @param interval Indicates work interval.
 * @param bcHandle Indicates the broadcast handle.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service set low power broadcast parameters succ.
 * returns any other value for failed.
 *
 * @since 5.0
 * @version 1.0
 */
int32_t SchedulerSetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // BROADCAST_SCHEDULER_H

