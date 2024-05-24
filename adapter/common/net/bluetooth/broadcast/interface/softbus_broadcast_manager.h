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
 * @file softbus_broadcast_manager.h
 * @brief
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_MANAGER_H
#define SOFTBUS_BROADCAST_MANAGER_H

#include "softbus_broadcast_type.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines the broadcast callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnStopBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnUpdateBroadcastingCallback)(int32_t bcId, int32_t status);
    void (*OnSetBroadcastingCallback)(int32_t bcId, int32_t status);
} BroadcastCallback;

/**
 * @brief Defines the broadcast scan callback function.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    void (*OnStartScanCallback)(int32_t listenerId, int32_t status);
    void (*OnStopScanCallback)(int32_t listenerId, int32_t status);
    void (*OnReportScanDataCallback)(int32_t listenerId, const BroadcastReportInfo *reportInfo);
    void (*OnScanStateChanged)(int32_t resultCode, bool isStartScan);
    void (*OnLpDeviceInfoCallback)(const BroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize);
} ScanCallback;

/**
 * @brief init broadcast manager.
 *
 * @return Returns <b>0</b> If the broadcast management initialization fails;
 * returns any other value if the request fails.
 * @since 4.1
 * @version 1.0
 */
int32_t InitBroadcastMgr(void);

/**
 * @brief init broadcast manager.
 *
 * @return Returns <b>SOFTBUS_OK</b> If the broadcast management deinitialization fails;
 * returns any other value if the request fails.
 * @since 4.1
 * @version 1.0
 */
int32_t DeInitBroadcastMgr(void);

/**
 * @brief Register the service to the broadcast manager.
 *
 * @param type Indicates the service type {@link BaseServiceType}.
 * @param bcId Indicates the service broadcast ID.
 * @param cb Indicates the service broadcast callback {@link BroadcastCallback}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service register is successful.
 * returns any other value if the register fails.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t RegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb);

/**
 * @brief UnRegister the service to the broadcast manager.
 *
 * @param bcId Indicates the service broadcast ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister is successful.
 * returns any other value if the unregister fails.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t UnRegisterBroadcaster(int32_t bcId);

/**
 * @brief Register the service listener to the broadcast manager.
 *
 * @param type Indicates the service type {@link BaseServiceType}.
 * @param listenerId Indicates the service listener ID.
 * @param cb Indicates the service listener callback {@link ScanCallback}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service register is successful.
 * returns any other value if the register fails.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t RegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);

/**
 * @brief UnRegister the service listener to the broadcast manager.
 *
 * @param listenerId Indicates the service listener ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service unregister is successful.
 * returns any other value if the unregister fails.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t UnRegisterScanListener(int32_t listenerId);

/**
 * @brief The service enable broadcast
 *
 * @param bcId Indicates the service broadcast ID.
 * @param param Indicates the pointer to the service parameter information. For details, see {@link BroadcastParam}.
 * @param packet Indicates the pointer to the service advertising data. For details, see {@link BroadcastPacket}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service starts the broadcast successfully.
 * returns any other value if the unregister fails.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);

/**
 * @brief The service update broadcast data and parameters.When the broadcast is updated,
 * the broadcast is stopped and then started.
 *
 * @param bcId Indicates the service broadcast ID.
 * @param param Indicates the pointer to the service parameter information. For details, see {@link BroadcastParam}.
 * @param bcData Indicates the pointer to the service advertising data. For details, see {@link BroadcastPacket}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service updates the broadcast successfully.
 * returns any other value if the service fails to update the broadcast.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);

/**
 * @brief The service set broadcast data. Set broadcast data when broadcast is enabled.
 *
 * @param bcId Indicates the service broadcast ID.
 * @param packet Indicates the pointer to the service advertising data. For details, see {@link BroadcastPacket}.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service starts the broadcast successfully.
 * returns any other value if the unregister fails.
 *
 * @since 4.1
 * @version 1.0
 */

int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet);
/**
 * @brief The service stop broadcast
 *
 * @param bcId Indicates the service broadcast ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service stop the broadcast successfully.
 * returns any other value if the service fails to stop the broadcast.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t StopBroadcasting(int32_t bcId);

/**
 * @brief The service enable broadcast scanning
 *
 * @param listenerId Indicates the service listener ID.
 * @param param Indicates the broadcast scan parameter {@link BcScanParams}
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service start to scan the broadcast successfully.
 * returns any other value if the service fails to scan the broadcast.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t StartScan(int32_t listenerId, const BcScanParams *param);

/**
 * @brief The service stop broadcast scanning
 *
 * @param listenerId Indicates the service listener ID.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service stop to scan the broadcast successfully.
 * returns any other value if the service fails to stop scanning the broadcast.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t StopScan(int32_t listenerId);

/**
 * @brief Set the Scan Filter object
 *
 * @param listenerId Indicates the service listener ID.
 * @param scanFilter Indicates the broadcast scan filter parameter {@link BcScanFilter}
 * @param filterNum Indicates the number of the filter parameter
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service set the Scan Filter successfully.
 * returns any other value if the service fails to set the Scan Filter.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);

/**
 * @brief Get the Scan Filter object
 *
 * @param listenerId Indicates the service listener ID.
 * @param scanFilter Indicates the broadcast scan filter parameter {@link BcScanFilter}
 * @param filterNum Indicates the number of the filter parameter
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service get the Scan Filter successfully.
 * returns any other value if the service fails to get the Scan Filter.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t GetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum);

/**
 * @brief Check whether available resources are available by using the bcid
 *
 * @param bcId Indicates the service broadcast ID, when the service register successfully
 * @param status Indicates the status of available broadcast resources
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service query status successfully.
 * returns any other value if the service fails to query status.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t QueryBroadcastStatus(int32_t bcId, int32_t *status);

/**
 * @brief Check whether the device is a low-power device.
 *
 * @return Returns <b>true</b> if the device is a low-power device.
 * @return returns false value if the service fails to query a low-power device.
 *
 * @since 4.1
 * @version 1.0
 */
bool BroadcastIsLpDeviceAvailable(void);

/**
 * @brief Set low-power chip broadcast parameters, scanning parameters, scanning filters, and broadcast data.
 *
 * @param bcParam Indicates low-power chip broadcast parameters and broadcast data.
 * @param scanParam Indicates low power chip scan parameters and filters.
 *
 * @return Returns <b>true</b> if the service set parameters successfully.
 * @return returns false value if the service fails set parameters.
 *
 * @since 4.1
 * @version 1.0
 */
bool BroadcastSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam);

/**
 * @brief Obtain the advHandle using advId.
 *
 * @param bcId Indicates the service broadcast ID, when the service register successfully
 * @param bcHandle Indicates Convert to bcHandle via advId,.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service get the handle successfully.
 * returns any other value if the service fails to get the handle.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle);

/**
 * @brief Enables data synchronization to a low-power chip.
 *
* @return Returns <b>SOFTBUS_OK</b> if the service enable SyncData successfully.
 * returns any other value if the service fails to enable SyncData.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t BroadcastEnableSyncDataToLpDevice(void);

/**
 * @brief Disables data synchronization to a low-power chip.
 *
* @return Returns <b>SOFTBUS_OK</b> if the service disable syncData successfully.
 * returns any other value if the service fails to disable syncData.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t BroadcastDisableSyncDataToLpDevice(void);

/**
 * @brief set scanReport channel to a low-power chip.
 *
* @return Returns <b>SOFTBUS_OK</b> if the service set scanReport channel successfully.
 * returns any other value if the service fails to set scanReport channel.
 *
 * @since 4.1
 * @version 1.0
 */
int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable);

/**
 * @brief set low-power broadcast channel parameters.
 *
 * @param duration Indicates broadcast duration.
 * @param maxExtAdvEvents Indicates maximum number of extended broadcast events.
 * @param window Indicates work window.
 * @param interval Indicates work interval.
 * @param bcHandle Indicates the broadcast handle.
 *
 * @return Returns <b>SOFTBUS_OK</b> if the service set low power broadcast parameters successfully.
 * returns any other value if the service fails to set low power broadcast parameters.
 *
 * @since 1.0
 * @version 1.0
 */
int32_t BroadcastSetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle);

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_MANAGER_H */
