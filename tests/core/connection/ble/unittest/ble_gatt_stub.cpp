#include "softbus_conn_ble_client.h"
#include "softbus_conn_ble_server.h"
#include "softbus_error_code.h"

int32_t ConnGattClientConnect(ConnBleConnection *connection)
{
    (void)connection;
    return SOFTBUS_ERR;
}

int32_t ConnGattClientDisconnect(ConnBleConnection *connection, bool grace, bool refreshGatt)
{
    (void)connection;
    (void)grace;
    (void)refreshGatt;
    return SOFTBUS_ERR;
}

int32_t ConnGattClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    (void)connection;
    (void)data;
    (void)dataLen;
    (void)module;
    return SOFTBUS_ERR;
}

int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    (void)connection;
    (void)priority;
    return SOFTBUS_ERR;
}

int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener)
{
    (void)looper;
    (void)listener;
    return SOFTBUS_ERR;
}

int32_t ConnGattServerStartService(void)
{
    return SOFTBUS_ERR;
}

int32_t ConnGattServerStopService(void)
{
    return SOFTBUS_ERR;
}

int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    (void)connection;
    (void)data;
    (void)dataLen;
    (void)module;
    return SOFTBUS_ERR;
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    (void)connection;
    return SOFTBUS_ERR;
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    (void)connection;
    return SOFTBUS_ERR;
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener)
{
    (void)looper;
    (void)listener;
    return SOFTBUS_ERR;
}
