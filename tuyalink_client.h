#ifndef _TUYALINK_CLIENT_H_
#define _TUYALINK_CLIENT_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mqtt_client.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TUYALINK_REGION_CHINA,
    TUYALINK_REGION_CENTRAL_EUROPE,
    TUYALINK_REGION_WESTERN_AMERICA,
    TUYALINK_REGION_EASTERN_AMERICA,
    TUYALINK_REGION_WESTERN_EUROPE,
    TUYALINK_REGION_INDIA,
} tuyalink_client_region_t;

typedef enum {
    TUYALINK_ENDPOINT_PROPERTY_REPORT,
    TUYALINK_ENDPOINT_PROPERTY_REPORT_RESPONSE,
    TUYALINK_ENDPOINT_PROPERTY_SET,
    TUYALINK_ENDPOINT_PROPERTY_SET_RESPONSE,
} tuyalink_client_endpoint_t;

typedef enum {
    TUYALINK_STATUS_CONNECTING,
    TUYALINK_STATUS_CONNECTED,
    TUYALINK_STATUS_DISCONNECTED,
} tuyalink_client_status_t;

typedef struct {
    const char *uri;
    const char *device_id;
    const char *device_secret;
    void (*message_handler)(void *, void *);
    void (*status_handler)(void *, void *);
} tuyalink_client_config_t;

typedef struct {
    const tuyalink_client_config_t *config;
    esp_mqtt_client_handle_t mqtt_client;
    tuyalink_client_status_t status;
} tuyalink_client_instance_t;

typedef struct {
    char *endpoint;
    uint32_t timestamp;
    uint32_t code;
    char *device_id;
    char *msgid;
    char *data;
    size_t data_len;
    bool ack;
} tuyalink_message_t;

const char *tuyalink_get_region_uri(tuyalink_client_region_t region);

const char *tuyalink_get_endpoint(tuyalink_client_endpoint_t endpoint);

tuyalink_client_instance_t *tuyalink_client_init(const tuyalink_client_config_t *config);

void tuyalink_client_start(tuyalink_client_instance_t *client);

void tuyalink_client_destroy(tuyalink_client_instance_t *client);

void tuyalink_message_send(tuyalink_client_instance_t *client, tuyalink_message_t *message);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif