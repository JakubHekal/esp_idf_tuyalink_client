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

typedef struct {
    const char *uri;
    const char *device_id;
    const char *device_secret;
    void (*message_handler)(void);
} tuyalink_client_config_t;

typedef struct {
    const tuyalink_client_config_t *config;
    esp_mqtt_client_handle_t mqtt_client;
    bool connected;
} tuyalink_client_instance_t;

typedef struct {
    uint32_t timestamp;
    uint32_t code;
    char *device_id;
    char *msgid;
    char *data;
    size_t data_len;
    bool ack;
} tuyalink_message_t;

const char *tuyalink_get_region_uri(tuyalink_client_region_t region);

tuyalink_client_instance_t *tuyalink_client_init(const tuyalink_client_config_t *config);

void tuyalink_client_start(tuyalink_client_instance_t *client);

void tuyalink_message_send(tuyalink_client_instance_t *client, char *topic, tuyalink_message_t *message);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif