#include <stdio.h>
#include "tuyalink_client.h"
#include "esp_log.h"
#include "cJSON.h"

#include "mbedtls/md.h"
#include <sys/time.h>

static const char *TAG = "TUYALINK_CLIENT";

static const char tuyalink_default_cacert[] = {"-----BEGIN CERTIFICATE-----\n"
"MIIDxTCCAq2gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx\n"
"EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT\n"
"EUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp\n"
"ZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIz\n"
"NTk1OVowgYMxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH\n"
"EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8GA1UE\n"
"AxMoR28gRGFkZHkgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw\n"
"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9xYgjx+lk09xvJGKP3gElY6SKD\n"
"E6bFIEMBO4Tx5oVJnyfq9oQbTqC023CYxzIBsQU+B07u9PpPL1kwIuerGVZr4oAH\n"
"/PMWdYA5UXvl+TW2dE6pjYIT5LY/qQOD+qK+ihVqf94Lw7YZFAXK6sOoBJQ7Rnwy\n"
"DfMAZiLIjWltNowRGLfTshxgtDj6AozO091GB94KPutdfMh8+7ArU6SSYmlRJQVh\n"
"GkSBjCypQ5Yj36w6gZoOKcUcqeldHraenjAKOc7xiID7S13MMuyFYkMlNAJWJwGR\n"
"tDtwKj9useiciAF9n9T521NtYJ2/LOdYq7hfRvzOxBsDPAnrSTFcaUaz4EcCAwEA\n"
"AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE\n"
"FDqahQcQZyi27/a9BUFuIMGU2g/eMA0GCSqGSIb3DQEBCwUAA4IBAQCZ21151fmX\n"
"WWcDYfF+OwYxdS2hII5PZYe096acvNjpL9DbWu7PdIxztDhC2gV7+AJ1uP2lsdeu\n"
"9tfeE8tTEH6KRtGX+rcuKxGrkLAngPnon1rpN5+r5N9ss4UXnT3ZJE95kTXWXwTr\n"
"gIOrmgIttRD02JDHBHNA7XIloKmf7J6raBKZV8aPEjoJpL1E/QYVN8Gb5DKj7Tjo\n"
"2GTzLH4U/ALqn83/B2gX2yKQOC16jdFU8WnjXzPKej17CuPKf1855eJ1usV2GDPO\n"
"LPAvTK33sefOT6jEm0pUBsV/fdUID+Ic/n4XuKxe9tQWskMJDE32p2u0mYRlynqI\n"
"4uJEvlz36hz1\n"
"-----END CERTIFICATE-----"};

static const char *tuyalink_client_region_uris[] =
{
    [TUYALINK_REGION_CHINA] = "mqtts://m1.tuyacn.com:8883",
    [TUYALINK_REGION_CENTRAL_EUROPE] = "mqtts://m1.tuyaeu.com:8883",
    [TUYALINK_REGION_WESTERN_AMERICA]  = "mqtts://m1.tuyaus.com:8883",
    [TUYALINK_REGION_EASTERN_AMERICA]  = "mqtts://m1-ueaz.tuyaus.com:8883",
    [TUYALINK_REGION_WESTERN_EUROPE]  = "mqtts://m1-weaz.tuyaeu.com	:8883",
    [TUYALINK_REGION_INDIA]  = "mqtts://m1.tuyain.com:8883", 
};

static const char *tuyalink_client_endpoints[] = {
	"thing/property/report",
	"thing/property/report_response",
	"thing/property/set",
	"thing/property/set_response",
};

static uint32_t get_timestamp() {
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec;
}

static void hmac256_create(unsigned char *key, size_t key_len, unsigned char *message, size_t message_len, unsigned char *out)
{
    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, message, message_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

static void create_credentials(const char *device_id, const char *device_secret, char *client_id, char *username, char *password) {
    uint32_t timestamp = get_timestamp();

    sprintf(username, "%s|signMethod=hmacSha256,timestamp=%d,secureMode=1,accessType=1", device_id, timestamp);

    sprintf(client_id, "tuyalink_%s", device_id);

    char password_raw[255];
    size_t password_raw_len = sprintf(password_raw, "deviceId=%s,timestamp=%d,secureMode=1,accessType=1", device_id, timestamp);

    unsigned char hmac[32];

    hmac256_create(device_secret, strlen(device_secret), (unsigned char*)password_raw, password_raw_len, hmac);

    for (int i = 0; i < 32; i++) {
        sprintf(password + 2*i, "%02x", hmac[i]);
    }
}

static void tuyalink_client_set_state(tuyalink_client_instance_t *client, tuyalink_client_status_t status) {
    client->status = status;
    (client->config->status_handler)(client, &client->status);
}

static void tuyalink_mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, event_id);
    esp_mqtt_event_handle_t event = event_data;
    tuyalink_client_instance_t *client = handler_args;
    switch ((esp_mqtt_event_id_t)event_id) {

        case MQTT_EVENT_BEFORE_CONNECT: ESP_LOGI(TAG, "MQTT_EVENT_BEFORE_CONNECT"); break;
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");

            char topic_auto_subscribe[64];
            sprintf(topic_auto_subscribe, "tylink/%s/channel/downlink/auto_subscribe", client->config->device_id);
            esp_mqtt_client_subscribe(client->mqtt_client, topic_auto_subscribe, 1);
            ESP_LOGI(TAG, "sent subscribe successful");
            tuyalink_client_set_state(client, TUYALINK_STATUS_CONNECTED);
            break;
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            tuyalink_client_set_state(client, TUYALINK_STATUS_DISCONNECTED);
            break;
        case MQTT_EVENT_SUBSCRIBED: ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id); break;
        case MQTT_EVENT_UNSUBSCRIBED: ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id); break;
        case MQTT_EVENT_PUBLISHED: ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id); break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");

            printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
            printf("DATA=%.*s\r\n", event->data_len, event->data);

            cJSON *message_json = cJSON_ParseWithLength(event->data, event->data_len);
            cJSON *msgid = cJSON_GetObjectItemCaseSensitive(message_json, "msgId"); 
            cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(message_json, "time"); 
            cJSON *data = cJSON_GetObjectItemCaseSensitive(message_json, "data"); 

            tuyalink_message_t message;

            char endpoint[128];
            strncpy(endpoint, event->topic + 30, event->topic_len - 29);

            for (size_t i = 0; i < sizeof(tuyalink_client_endpoints)/4; i++) {
                if(strncmp(endpoint, tuyalink_client_endpoints[i], event->topic_len - 29) == 0) {
                    message.endpoint = i;
                    break;
                }
            }
            
            if(cJSON_IsNumber(msgid) && msgid->valueint != NULL) {
                char msgid_int[32];
                sprintf(msgid_int, "%d", msgid->valueint);
                message.msgid = msgid_int;
            }
            if(cJSON_IsString(msgid) && msgid->valuestring != NULL) message.msgid = msgid->valuestring;
            if(cJSON_IsNumber(timestamp) && timestamp->valueint != NULL) message.timestamp = timestamp->valueint;
            if(cJSON_IsObject(data)) message.data = cJSON_Print(data);
            
            (client->config->message_handler)(client, &message);

            cJSON_Delete(message_json);

            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
                ESP_LOGI(TAG, "Last error code reported from esp-tls: 0x%x", event->error_handle->esp_tls_last_esp_err);
                ESP_LOGI(TAG, "Last tls stack error number: 0x%x", event->error_handle->esp_tls_stack_err);
                ESP_LOGI(TAG, "Last captured errno : %d (%s)",  event->error_handle->esp_transport_sock_errno,
                        strerror(event->error_handle->esp_transport_sock_errno));
            } else if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
                ESP_LOGI(TAG, "Connection refused error: 0x%x", event->error_handle->connect_return_code);
            } else {
                ESP_LOGW(TAG, "Unknown error type: 0x%x", event->error_handle->error_type);
            }
            break;
        default: ESP_LOGI(TAG, "Other event id:%d", event->event_id); break;
    }
}

const char *tuyalink_get_region_uri(tuyalink_client_region_t region) {
    return tuyalink_client_region_uris[region];
}

tuyalink_client_instance_t *tuyalink_client_init(const tuyalink_client_config_t *config) {
    tuyalink_client_instance_t *client = calloc(1, sizeof(tuyalink_client_instance_t));
    
    char client_id[32];
    char username[92];
    char password[96];

    create_credentials(config->device_id, config->device_secret, client_id, username, password);

    const esp_mqtt_client_config_t mqtt_cfg = {
        .uri = config->uri,
        .keepalive = 60,
        .cert_pem = tuyalink_default_cacert,
        .client_id = client_id,
        .username = username,
        .password = password,
    };

    client->mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client->mqtt_client, ESP_EVENT_ANY_ID, tuyalink_mqtt_event_handler, client);
    client->config = config;
    client->status = TUYALINK_STATUS_DISCONNECTED;
    
    return client;
}

void tuyalink_client_start(tuyalink_client_instance_t *client) {
    esp_mqtt_client_start(client->mqtt_client);
    tuyalink_client_set_state(client, TUYALINK_STATUS_CONNECTING);
}

void tuyalink_client_destroy(tuyalink_client_instance_t *client) {
    if (client) {
        if (client->mqtt_client) esp_mqtt_client_destroy(client->mqtt_client);
        free(client);
    }
}

void tuyalink_message_send(tuyalink_client_instance_t *client, tuyalink_message_t *message) {
    cJSON *message_json = cJSON_CreateObject();

    cJSON_AddStringToObject(message_json, "msgId", message->msgid);
    cJSON_AddNumberToObject(message_json, "time", message->timestamp ? message->timestamp : get_timestamp());

    if(message->data) cJSON_AddRawToObject(message_json, "data", message->data);
    if(message->ack) cJSON_AddRawToObject(message_json, "sys", "{\"ack\":1}");

    char *payload = cJSON_Print(message_json);
    cJSON_Delete(message_json);
    size_t payload_len = strlen(payload) * sizeof(char);

    char topic_path[128];
	sprintf(topic_path, "tylink/%s/%s", client->config->device_id, tuyalink_client_endpoints[message->endpoint]);

    ESP_LOGI(TAG, "publish topic:%s", topic_path);
	ESP_LOGI(TAG, "payload size:%d, %s\r\n", payload_len, payload);
	int msg_id = esp_mqtt_client_publish(client->mqtt_client, topic_path, payload, payload_len, 0, 0);
    ESP_LOGI(TAG, "publish successful, msg_id=%d", msg_id);

    free(payload);
}
