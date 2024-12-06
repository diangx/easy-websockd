#include <libwebsockets.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <openssl/hmac.h>
#include <unistd.h>
#include <time.h>

#define MAX_WSI_COUNT   10          // max client

#define DEFAULT_PORT 8000           // websocket port
#define DEFAULT_LOG_FILE "/var/log/easy-websockd.log" // log file path
#define DEFAULT_KEY "007208e6b9ff54e974c08635397b12f4" // HMAC Key
#define LWS_PATH_MAX    256         // max path length
#define LWS_BODY_MAX    1048576     // max body size (1MB)
#define LWS_BUFFER_SIZE 16384       // buffer size (16KB)

int PORT = DEFAULT_PORT;
const char *LOG_FILE = DEFAULT_LOG_FILE;
const char *key = DEFAULT_KEY;

typedef struct per_session_data {
    struct lws *wsi; // WebSocket connection handle
    char client_ip[LWS_PATH_MAX]; // client ip
    char client_sid[LWS_PATH_MAX]; // client sid
    char client_perm[LWS_PATH_MAX]; // client permission
    int values_stored; // flag for array save (1 : save true, 0: save false)
} per_session_data_t;

typedef struct session_user_data {
    per_session_data_t *psds[MAX_WSI_COUNT]; // client management array
    int psd_count; // curren client connected count
} session_user_data_t;

pthread_mutex_t lock; // mutex
session_user_data_t session_user;

// log write
void log_to_file(const char *message) {
    if (!LOG_FILE) return;

    FILE *file = fopen(LOG_FILE, "a");
    if (file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
        fprintf(file, "[%s] %s\n", timestamp, message);
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open log file: %s\n", LOG_FILE);
    }
}

// ubus exec
char *execute_ubus_command(const char *path, const char *action, const char *msg) {
    char command[1024];
    snprintf(command, sizeof(command), "ubus call %s %s '%s'", path, action, msg);

    // log_to_file(command); // command
    FILE *cmd_output = popen(command, "r");
    if (!cmd_output) {
        log_to_file("Failed to execute ubus command.");
        return NULL;
    }

    static char result[LWS_BODY_MAX];
    memset(result, 0, sizeof(result));
    fread(result, 1, sizeof(result) - 1, cmd_output);
    pclose(cmd_output);

    // log_to_file(result); // command result
    return result;
}

// hash verification
int verify_hash(const char *params, const char *received_hash) {
    if (!params || !received_hash) {
        log_to_file("Invalid parameters for hash verification.");
        return 0;
    }

    char *cleaned_params = strdup(params);
    if (!cleaned_params) {
        log_to_file("Memory allocation failed for cleaned_params.");
        return 0;
    }

    char *src = cleaned_params;
    char *dst = cleaned_params;
    while (*src) {
        if (src[0] == '\\' && src[1] == '/') {
            src++;
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    unsigned char recalculated_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    HMAC(EVP_sha256(), key, strlen(key),
         (unsigned char *)cleaned_params, strlen(cleaned_params),
         recalculated_hash, &hash_len);

    char recalculated_hash_hex[2 * hash_len + 1];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&recalculated_hash_hex[i * 2], "%02x", recalculated_hash[i]);
    }
    recalculated_hash_hex[2 * hash_len] = '\0';

    int result = strcmp(received_hash, recalculated_hash_hex) == 0;

    free(cleaned_params);

    return result;
}

// send error to client
void send_error_to_client(struct lws *wsi, int error_code, const char *error_message) {
    struct json_object *response_obj = json_object_new_object();
    struct json_object *error_obj = json_object_new_object();

    json_object_object_add(error_obj, "code", json_object_new_int(error_code));
    json_object_object_add(error_obj, "message", json_object_new_string(error_message));
    json_object_object_add(response_obj, "error", error_obj);

    json_object_object_add(response_obj, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(response_obj, "id", NULL); // NULL when ID is not exist

    // crate json
    const char *response_str = json_object_to_json_string(response_obj);

    // ready for websocket buffer
    unsigned char buffer[LWS_PRE + LWS_BUFFER_SIZE];
    size_t response_len = strlen(response_str);
    memcpy(&buffer[LWS_PRE], response_str, response_len);

    // send websocket
    int ret = lws_write(wsi, &buffer[LWS_PRE], response_len, LWS_WRITE_TEXT);
    if (ret < 0) {
        log_to_file("Failed to send error message to WebSocket client.");
    }

    json_object_put(response_obj);
}

// websocket callback
static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            pthread_mutex_lock(&lock);

            if (session_user.psd_count >= MAX_WSI_COUNT) {
                pthread_mutex_unlock(&lock);
                log_to_file("Max clients reached, rejecting connection.");
                return -1;
            }

            per_session_data_t *psd = malloc(sizeof(per_session_data_t));
            if (!psd) {
                pthread_mutex_unlock(&lock);
                log_to_file("Failed to allocate memory for client.");
                return -1;
            }

            char client_ip[LWS_PATH_MAX] = {0};
            lws_hdr_copy(wsi, client_ip, sizeof(client_ip), WSI_TOKEN_HTTP_X_REAL_IP);
            if (strlen(client_ip) == 0) {
                strncpy(client_ip, "unknown", LWS_PATH_MAX);
            }
            strncpy(psd->client_ip, client_ip, LWS_PATH_MAX);
            psd->wsi = wsi;

            session_user.psds[session_user.psd_count++] = psd;
            session_user.psds[session_user.psd_count-1]->values_stored = 0;

            char log_msg[LWS_PATH_MAX + 64];
            snprintf(log_msg, sizeof(log_msg), "< LWS_ESTABLISHED > INDEX : %d, IP: %s, Total clients: %d", session_user.psd_count-1, client_ip, session_user.psd_count);
            log_to_file(log_msg);

            pthread_mutex_unlock(&lock);
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            // char log_msg[512];
            // snprintf(log_msg, sizeof(log_msg), "Received message: %.*s", (int)len, (char *)in);
            // log_to_file(log_msg);

            struct json_object *request = json_tokener_parse((char *)in);
            if (!request) {
                log_to_file("Invalid JSON format.");
                break;
            }

            struct json_object *method_obj, *params_obj, *hash_obj, *sid_obj;
            if (json_object_object_get_ex(request, "method", &method_obj) &&
                json_object_object_get_ex(request, "params", &params_obj) &&
                json_object_object_get_ex(request, "hash", &hash_obj)&&
                json_object_object_get_ex(params_obj, "sid", &sid_obj)) {

                const char *method = json_object_get_string(method_obj);
                const char *received_hash = json_object_get_string(hash_obj);
                const char *params_string = json_object_to_json_string_ext(params_obj, JSON_C_TO_STRING_PLAIN);

                int process_complete = 0;

                for (int i = 0; i < session_user.psd_count; i++) {
                    if (session_user.psds[i]->wsi == wsi) {
                        const char *sid = json_object_get_string(sid_obj);
                        if (!sid) { // return when sid is NULL
                            send_error_to_client(session_user.psds[i]->wsi, 5000, "session not found.");
                            return -1;
                        }

                        char ubus_query[512];
                        snprintf(ubus_query, sizeof(ubus_query), "{\"ubus_rpc_session\":\"%s\"}", sid);

                        char *result_sid = execute_ubus_command("session", "get", ubus_query);
                        char username_buf[LWS_PATH_MAX] = "unknown";

                        if (result_sid) {
                            struct json_object *root = json_tokener_parse(result_sid);
                            if (root) {
                                struct json_object *values, *username;
                                if (json_object_object_get_ex(root, "values", &values) &&
                                    json_object_object_get_ex(values, "username", &username) &&
                                    json_object_is_type(username, json_type_string)) {
                                    const char *username_str = json_object_get_string(username);
                                    if (username_str) {
                                        strncpy(username_buf, username_str, LWS_PATH_MAX - 1);
                                        username_buf[LWS_PATH_MAX - 1] = '\0';
                                    }
                                }
                                json_object_put(root);
                            }
                            free(result_sid);
                        }

                        if (strcmp(username_buf, "unknown") == 0) { // client session of username not exist (ubus call session get)
                            send_error_to_client(session_user.psds[i]->wsi, 5001, "username unknown.");
                            lws_set_timeout(session_user.psds[i]->wsi, PENDING_TIMEOUT_CLOSE_SEND, 1);
                            // return 0;
                        }
                        else if (session_user.psds[i]->values_stored) { // already exist client value
                            process_complete = 1;
                            continue;
                        }
                        else { // save client info
                            strncpy(session_user.psds[i]->client_sid, sid, LWS_PATH_MAX - 1);
                            session_user.psds[i]->client_sid[LWS_PATH_MAX - 1] = '\0';

                            strncpy(session_user.psds[i]->client_perm, username_buf, LWS_PATH_MAX - 1);
                            session_user.psds[i]->client_perm[LWS_PATH_MAX - 1] = '\0';

                            char log_msg_info_connect[LWS_PATH_MAX + 128];
                            snprintf(log_msg_info_connect, sizeof(log_msg_info_connect),
                                    "<< LWS_RECEIVE >> INDEX: %d, IP: %s, WSI: %p, SID: %s, PERM: %s",
                                    i,
                                    session_user.psds[i]->client_ip ? session_user.psds[i]->client_ip : "unknown",
                                    (void *)session_user.psds[i]->wsi,
                                    session_user.psds[i]->client_sid,
                                    session_user.psds[i]->client_perm);
                            log_to_file(log_msg_info_connect);

                            for (int j = 0; j < session_user.psd_count; j++) {
                                if (i != j &&
                                    session_user.psds[j]->wsi != wsi && 
                                    strcmp(session_user.psds[j]->client_ip, session_user.psds[i]->client_ip) != 0 &&
                                    strcmp(session_user.psds[j]->client_perm, session_user.psds[i]->client_perm) == 0) {
                                        log_to_file("Other IP Client init.");
                                        send_error_to_client(session_user.psds[j]->wsi, 5002, "other ip init. logout");
                                        send_error_to_client(session_user.psds[i]->wsi, 5003, "other ip init. login");
                                }
                            }

                            session_user.psds[i]->values_stored = 1;
                            process_complete = 1;
                        }
                    }
                }

                if (process_complete) {
                    if (!verify_hash(params_string, received_hash)) {
                        log_to_file("Hash mismatch. Dropping message.");
                        json_object_put(request);
                        break;
                    }

                    if (strcmp(method, "ubus") == 0) {
                        struct json_object *path_obj, *action_obj, *msg_obj;
                        if (json_object_object_get_ex(params_obj, "path", &path_obj) &&
                            json_object_object_get_ex(params_obj, "action", &action_obj)) {
                            const char *path = json_object_get_string(path_obj);
                            const char *action = json_object_get_string(action_obj);
                            const char *msg = json_object_object_get_ex(params_obj, "msg", &msg_obj)
                                                ? json_object_to_json_string(msg_obj)
                                                : "{}";

                            char *result = execute_ubus_command(path, action, msg);
                            if (!result) {
                                log_to_file("Failed to execute ubus command or no response.");
                                break;
                            }

                            struct json_object *response_obj = json_tokener_parse(result);
                            if (!response_obj) {
                                response_obj = json_object_new_object();
                            }

                            struct json_object *response = json_object_new_object();
                            json_object_object_add(response, "jsonrpc", json_object_new_string("2.0"));

                            struct json_object *id_obj;
                            if (json_object_object_get_ex(request, "id", &id_obj)) {
                                json_object_object_add(response, "id", id_obj);
                            }
                            json_object_object_add(response, "result", response_obj);

                            const char *response_str = json_object_to_json_string(response);

                            unsigned char buffer[LWS_PRE + LWS_BUFFER_SIZE];
                            size_t response_len = strlen(response_str);

                            memcpy(&buffer[LWS_PRE], response_str, response_len);
                            if (lws_write(wsi, &buffer[LWS_PRE], response_len, LWS_WRITE_TEXT) < 0) {
                                log_to_file("Failed to send response.");
                            }

                            json_object_put(response);
                        }
                    }
                }
            } else {
                log_to_file("Invalid JSON-RPC format.");
            }

            json_object_put(request);
            break;
        }

        case LWS_CALLBACK_CLOSED: {
            pthread_mutex_lock(&lock);

            for (int i = 0; i < session_user.psd_count; ++i) {
                if (session_user.psds[i]->wsi == wsi) {
                    char log_msg[LWS_PATH_MAX + 256];
                    snprintf(log_msg, sizeof(log_msg), "<<< LWS_CALLBACK_CLOSED >>> INDEX: %d, IP: %s, Total clients: %d", i, session_user.psds[i]->client_ip, session_user.psd_count - 1);
                    log_to_file(log_msg);

                    char ubus_query[512];
                    snprintf(ubus_query, sizeof(ubus_query), "{\"ubus_rpc_session\":\"%s\"}", session_user.psds[i]->client_sid);
                    execute_ubus_command("session", "destroy", ubus_query);

                    free(session_user.psds[i]);
                    session_user.psds[i] = NULL;

                    for (int j = i; j < session_user.psd_count - 1; ++j) {
                        session_user.psds[j] = session_user.psds[j + 1];
                    }

                    session_user.psd_count--;
                    break;
                }
            }

            pthread_mutex_unlock(&lock);
            break;
        }

        default:
            break;
    }
    return 0;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:l:")) != -1) {
        switch (opt) {
            case 'p':
                PORT = atoi(optarg);
                break;
            case 'l':
                LOG_FILE = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-l log_file]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    struct lws_context_creation_info info;
    struct lws_protocols protocols[] = {
        { "jsonrpc", websocket_callback, sizeof(per_session_data_t), LWS_BUFFER_SIZE },
        { NULL, NULL, 0, 0 }
    };

    pthread_mutex_init(&lock, NULL);
    session_user.psd_count = 0;
    memset(session_user.psds, 0, sizeof(session_user.psds));

    memset(&info, 0, sizeof(info));
    info.port = PORT;
    info.protocols = protocols;

    info.max_http_header_data = LWS_BUFFER_SIZE;
    info.max_http_header_pool = MAX_WSI_COUNT;
    info.timeout_secs = 0;

    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        log_to_file("Failed to create lws context.");
        return 1;
    }

    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "WebSocket server started on ws://localhost:%d", PORT);
    log_to_file(log_msg);

    while (1) {
        lws_service(context, 1000);
    }

    lws_context_destroy(context);
    pthread_mutex_destroy(&lock);
    return 0;
}
