#include <libwebsockets.h>
#include <signal.h>
#include <string>

static volatile int exit_sig = 0;
#define MAX_PAYLOAD_SIZE 10 * 1024

void sighdl(int sig) {
    lwsl_notice("%d trapped\n", sig);
    exit_sig = 1;
}

struct session_data {
    int msg_count;
    unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
    int len;
};

int protocol_callback(struct lws* wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len) {
    struct session_data* data = (struct session_data*)user;
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            lwsl_notice("Connected to server ok!\n");
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            std::string message((char*)in, len);
            lwsl_notice("Rx: %s\n", message.c_str());
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            if (data->msg_count < 3) {
                memset(data->buf, 0, sizeof(data->buf));
                char* msg = (char*)&data->buf[LWS_PRE];
                data->len = sprintf_s(msg, sizeof(data->buf) - LWS_PRE, "ÄãºÃ %d", ++data->msg_count);
                lwsl_notice("Tx: %s\n", msg);
                lws_write(wsi, &data->buf[LWS_PRE], data->len, LWS_WRITE_TEXT);
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            lwsl_err("CLIENT_CONNECTION_ERROR: %s\n", in ? (char*)in : "(null)");
            exit_sig = 1; // Exit on connection error
            break;
        }

        default:
            break;
    }

    return 0;
}

struct lws_protocols protocols[] = {
    {
        "wss", protocol_callback, sizeof(struct session_data), MAX_PAYLOAD_SIZE,
    },
    LWS_PROTOCOL_LIST_TERM
};

int main() {
    signal(SIGTERM, sighdl);
    signal(SIGINT, sighdl); // Handle Ctrl+C

    struct lws_context_creation_info ctx_info = { 0 };
    ctx_info.port = CONTEXT_PORT_NO_LISTEN;
    ctx_info.iface = nullptr;
    ctx_info.protocols = protocols;
    ctx_info.gid = -1;
    ctx_info.uid = -1;

    ctx_info.ssl_ca_filepath = "./ca-cert.pem";
    ctx_info.ssl_cert_filepath = "./client-cert.pem";
    ctx_info.ssl_private_key_filepath = "./client-key.pem";
    ctx_info.ssl_private_key_password = "123.com";
    ctx_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    struct lws_context* context = lws_create_context(&ctx_info);
    if (!context) {
        lwsl_err("lws_create_context failed\n");
        return -1;
    }

    char address[] = "127.0.0.1";
    int port = 8000;

    char addr_port[256] = { 0 };
    sprintf_s(addr_port, sizeof(addr_port), "%s:%u", address, port);

    struct lws_client_connect_info conn_info = { 0 };
    conn_info.context = context;
    conn_info.address = address;
    conn_info.port = port;
    conn_info.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED| LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK; // Allow self-signed certs
    conn_info.path = "./";
    conn_info.host = addr_port;
    conn_info.origin = addr_port;
    conn_info.protocol = protocols[0].name;

    struct lws* wsi = lws_client_connect_via_info(&conn_info);
    if (!wsi) {
        lwsl_err("lws_client_connect_via_info failed\n");
        lws_context_destroy(context);
        return -1;
    }

    while (!exit_sig) {
        lws_service(context, 1000);
        lws_callback_on_writable(wsi);
    }

    lws_context_destroy(context);

    return 0;
}