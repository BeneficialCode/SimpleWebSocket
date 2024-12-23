#include <libwebsockets.h>
#include <signal.h>
#include <string.h>
#include <string>

#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"Userenv.lib")


static volatile int exit_sig = 0;
#define MAX_PAYLOAD_SIZE  10 * 1024

void sighdl(int sig) {
	lwsl_notice("%d traped", sig);
	exit_sig = 1;
}

/**
 * 会话上下文对象，结构根据需要自定义
 */
struct session_data {
	int msg_count;
	unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
	int len;
	bool bin;
	bool fin;
};

static int protocol_callback(struct lws* wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len) {
	struct session_data* data = (struct session_data*)user;
	switch (reason)
	{
		case LWS_CALLBACK_ESTABLISHED:
			printf("Client connect!\n");
			break;
		case LWS_CALLBACK_SERVER_WRITEABLE:
			lws_write(wsi, &data->buf[LWS_PRE], data->len, LWS_WRITE_TEXT);
			lws_rx_flow_control(wsi, 1);
			break;
		case LWS_CALLBACK_RECEIVE:
		{
			data->fin = lws_is_final_fragment(wsi);
			data->bin = lws_frame_is_binary(wsi);
			lws_rx_flow_control(wsi, 0);

			memcpy(&data->buf[LWS_PRE], in, len);
			data->len = len;

			std::string message((char*)in, len);
			printf("received message: %s\n", message.c_str());
			lws_callback_on_writable(wsi);
			data = nullptr;

			break;
		}
	}


	return 0;
}


struct lws_protocols protocols[] = {
	{
		"wss",protocol_callback,sizeof(struct session_data),MAX_PAYLOAD_SIZE,
	},
	{
		nullptr,nullptr,0
	}
};

int main(int argc, char** argv) {
	signal(SIGTERM, sighdl);

	struct lws_context_creation_info ctx_info = { 0 };
	ctx_info.port = 8000;
	ctx_info.iface = nullptr;
	ctx_info.protocols = protocols;
	ctx_info.gid = -1;
	ctx_info.uid = -1;
	ctx_info.options = LWS_SERVER_OPTION_VALIDATE_UTF8;

	ctx_info.ssl_ca_filepath = "./ca-cert.pem";
	ctx_info.ssl_cert_filepath = "./server-cert.pem";
	ctx_info.ssl_private_key_filepath = "./server-key.pem";
	ctx_info.ssl_private_key_password = "123.com";
	ctx_info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	struct lws_context* context = lws_create_context(&ctx_info);
	while (!exit_sig) {
		lws_service(context, 1000);
	}
	lws_context_destroy(context);

	return 0;
}

