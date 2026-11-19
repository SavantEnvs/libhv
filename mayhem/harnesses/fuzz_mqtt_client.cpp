// MQTT broker -> client: libhv's mqtt_client (mqtt/mqtt_client.c on_packet: CONNACK, PUBLISH,
// SUBACK, ... and the varint length unpacking) receives the fuzz input as the broker's byte
// stream. Per input: a fresh hloop holds an in-process TCP listener on 127.0.0.1 that sends the
// input to the client that connects, then half-closes; the loop stops when the client sees
// the connection close. Reconnect is off (the default), so the loop always drains.
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "hloop.h"
#include "mqtt_client.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

static const uint8_t* g_data;
static size_t g_size;
static int g_events;

static void srv_on_write(hio_t* io, const void*, int) {
    if (hio_write_is_complete(io)) shutdown(hio_fd(io), SHUT_WR);
}
static void srv_on_read(hio_t*, void*, int) {}
static void srv_on_accept(hio_t* io) {
    hio_setcb_read(io, srv_on_read);
    hio_read(io);
    hio_setcb_write(io, srv_on_write);
    if (g_size == 0) { shutdown(hio_fd(io), SHUT_WR); return; }
    hio_write(io, g_data, g_size);
    if (hio_write_is_complete(io)) shutdown(hio_fd(io), SHUT_WR);
}

static void cli_cb(mqtt_client_t* cli, int type) {
    g_events++;
    if (type == MQTT_TYPE_CONNACK) {
        // exercise the client's send path once the broker accepted us
        mqtt_client_subscribe(cli, "fuzz/#", 1);
    }
    if (type == MQTT_TYPE_DISCONNECT) hloop_stop((hloop_t*)mqtt_client_get_userdata(cli));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > (1 << 20)) return -1;
    g_data = data; g_size = size;
    hloop_t* loop = hloop_new(0);
    hio_t* listenio = hloop_create_tcp_server(loop, "127.0.0.1", 0, srv_on_accept);
    if (!listenio) { hloop_free(&loop); return 0; }
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    getsockname(hio_fd(listenio), (struct sockaddr*)&addr, &alen);
    int port = ntohs(addr.sin_port);

    mqtt_client_t* cli = mqtt_client_new(loop);
    mqtt_client_set_userdata(cli, loop);
    mqtt_client_set_id(cli, "fuzz");
    mqtt_client_set_callback(cli, cli_cb);
    if (mqtt_client_connect(cli, "127.0.0.1", port, 0) == 0) {
        hloop_run(loop);
    }
    mqtt_client_free(cli);
    hloop_free(&loop);
    return 0;
}
