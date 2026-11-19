// TCP stream reassembly (event/unpack.c via the public hio_set_unpack): fixed-length,
// delimiter and length-field framing (big/little endian, varint, ASN.1, adjustment) plus the
// hio read-buffer growth in hevent.c/nio.c. The input is a 12-byte framing setting followed by
// the stream bytes, which are written into one end of a socketpair; the other end is an hio in a
// fresh hloop that runs until the peer's EOF (or an unpack error) closes it.
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hloop.h"
#include "fuzz_common.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) { fuzz_quiet_logs(); return 0; }

static unsigned long g_bytes;
static void on_read(hio_t*, void*, int len) { g_bytes += len; }
static void on_close(hio_t* io) { hloop_stop(hevent_loop(io)); }

// Socket buffer room for one write before the loop runs (the writer is not event driven).
static const size_t kMaxStream = 100000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 12 || size - 12 > kMaxStream) return -1;
    // hio_set_unpack asserts these preconditions on the setting (hevent.c), so the harness only
    // builds settings that satisfy them: fixed_length in [1, package_max_length], and
    // body_offset >= length_field_offset + length_field_bytes.
    unpack_setting_t s;
    memset(&s, 0, sizeof(s));
    s.mode = (unpack_mode_e)(1 + data[0] % 3);
    s.package_max_length = 1 + ((unsigned)data[1] << 8 | data[2]);
    if (s.mode == UNPACK_BY_FIXED_LENGTH) {
        s.fixed_length = 1 + ((unsigned)data[3] << 8 | data[4]) % s.package_max_length;
    } else if (s.mode == UNPACK_BY_DELIMITER) {
        s.delimiter_bytes = 1 + data[3] % PACKAGE_MAX_DELIMITER_BYTES;
        memcpy(s.delimiter, data + 4, PACKAGE_MAX_DELIMITER_BYTES);
    } else {
        static const unpack_coding_e codings[] = {ENCODE_BY_VARINT, ENCODE_BY_LITTLE_ENDIAN,
                                                  ENCODE_BY_BIG_ENDIAN, ENCODE_BY_ASN1};
        s.length_field_offset = data[3] % 16;
        s.length_field_bytes = 1 + data[4] % 4;
        s.body_offset = s.length_field_offset + s.length_field_bytes + data[5] % 8;
        s.length_adjustment = (int8_t)data[6];
        s.length_field_coding = codings[data[7] % 4];
    }
    data += 12; size -= 12;

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 0;
    int sndbuf = (int)kMaxStream * 2;
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fds[1], data + off, size - off);
        if (n <= 0) break;
        off += n;
    }
    close(fds[1]);

    hloop_t* loop = hloop_new(0);
    hio_t* io = hio_get(loop, fds[0]);
    hio_set_unpack(io, &s);
    hio_setcb_read(io, on_read);
    hio_setcb_close(io, on_close);
    hio_read(io);
    hloop_run(loop);
    hloop_free(&loop);
    return 0;
}
