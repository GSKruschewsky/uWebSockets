/*
 * Authored by Alex Hultman, 2018-2020.
 * Intellectual property of third-party.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UWS_WEBSOCKETPROTOCOL_H
#define UWS_WEBSOCKETPROTOCOL_H

#include <libusockets.h>

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string_view>

#ifdef UWS_USE_SIMDUTF
  #include <simdutf.h>
#endif

namespace uWS {

/* We should not overcomplicate these */
constexpr std::string_view ERR_TOO_BIG_MESSAGE("Received too big message");
constexpr std::string_view ERR_WEBSOCKET_TIMEOUT("WebSocket timed out from inactivity");
constexpr std::string_view ERR_INVALID_TEXT("Received invalid UTF-8");
constexpr std::string_view ERR_TOO_BIG_MESSAGE_INFLATION("Received too big message, or other inflation error");
constexpr std::string_view ERR_INVALID_CLOSE_PAYLOAD("Received invalid close payload");
constexpr std::string_view ERR_PROTOCOL("Received invalid WebSocket frame");
constexpr std::string_view ERR_TCP_FIN("Received TCP FIN before WebSocket close frame");

enum OpCode : unsigned char {
    CONTINUATION = 0,
    TEXT = 1,
    BINARY = 2,
    CLOSE = 8,
    PING = 9,
    PONG = 10
};

enum {
    CLIENT,
    SERVER
};

/* I belive this sould not be templated, always used with "isServer" set to true. */
// 24 bytes perfectly
template <bool isServer>
struct WebSocketState {
public:
    static const unsigned int SHORT_MESSAGE_HEADER = isServer ? 6 : 2;
    static const unsigned int MEDIUM_MESSAGE_HEADER = isServer ? 8 : 4;
    static const unsigned int LONG_MESSAGE_HEADER = isServer ? 14 : 10;

    // 16 bytes
    struct State {
        unsigned int wantsHead : 1;
        unsigned int spillLength : 4;
        signed int opStack : 2; // -1, 0, 1
        unsigned int lastFin : 1;

        // 15 bytes
        unsigned char spill[LONG_MESSAGE_HEADER - 1];
        OpCode opCode[2];

        State() {
            wantsHead = true;
            spillLength = 0;
            opStack = -1;
            lastFin = true;
        }

    } state;

    // 8 bytes
    unsigned int remainingBytes = 0;
    char mask[isServer ? 4 : 1];
};

namespace protocol {

template <typename T>
T bit_cast(char *c) {
    T val;
    memcpy(&val, c, sizeof(T));
    return val;
}

/* Byte swap for little-endian systems */
template <typename T>
T cond_byte_swap(T value) {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");
    uint32_t endian_test = 1;
    if (*reinterpret_cast<char*>(&endian_test)) {
        uint8_t src[sizeof(T)];
        uint8_t dst[sizeof(T)];

        std::memcpy(src, &value, sizeof(T));
        for (size_t i = 0; i < sizeof(T); ++i) {
            dst[i] = src[sizeof(T) - 1 - i];
        }

        T result;
        std::memcpy(&result, dst, sizeof(T));
        return result;
    }
    return value;
}

#ifdef UWS_USE_SIMDUTF

static bool isValidUtf8(unsigned char *s, size_t length)
{
    return simdutf::validate_utf8((const char *)s, length);
}

#else
// Based on utf8_check.c by Markus Kuhn, 2005
// https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
// Optimized for predominantly 7-bit content by Alex Hultman, 2016
// Licensed as Zlib, like the rest of this project
// This runs about 40% faster than simdutf with g++ -mavx
static bool isValidUtf8(unsigned char *s, size_t length)
{
    for (unsigned char *e = s + length; s != e; ) {
        if (s + 16 <= e) {
            uint64_t tmp[2];
            memcpy(tmp, s, 16);
            if (((tmp[0] & 0x8080808080808080) | (tmp[1] & 0x8080808080808080)) == 0) {
                s += 16;
                continue;
            }
        }

        while (!(*s & 0x80)) {
            if (++s == e) {
                return true;
            }
        }

        if ((s[0] & 0x60) == 0x40) {
            if (s + 1 >= e || (s[1] & 0xc0) != 0x80 || (s[0] & 0xfe) == 0xc0) {
                return false;
            }
            s += 2;
        } else if ((s[0] & 0xf0) == 0xe0) {
            if (s + 2 >= e || (s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 ||
                    (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80) || (s[0] == 0xed && (s[1] & 0xe0) == 0xa0)) {
                return false;
            }
            s += 3;
        } else if ((s[0] & 0xf8) == 0xf0) {
            if (s + 3 >= e || (s[1] & 0xc0) != 0x80 || (s[2] & 0xc0) != 0x80 || (s[3] & 0xc0) != 0x80 ||
                    (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) || (s[0] == 0xf4 && s[1] > 0x8f) || s[0] > 0xf4) {
                return false;
            }
            s += 4;
        } else {
            return false;
        }
    }
    return true;
}

#endif

struct CloseFrame {
    uint16_t code;
    char *message;
    size_t length;
};

static inline CloseFrame parseClosePayload(char *src, size_t length, const bool& skipUTF8Validation = false) {
    /* If we get no code or message, default to reporting 1005 no status code present */
    CloseFrame cf = {1005, nullptr, 0};
    if (length >= 2) {
        memcpy(&cf.code, src, 2);
        cf = {cond_byte_swap<uint16_t>(cf.code), src + 2, length - 2};
        if (cf.code < 1000 || cf.code > 4999 || (cf.code > 1011 && cf.code < 4000) ||
            (cf.code >= 1004 && cf.code <= 1006) || ((!skipUTF8Validation) && !isValidUtf8((unsigned char *) cf.message, cf.length))) {
            /* Even though we got a WebSocket close frame, it in itself is abnormal */
            return {1006, (char *) ERR_INVALID_CLOSE_PAYLOAD.data(), ERR_INVALID_CLOSE_PAYLOAD.length()};
        }
    }
    return cf;
}

static inline size_t formatClosePayload(char *dst, uint16_t code, const char *message, size_t length) {
    /* We could have more strict checks here, but never append code 0 or 1005 or 1006 */
    if (code && code != 1005 && code != 1006) {
        code = cond_byte_swap<uint16_t>(code);
        memcpy(dst, &code, 2);
        /* It is invalid to pass nullptr to memcpy, even though length is 0 */
        if (message) {
            memcpy(dst + 2, message, length);
        }
        return length + 2;
    }
    return 0;
}

template <bool isServer>
static inline size_t messageFrameSize(size_t messageSize) {
    /* Clients must have +4 chars for the mask key */
    if (messageSize < 126) {
        return (isServer ? 2 : 6) + messageSize;
    } else if (messageSize <= UINT16_MAX) {
        return (isServer ? 4 : 8) + messageSize;
    }

    return (isServer ? 10 : 14) + messageSize;
}

enum {
    SND_CONTINUATION = 1,
    SND_NO_FIN = 2,
    SND_COMPRESSED = 64
};

template <bool isServer>
static inline size_t formatMessage(char *dst, const char *src, size_t length, OpCode opCode, size_t reportedLength, bool compressed, bool fin) {
    size_t messageLength;
    size_t headerLength;
    if (reportedLength < 126) {
        headerLength = 2;
        dst[1] = (char) reportedLength;
    } else if (reportedLength <= UINT16_MAX) {
        headerLength = 4;
        dst[1] = 126;
        uint16_t tmp = cond_byte_swap<uint16_t>((uint16_t) reportedLength);
        memcpy(&dst[2], &tmp, sizeof(uint16_t));
    } else {
        headerLength = 10;
        dst[1] = 127;
        uint64_t tmp = cond_byte_swap<uint64_t>((uint64_t) reportedLength);
        memcpy(&dst[2], &tmp, sizeof(uint64_t));
    }

    dst[0] = (char) ((fin ? 128 : 0) | ((compressed && opCode) ? SND_COMPRESSED : 0) | (char) opCode);

    //printf("%d\n", (int)dst[0]);

    char mask[4];
    if (!isServer) {
        dst[1] |= 0x80;
        uint32_t random = (uint32_t) rand();
        memcpy(mask, &random, 4);
        memcpy(dst + headerLength, &random, 4);
        headerLength += 4;
    }

    messageLength = headerLength + length;
    memcpy(dst + headerLength, src, length);

    if (!isServer) {

        // overwrites up to 3 bytes outside of the given buffer!
        //WebSocketProtocol<isServer>::unmaskInplace(dst + headerLength, dst + headerLength + length, mask);

        // this is not optimal
        char *start = dst + headerLength;
        char *stop = start + length;
        int i = 0;
        while (start != stop) {
            (*start++) ^= mask[i++ % 4];
        }
    }
    return messageLength;
}

}

// essentially this is only a parser
template <const bool isServer, typename Impl>
struct WebSocketProtocol {
public:
    static const unsigned int SHORT_MESSAGE_HEADER = isServer ? 6 : 2;
    static const unsigned int MEDIUM_MESSAGE_HEADER = isServer ? 8 : 4;
    static const unsigned int LONG_MESSAGE_HEADER = isServer ? 14 : 10;

protected:
    static inline bool isFin(char *frame) {return *((unsigned char *) frame) & 128;}
    static inline unsigned char getOpCode(char *frame) {return *((unsigned char *) frame) & 15;}
    static inline unsigned char payloadLength(char *frame) {return ((unsigned char *) frame)[1] & 127;}
    static inline bool rsv23(char *frame) {return *((unsigned char *) frame) & 48;}
    static inline bool rsv1(char *frame) {return *((unsigned char *) frame) & 64;}

    template <int N>
    static inline void UnrolledXor(char * __restrict data, char * __restrict mask) {
        if constexpr (N != 1) {
            UnrolledXor<N - 1>(data, mask);
        }
        data[N - 1] ^= mask[(N - 1) % 4];
    }

    template <int DESTINATION>
    static inline void unmaskImprecise8(char *src, uint64_t mask, unsigned int length) {
        for (unsigned int n = (length >> 3) + 1; n; n--) {
            uint64_t loaded;
            memcpy(&loaded, src, 8);
            loaded ^= mask;
            memcpy(src - DESTINATION, &loaded, 8);
            src += 8;
        }
    }

    /* DESTINATION = 6 makes this not SIMD, DESTINATION = 4 is with SIMD but we don't want that for short messages */
    template <int DESTINATION>
    static inline void unmaskImprecise4(char *src, uint32_t mask, unsigned int length) {
        for (unsigned int n = (length >> 2) + 1; n; n--) {
            uint32_t loaded;
            memcpy(&loaded, src, 4);
            loaded ^= mask;
            memcpy(src - DESTINATION, &loaded, 4);
            src += 4;
        }
    }

    template <int HEADER_SIZE>
    static inline void unmaskImpreciseCopyMask(char *src, unsigned int length) {
        if constexpr (HEADER_SIZE != 6) {
            char mask[8] = {src[-4], src[-3], src[-2], src[-1], src[-4], src[-3], src[-2], src[-1]};
            uint64_t maskInt;
            memcpy(&maskInt, mask, 8);
            unmaskImprecise8<HEADER_SIZE>(src, maskInt, length);
        } else {
            char mask[4] = {src[-4], src[-3], src[-2], src[-1]};
            uint32_t maskInt;
            memcpy(&maskInt, mask, 4);
            unmaskImprecise4<HEADER_SIZE>(src, maskInt, length);
        }
    }

    static inline void rotateMask(unsigned int offset, char *mask) {
        char originalMask[4] = {mask[0], mask[1], mask[2], mask[3]};
        mask[(0 + offset) % 4] = originalMask[0];
        mask[(1 + offset) % 4] = originalMask[1];
        mask[(2 + offset) % 4] = originalMask[2];
        mask[(3 + offset) % 4] = originalMask[3];
    }

    static inline void unmaskInplace(char *data, char *stop, char *mask) {
        while (data < stop) {
            *(data++) ^= mask[0];
            *(data++) ^= mask[1];
            *(data++) ^= mask[2];
            *(data++) ^= mask[3];
        }
    }

    template <unsigned int MESSAGE_HEADER, typename T>
    static inline bool consumeMessage(T payLength, char *&src, unsigned int &length, WebSocketState<true> *wState, void *user) {
        if (getOpCode(src)) {
            if (wState->state.opStack == 1 || (!wState->state.lastFin && getOpCode(src) < 2)) {
                Impl::forceClose(wState, user, ERR_PROTOCOL);
                return true;
            }
            wState->state.opCode[++wState->state.opStack] = (OpCode) getOpCode(src);
        } else if (wState->state.opStack == -1) {
            Impl::forceClose(wState, user, ERR_PROTOCOL);
            return true;
        }
        wState->state.lastFin = isFin(src);

        if (Impl::refusePayloadLength(payLength, wState, user)) {
            Impl::forceClose(wState, user, ERR_TOO_BIG_MESSAGE);
            return true;
        }

        if (payLength + MESSAGE_HEADER <= length) {
            bool fin = isFin(src);
            if (isServer) {
                /* This guy can never be assumed to be perfectly aligned since we can get multiple messages in one read */
                unmaskImpreciseCopyMask<MESSAGE_HEADER>(src + MESSAGE_HEADER, (unsigned int) payLength);
                if (Impl::handleFragment(src, payLength, 0, wState->state.opCode[wState->state.opStack], fin, wState, user)) {
                    return true;
                }
            } else {
                if (Impl::handleFragment(src + MESSAGE_HEADER, payLength, 0, wState->state.opCode[wState->state.opStack], isFin(src), wState, user, (payLength + MESSAGE_HEADER == length))) {
                    return true;
                }
            }

            if (fin) {
                wState->state.opStack--;
            }

            src += payLength + MESSAGE_HEADER;
            length -= (unsigned int) (payLength + MESSAGE_HEADER);
            wState->state.spillLength = 0;
            return false;
        } else {
            wState->state.spillLength = 0;
            wState->state.wantsHead = false;
            wState->remainingBytes = (unsigned int) (payLength - length + MESSAGE_HEADER);
            bool fin = isFin(src);
            if constexpr (isServer) {
                memcpy(wState->mask, src + MESSAGE_HEADER - 4, 4);
                uint64_t mask;
                memcpy(&mask, src + MESSAGE_HEADER - 4, 4);
                memcpy(((char *)&mask) + 4, src + MESSAGE_HEADER - 4, 4);
                unmaskImprecise8<0>(src + MESSAGE_HEADER, mask, length);
                rotateMask(4 - (length - MESSAGE_HEADER) % 4, wState->mask);
            }
            Impl::handleFragment(src + MESSAGE_HEADER, length - MESSAGE_HEADER, wState->remainingBytes, wState->state.opCode[wState->state.opStack], fin, wState, user);
            return true;
        }
    }

    /* This one is nicely vectorized on both ARM64 and X64 - especially with -mavx */
    static inline void unmaskAll(char * __restrict data, char * __restrict mask) {
        for (int i = 0; i < LIBUS_RECV_BUFFER_LENGTH; i += 16) {
            UnrolledXor<16>(data + i, mask);
        }
    }

    static inline bool consumeContinuation(char *&src, unsigned int &length, WebSocketState<true> *wState, void *user) {
        if (wState->remainingBytes <= length) {
            if (isServer) {
                unsigned int n = wState->remainingBytes >> 2;
                unmaskInplace(src, src + n * 4, wState->mask);
                for (unsigned int i = 0, s = wState->remainingBytes % 4; i < s; i++) {
                    src[n * 4 + i] ^= wState->mask[i];
                }
            }

            if (Impl::handleFragment(src, wState->remainingBytes, 0, wState->state.opCode[wState->state.opStack], wState->state.lastFin, wState, user)) {
                return false;
            }

            if (wState->state.lastFin) {
                wState->state.opStack--;
            }

            src += wState->remainingBytes;
            length -= wState->remainingBytes;
            wState->state.wantsHead = true;
            return true;
        } else {
            if (isServer) {
                /* No need to unmask if mask is 0 */
                uint32_t nullmask = 0;
                if (memcmp(wState->mask, &nullmask, sizeof(uint32_t))) {
                    if /*constexpr*/ (LIBUS_RECV_BUFFER_LENGTH == length) {
                        unmaskAll(src, wState->mask);
                    } else {
                        // Slow path
                        unmaskInplace(src, src + ((length >> 2) + 1) * 4, wState->mask);
                    }
                }
            }

            wState->remainingBytes -= length;
            if (Impl::handleFragment(src, length, wState->remainingBytes, wState->state.opCode[wState->state.opStack], wState->state.lastFin, wState, user)) {
                return false;
            }

            if (isServer && length % 4) {
                rotateMask(4 - (length % 4), wState->mask);
            }
            return false;
        }
    }

public:
    WebSocketProtocol() {

    }

    static inline void consume(char *src, unsigned int length, WebSocketState<true> *wState, void *user) {
        if (wState->state.spillLength) {
            src -= wState->state.spillLength;
            length += wState->state.spillLength;
            memcpy(src, wState->state.spill, wState->state.spillLength);
        }
        if (wState->state.wantsHead) {
            parseNext:
            while (length >= SHORT_MESSAGE_HEADER) {

                // invalid reserved bits / invalid opcodes / invalid control frames / set compressed frame
                if ((rsv1(src) && !Impl::setCompressed(wState, user)) || rsv23(src) || (getOpCode(src) > 2 && getOpCode(src) < 8) ||
                    getOpCode(src) > 10 || (getOpCode(src) > 2 && (!isFin(src) || payloadLength(src) > 125))) {
                    Impl::forceClose(wState, user, ERR_PROTOCOL);
                    return;
                }

                if (payloadLength(src) < 126) {
                    if (consumeMessage<SHORT_MESSAGE_HEADER, uint8_t>(payloadLength(src), src, length, wState, user)) {
                        return;
                    }
                } else if (payloadLength(src) == 126) {
                    if (length < MEDIUM_MESSAGE_HEADER) {
                        break;
                    } else if(consumeMessage<MEDIUM_MESSAGE_HEADER, uint16_t>(protocol::cond_byte_swap<uint16_t>(protocol::bit_cast<uint16_t>(src + 2)), src, length, wState, user)) {
                        return;
                    }
                } else if (length < LONG_MESSAGE_HEADER) {
                    break;
                } else if (consumeMessage<LONG_MESSAGE_HEADER, uint64_t>(protocol::cond_byte_swap<uint64_t>(protocol::bit_cast<uint64_t>(src + 2)), src, length, wState, user)) {
                    return;
                }
            }
            if (length) {
                memcpy(wState->state.spill, src, length);
                wState->state.spillLength = length & 0xf;
            }
        } else if (consumeContinuation(src, length, wState, user)) {
            goto parseNext;
        }
    }

    static const int CONSUME_POST_PADDING = 4;
    static const int CONSUME_PRE_PADDING = LONG_MESSAGE_HEADER - 1;
};

}

#endif // UWS_WEBSOCKETPROTOCOL_H
