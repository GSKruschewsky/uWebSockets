#ifndef UWS_CLI_APP_H
#define UWS_CLI_APP_H

#include <string>
#include <charconv>
#include <string_view>
#include <sstream>
#include <cerrno>

/* An app is a convenience wrapper of some of the most used fuctionalities and allows a
 * builder-pattern kind of init. Apps operate on the implicit thread local Loop */

#include "HttpContext.h"
#include "HttpResponse.h"
#include "WebSocketContext.h"
#include "WebSocket.h"
#include "PerMessageDeflate.h"

namespace uWS {

/* connectError codes. A positive code is the platform's socket error (errno / WSAGetLastError:
 * ECONNREFUSED, ENETUNREACH, ETIMEDOUT ...). A code at or below CONNECT_ERROR_RESOLVE_BASE is a failed
 * name lookup carrying the getaddrinfo error: connectErrorResolveCode(code) gives the EAI_* value
 * (EAI_NONAME, EAI_AGAIN ...). An attempt that could not be started reports the platform error of the
 * socket/bind/connect call or of the resolver thread (ENOMEM, EAGAIN); 0 is never produced by the
 * library itself. */
static constexpr int CONNECT_ERROR_RESOLVE_BASE = LIBUS_CONNECT_ERROR_RESOLVE_BASE;
static inline bool isConnectErrorResolve(int code) { return LIBUS_CONNECT_ERROR_IS_RESOLVE(code); }
static inline int connectErrorResolveCode(int code) { return LIBUS_CONNECT_ERROR_RESOLVE_CODE(code); }

    /* This one matches us_socket_context_options_t but has default values */
    struct ClientSocketContextOptions {
        const char *key_file_name = nullptr;
        const char *cert_file_name = nullptr;
        const char *passphrase = nullptr;
        const char *dh_params_file_name = nullptr;
        const char *ca_file_name = nullptr;
        const char *ssl_ciphers = nullptr;
        int ssl_prefer_low_memory_usage = 0;

        /* Conversion operator used internally */
        operator struct us_socket_context_options_t() const {
            struct us_socket_context_options_t socket_context_options;
            memcpy(&socket_context_options, this, sizeof(ClientSocketContextOptions));
            return socket_context_options;
        }
    };

    static_assert(sizeof(struct us_socket_context_options_t) == sizeof(ClientSocketContextOptions), "Mismatching uSockets/uWebSockets ABI");
    
template <bool SSL>
struct TemplatedClientApp {
private:
    /* The app always owns at least one http context, but creates websocket contexts on demand */
    HttpContext<SSL> *httpContext;

    /* Attempts are numbered per app from 1; connect() returns the number and every callback
     * about that attempt carries it, since attempts may overlap (a re-dial while an earlier
     * one is still resolving, connecting or awaiting its handshake response). What an attempt
     * sends - Host header, path, SNI - is stored per socket in the HTTP context data until the
     * socket opens, never on the app. */
    unsigned int lastAttempt = 0;
    char *source_host;
    /* Seconds a connect attempt (name lookup + TCP connect) may take before it fails with
     * connectError(ETIMEDOUT); 0 leaves it to the kernel's own connect timeout */
    unsigned short connectTimeout = 10;

    /* The request line and the Host header are written verbatim, so a CR, LF or other control
     * character in the URL or the hostname would let a caller forge headers */
    static bool hasControlChars(std::string_view s) {
        for (unsigned char c : s) {
            if (c < 0x20 || c == 0x7f) {
                return true;
            }
        }
        return false;
    }

    /* An IPv4 (digits and dots) or IPv6 (contains ':') literal: never sent as SNI */
    static bool isAddressLiteral(std::string_view s) {
        if (s.find(':') != std::string_view::npos) {
            return true;
        }
        if (s.empty()) {
            return false;
        }
        for (unsigned char c : s) {
            if (!(c == '.' || (c >= '0' && c <= '9'))) {
                return false;
            }
        }
        return true;
    }
    std::unordered_map<std::string, std::string> customHeaders;

public:

    TemplatedClientApp(ClientSocketContextOptions options = {}) {
        httpContext = HttpContext<SSL>::create(Loop::get(), options);

        if (httpContext) {
            /* A connect that fails before opening (refused, unreachable) reaches
             * neither on_open nor on_close — uSockets delivers it here. Without a
             * registered handler uSockets has nowhere to report the failure. Note
             * that the socket is a dead semi-socket: its ext is uninitialized, so
             * only the context may be touched. */
            us_socket_context_on_connect_error(SSL, (struct us_socket_context_t *) httpContext, [](struct us_socket_t *s, int code) {
                HttpContextData<SSL> *httpContextData = HttpContext<SSL>::getSocketContextDataS(s);
                unsigned int attempt = httpContextData->dropClientAttempt(s);
                if (httpContextData->clientConnectErrorHandler) {
                    httpContextData->clientConnectErrorHandler(code, attempt);
                } else if (httpContextData->clientHandshakeAbortedHandler) {
                    /* No connectError registered: report through rejectedHandshake so the
                     * failure is never silent */
                    httpContextData->clientHandshakeAbortedHandler(std::string_view("", 0), attempt);
                }
                return s;
            });
        }
    }

    bool constructorFailed() {
        return !httpContext;
    }

    template <typename UserData>
    struct WebSocketBehavior {
        /* Disabled compression by default - probably a bad default */
        CompressOptions compression = DISABLED;
        /* Maximum message size we can receive */
        unsigned int maxPayloadLength = 16 * 1024;
        /* 2 minutes timeout is good */
        unsigned short idleTimeout = 120;
        /* 64kb backpressure is probably good */
        unsigned int maxBackpressure = 64 * 1024;
        bool closeOnBackpressureLimit = false;
        /* This one depends on kernel timeouts and is a bad default */
        bool resetIdleTimeoutOnSend = false;
        /* A good default, esp. for newcomers */
        bool sendPingsAutomatically = true;
        /* Custom aditional options (Client-specific) */
        bool skipUTF8Validation = false;
        bool onlyLastPacketFrame = false;
        /* Kernel receive timestamps (Linux SO_TIMESTAMPING) on this client's sockets: while a
         * message handler runs, us_loop_last_rx_timestamp() on the loop returns the stamp of the
         * read that carried it. Off by default, which leaves the receive path untouched. */
        bool rxTimestamps = false;
        std::unordered_map<std::string, std::string> customHeaders = {};
        char *localAddress = nullptr;
        /* Maximum socket lifetime in minutes before forced closure (defaults to disabled) */
        unsigned short maxLifetime = 0;
        /* Seconds from connect() until the TCP connection must be established (the name lookup
         * included); when it is not, the attempt fails with connectError(ETIMEDOUT). The HTTP
         * idle timeout then covers the handshake response. 0 disables it, leaving a resolving
         * or connecting socket to the resolver's and the kernel's own limits. The uSockets
         * timer has a 4-second granularity. */
        unsigned short connectTimeout = 10;
        MoveOnlyFunction<void(HttpResponse<SSL> *, HttpRequest *, struct us_socket_context_t *)> upgrade = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *)> open = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view, OpCode)> message = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view, OpCode)> dropped = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *)> drain = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view)> ping = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view)> pong = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view, int, int)> subscription = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, int, std::string_view)> close = nullptr;
        /* Called when the server answered the handshake with anything but 101, or when the
         * attempt died without a parsed response (empty status; body = raw bytes, if any).
         * The last argument is the attempt number connect() returned. */
        MoveOnlyFunction<void(std::string_view, std::string_view, std::string_view, HttpRequest *, unsigned int)> rejectedHandshake = nullptr;
        /* Called when the connection itself fails (name lookup, refused, unreachable, connect
         * timeout) before any of open/close/rejectedHandshake could apply. A positive code is
         * the platform's socket error (errno / WSAGetLastError, e.g. ECONNREFUSED, ETIMEDOUT);
         * a code at or below CONNECT_ERROR_RESOLVE_BASE (isConnectErrorResolve) is a failed
         * lookup whose EAI_* value is connectErrorResolveCode(code); an attempt that could not
         * be started carries the error of the call that stopped it (EADDRNOTAVAIL, ENOMEM ...).
         * The second argument is the attempt number connect() returned. Without this handler
         * the same failures are reported through rejectedHandshake with an empty status. */
        MoveOnlyFunction<void(int, unsigned int)> connectError = nullptr;
    };

    /* Returns the SSL_CTX of this app, or nullptr. */
    void *getNativeHandle() {
        return us_socket_context_get_native_handle(SSL, (struct us_socket_context_t *) httpContext);
    }

    template <typename UserData>
    TemplatedClientApp &&ws(WebSocketBehavior<UserData> &&behavior) {
        /* Don't compile if alignment rules cannot be satisfied */
        static_assert(alignof(UserData) <= LIBUS_EXT_ALIGNMENT,
        "µWebSockets cannot satisfy UserData alignment requirements. You need to recompile µSockets with LIBUS_EXT_ALIGNMENT adjusted accordingly.");

        if (!httpContext) {
            return std::move(static_cast<TemplatedClientApp &&>(*this));
        }

        /* Terminate on misleading idleTimeout values */
        if (behavior.idleTimeout && behavior.idleTimeout < 8) {
            std::cerr << "Error: idleTimeout must be either 0 or greater than 8!" << std::endl;
            std::terminate();
        }

        /* Maximum idleTimeout is 16 minutes */
        if (behavior.idleTimeout > 240 * 4) {
            std::cerr << "Error: idleTimeout must not be greater than 960 seconds!" << std::endl;
            std::terminate();
        }

        /* Maximum maxLifetime is 4 hours */
        if (behavior.maxLifetime > 240) {
            std::cerr << "Error: maxLifetime must not be greater than 240 minutes!" << std::endl;
            std::terminate();
        }

        auto *webSocketContext = WebSocketContext<SSL, false, UserData>::create(Loop::get(), (us_socket_context_t *) httpContext, nullptr);

        /* Quick fix to disable any compression if set */
#ifdef UWS_NO_ZLIB
        behavior.compression = DISABLED;
#endif

        /* If we are the first one to use compression, initialize it */
        if (behavior.compression) {
            LoopData *loopData = (LoopData *) us_loop_ext(us_socket_context_loop(SSL, webSocketContext->getSocketContext()));

            /* Initialize loop's deflate inflate streams */
            if (!loopData->zlibContext) {
                loopData->zlibContext = new ZlibContext;
                loopData->inflationStream = new InflationStream(CompressOptions::DEDICATED_DECOMPRESSOR);
                loopData->deflationStream = new DeflationStream(CompressOptions::DEDICATED_COMPRESSOR);
            }
        }

        /* Copy all handlers */
        webSocketContext->getExt()->openHandler = std::move(behavior.open);
        webSocketContext->getExt()->messageHandler = std::move(behavior.message);
        webSocketContext->getExt()->droppedHandler = std::move(behavior.dropped);
        webSocketContext->getExt()->drainHandler = std::move(behavior.drain);
        webSocketContext->getExt()->subscriptionHandler = std::move(behavior.subscription);
        webSocketContext->getExt()->closeHandler = std::move(behavior.close);
        webSocketContext->getExt()->pingHandler = std::move(behavior.ping);
        webSocketContext->getExt()->pongHandler = std::move(behavior.pong);
        webSocketContext->getExt()->rejectedHandshakeHandler = std::move(behavior.rejectedHandshake);

        /* Connect errors happen while the socket still belongs to the HTTP context,
         * so this handler lives there rather than on the WebSocket context. Must be
         * taken out of behavior before the onHttp lambdas below move the rest of it. */
        httpContext->getSocketContextData()->clientConnectErrorHandler = std::move(behavior.connectError);

        /* Catch-all for attempts that die without a parsed rejection (refused with no
         * connectError registered, reset, timed out, or an unparseable response): route
         * them to rejectedHandshake so every failed connect reaches the app. Empty
         * status/text mean "no HTTP response"; body carries any raw bytes received. */
        httpContext->getSocketContextData()->clientHandshakeAbortedHandler = [webSocketContext](std::string_view rawResponse, unsigned int attempt) {
            WebSocketContextData<SSL, false, UserData> *webSocketContextData = (WebSocketContextData<SSL, false, UserData> *) us_socket_context_ext(SSL, (us_socket_context_t *) webSocketContext);
            if (webSocketContextData->rejectedHandshakeHandler) {
                /* There is no request to expose; hand out an inert empty one */
                HttpRequest emptyRequest;
                webSocketContextData->rejectedHandshakeHandler(std::string_view("", 0), std::string_view("", 0), rawResponse, &emptyRequest, attempt);
            }
        };

        /* Copy settings */
        webSocketContext->getExt()->maxPayloadLength = behavior.maxPayloadLength;
        webSocketContext->getExt()->maxBackpressure = behavior.maxBackpressure;
        webSocketContext->getExt()->closeOnBackpressureLimit = behavior.closeOnBackpressureLimit;
        webSocketContext->getExt()->resetIdleTimeoutOnSend = behavior.resetIdleTimeoutOnSend;
        webSocketContext->getExt()->sendPingsAutomatically = behavior.sendPingsAutomatically;
        webSocketContext->getExt()->maxLifetime = behavior.maxLifetime;
        webSocketContext->getExt()->compression = behavior.compression;
        
        /* Custom aditional options (Client-specific) */
        webSocketContext->getExt()->skipUTF8Validation = behavior.skipUTF8Validation;
        webSocketContext->getExt()->onlyLastPacketFrame = behavior.onlyLastPacketFrame;
        webSocketContext->getExt()->rxTimestamps = behavior.rxTimestamps;
        /* Receive timestamps are requested at connect time, which happens on the HTTP context;
         * the flag then rides on the socket into this WebSocket context after the upgrade */
        if (behavior.rxTimestamps) {
            us_socket_context_set_rx_timestamps(SSL, (struct us_socket_context_t *) httpContext, 1);
        }
        this->customHeaders = std::move(behavior.customHeaders);
        this->source_host = behavior.localAddress;
        this->connectTimeout = behavior.connectTimeout;

        /* Calculate idleTimeoutCompnents */
        webSocketContext->getExt()->calculateIdleTimeoutCompnents(behavior.idleTimeout);

        /* 
         * Filter is called only when the connection opens (event = 1) or 
         * closes (event = -1) of the socket. So we set a filter to send 
         * the initial websocket handshake once the server connection is open. 
         * Every ws() call registers one such filter and all of them fire per
         * socket open: the per-socket flag lets exactly one send the handshake.
         */
        httpContext->filter([ this ](HttpResponse<SSL> *res, int event) {
            if (event == 1) {
                /* Connection established */
                HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, (us_socket_t *) res);
                if (!httpResponseData->clientHandshakeSent) {
                    httpResponseData->clientHandshakeSent = true;

                    /* This socket's attempt, parked by connect() until now */
                    HttpContextData<SSL> *httpContextData = this->httpContext->getSocketContextData();
                    auto it = httpContextData->clientAttempts.find((us_socket_t *) res);
                    if (it == httpContextData->clientAttempts.end()) {
                        /* Not one of ours (cannot happen for a socket connect() returned): no
                         * handshake, the HTTP idle timeout ends it and the close path reports it */
                        return;
                    }
                    typename HttpContextData<SSL>::ClientAttempt attempt = std::move(it->second);
                    httpContextData->clientAttempts.erase(it);
                    httpResponseData->clientAttempt = attempt.id;

                    /* This socket's own SNI, before the TLS handshake starts with the first
                     * write (no-op without SSL); an address literal sends no name */
                    us_socket_set_host_name(SSL, (us_socket_t *) res, attempt.sniHost.empty() ? nullptr : attempt.sniHost.c_str());

                    /* Writes a new key for this socket */
                    WebSocketHandshake::generateKey(httpResponseData->clientWebSocketKey);

                    res->writeInitHandshake(
                        attempt.hostHeader,
                        attempt.path,
                        httpResponseData->clientWebSocketKey,
                        this->customHeaders
                    );
                }
            }
        });
        
        /* Creates a "fake" route to handle the server initial handshake successful response. */
        httpContext->onHttp("HTTP/1.1", "101", [webSocketContext, behavior = std::move(behavior)](HttpResponse<SSL> *res, HttpRequest *req) mutable {
            
            /* If we have this header set, it's a websocket handshake response */
            std::string_view secWebSocketAccept = req->getHeader("sec-websocket-accept");
            if (secWebSocketAccept.length() != 28) {
                /* Tell the router that we did not handle this request */
                req->setYield(true);
                return;
            }
            
            /* The accept value must answer the key this very socket sent */
            HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, (us_socket_t *) res);
            char expectedSecWebSocketAccept[29] = {};
            WebSocketHandshake::generate(httpResponseData->clientWebSocketKey, expectedSecWebSocketAccept);
            if (memcmp(secWebSocketAccept.data(), expectedSecWebSocketAccept, 28) != 0) {
                /* Tell the router that we did not handle this request */
                req->setYield(true);
                return;
            }

            /* Emit upgrade handler */
            if (behavior.upgrade) {
                behavior.upgrade(res, req, (struct us_socket_context_t *) webSocketContext);
            } else {
                /* Default handler upgrades to WebSocket */
                res->template upgradeClient<UserData>(
                    {}, 
                    {}, 
                    req->getHeader("sec-websocket-protocol"), 
                    req->getHeader("sec-websocket-extensions"), 
                    (struct us_socket_context_t *) webSocketContext
                );
            }

            /* We are going to get uncorked by the Http get return */

            /* We do not need to check for any close or shutdown here as we immediately return from get handler */

        }, true);
        
        /* Creates a "fake" route to handle the server initial handshake NOT successful response. */
        httpContext->onHttp("HTTP/1.1", "/*", [this, webSocketContext, behavior = std::move(behavior)](HttpResponse<SSL> *res, HttpRequest *req) mutable {
            /* This is the one terminal callback for this attempt; the close fallback
             * below (triggered by us_socket_close) must stay quiet */
            HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, (us_socket_t *) res);
            httpResponseData->clientCallbackDelivered = true;

            WebSocketContextData<SSL, false, UserData> *webSocketContextData = (WebSocketContextData<SSL, false, UserData> *) us_socket_context_ext(SSL, (us_socket_context_t *) webSocketContext);
            if (webSocketContextData->rejectedHandshakeHandler) {
                /* Deliver while the socket is still alive: status, headers and body are
                 * views into this socket's parser buffers and die with it on close */
                std::string_view status = req->getFullUrl();
                std::string_view statusText = req->getHeader(status);
                HttpContextData<SSL> *httpContextData = this->httpContext->getSocketContextData();
                std::string_view body {
                    httpContextData->reqRemaningData,
                    httpContextData->reqRemaningDataLen
                };
                webSocketContextData->rejectedHandshakeHandler(
                    status,
                    statusText,
                    body,
                    req,
                    httpResponseData->clientAttempt
                );
            }

            /* Close this socket */
            us_socket_shutdown(SSL, (us_socket_t *) res);
            /* Close any socket on HTTP errors */
            us_socket_close(SSL, (us_socket_t *) res, 0, nullptr);

        }, false);
        
        return std::move(static_cast<TemplatedClientApp &&>(*this));
    }

    /* A numeric host connects synchronously; a name is resolved by uSockets on a resolver thread
     * (the loop is never blocked) and the connect is finished when the lookup completes, so a
     * failed lookup arrives through connectError with a code in the CONNECT_ERROR_RESOLVE_BASE
     * range. 'hostname', when given, replaces the URL's host in the Host header and the SNI, for
     * callers that dial an address they resolved themselves: "name" takes the URL's port in the
     * Host header when it is not the scheme's default, "name:port" is sent as given. Throws
     * std::runtime_error on a scheme/SSL mismatch, an invalid port, or a control character in
     * the URL or the hostname. Returns the attempt number (from 1, per app) that the attempt's
     * open (WebSocket::getClientAttempt), rejectedHandshake or connectError will carry; attempts
     * may overlap and each sends its own Host header, path and SNI. */
    unsigned int connect(std::string url, std::string hostname = "") {
        int port;
        std::string host, path, hostHeader, sniHost;

        if (hasControlChars(url) || hasControlChars(hostname)) {
            throw std::runtime_error("WebSocket client URL and hostname must not contain control characters.");
        }

        /* Parses the URL setting "host", "path" and "port" */

        // Check protocol and validate against SSL setting
        if (url.rfind("wss://", 0) == 0) {
            if (!SSL) {
                 throw std::runtime_error("WebSocket client SSL is disabled but URL uses \"wss://\".");
            }
            url = url.substr(6);
        } else if (url.rfind("ws://", 0) == 0) {
            if (SSL) {
                throw std::runtime_error("WebSocket client SSL is enabled but URL uses \"ws://\".");
            }
            url = url.substr(5);
        }
        
        // Set default port based on protocol
        port = SSL ? 443 : 80;
        
        // Find the first occurrence of '/' or '?' to separate host:port from path
        size_t pathStart = url.find_first_of("/?");
        std::string hostPort = url.substr(0, pathStart);
        
        // Extract path (everything after host:port, including query string)
        if (pathStart != std::string::npos) {
            path = "/" + url.substr(pathStart + 1);
            // Handle the case where path starts with '?'
            if (url[pathStart] == '?') {
                path = "/?" + url.substr(pathStart + 1);
            } else {
                path = url.substr(pathStart);
            }
        } else {
            path = "/";
        }
        
        // Parse host and port
        size_t colon = hostPort.find(':');
        if (colon != std::string::npos) {
            host = hostPort.substr(0, colon);
            try {
                port = std::stoi(hostPort.substr(colon + 1));
            } catch (const std::exception &) {
                port = 0;
            }
            if (port <= 0 || port > 65535) {
                throw std::runtime_error("WebSocket client URL has an invalid port.");
            }
        } else {
            host = hostPort;
        }

        /* Host header and SNI. A hostname given as "name:port" is sent as the Host header
         * verbatim (its port may differ from the dialed one, e.g. behind a forwarder); a bare
         * name, like the URL's host, takes the dialed port when that is not the default. */
        size_t hostnameColon = hostname.find(':');
        if (!hostname.empty() && hostnameColon != std::string::npos && hostnameColon == hostname.rfind(':')) {
            sniHost = hostname.substr(0, hostnameColon);
            hostHeader = hostname;
        } else {
            sniHost = hostname.empty() ? host : hostname;
            hostHeader = sniHost;
            if (port != (SSL ? 443 : 80)) {
                hostHeader += ":" + std::to_string(port);
            }
        }

        /* The SNI is set per socket when it opens; an address literal sends none */
        if (isAddressLiteral(sniHost)) {
            sniHost.clear();
        }

        /* Everything checked: this is an attempt (a call that threw above started none) */
        unsigned int attempt = ++lastAttempt;

        /* Connect the socket. uSockets returns null only when the attempt could not be started
         * (a numeric host whose socket/bind/connect failed at once, or no resolver thread) and
         * keeps the error that stopped it on the context. */
        us_socket_t *connectSocket = httpContext->connect(host.c_str(), port, 0, this->source_host);

        if (!connectSocket) {
            int connectError = us_socket_context_last_connect_error(SSL, (struct us_socket_context_t *) httpContext);
            /* No socket exists to report the error through. Deliver the callback from a
             * one-shot timer rather than synchronously or via Loop::defer: the caller
             * observes every connect failure asynchronously and cannot recurse through
             * a retrying handler, while the timer (unlike a deferred lambda) is a poll
             * that keeps the loop alive until delivery. The context pointer and the error
             * are carried in the timer ext since the app itself may be moved by the
             * builder chain. */
            struct ConnectErrorTimerData { HttpContext<SSL> *httpContext; int code; unsigned int attempt; };
            struct us_timer_t *connectErrorTimer = us_create_timer((struct us_loop_t *) Loop::get(), 0, sizeof(ConnectErrorTimerData));
            *(ConnectErrorTimerData *) us_timer_ext(connectErrorTimer) = { httpContext, connectError, attempt };
            us_timer_set(connectErrorTimer, [](struct us_timer_t *t) {
                ConnectErrorTimerData data = *(ConnectErrorTimerData *) us_timer_ext(t);
                HttpContext<SSL> *localHttpContext = data.httpContext;
                us_timer_close(t);

                HttpContextData<SSL> *httpContextData = localHttpContext->getSocketContextData();
                if (httpContextData->clientConnectErrorHandler) {
                    httpContextData->clientConnectErrorHandler(data.code, data.attempt);
                } else if (httpContextData->clientHandshakeAbortedHandler) {
                    /* No connectError registered: report through rejectedHandshake */
                    httpContextData->clientHandshakeAbortedHandler(std::string_view("", 0), data.attempt);
                }
            }, 1, 0);

            return attempt;
        }

        /* Park what this socket must send once it opens */
        httpContext->getSocketContextData()->clientAttempts[connectSocket] = { attempt, std::move(hostHeader), std::move(path), std::move(sniHost) };

        /* The attempt is live: bound the lookup and the TCP connect together. on_open re-arms
         * the socket with the HTTP idle timeout; a socket that never opens is reported and
         * discarded by the HTTP context's timeout handler. */
        if (connectTimeout) {
            us_socket_timeout(SSL, connectSocket, connectTimeout);
        }

        return attempt;
    }

    TemplatedClientApp &&run() {
        uWS::run();
        return std::move(static_cast<TemplatedClientApp &&>(*this));
    }
};

};

namespace uWS {
    typedef uWS::TemplatedClientApp<false> CliApp;
    typedef uWS::TemplatedClientApp<true> CliSSLApp;
}

#endif // UWS_CLI_APP_H
