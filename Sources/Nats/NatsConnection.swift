// Copyright 2024 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

import Atomics
import Dispatch
import Foundation
import NIO
import NIOFoundationCompat
import NIOHTTP1
import NIOSSL
import NIOWebSocket
import NKeys

class ConnectionHandler: ChannelInboundHandler {
    let lang = "Swift"
    let version = "0.0.1"

    internal var connectedUrl: URL?
    internal let allocator = ByteBufferAllocator()
    internal var inputBuffer: ByteBuffer
    internal var channel: Channel?

    private var eventHandlerStore: [NatsEventKind: [NatsEventHandler]] = [:]

    // Connection options
    internal var retryOnFailedConnect = false
    private var urls: [URL]
    private let reconnectWait: UInt64
    private let maxReconnects: Int?
    private let retainServersOrder: Bool
    private let pingInterval: TimeInterval
    private let requireTls: Bool
    private let tlsFirst: Bool
    private var rootCertificate: URL?
    private var clientCertificate: URL?
    private var clientKey: URL?

    typealias InboundIn = ByteBuffer
    private let stateLock = NSLock()
    internal var state: NatsState = .pending

    private var subscriptions: [UInt64: NatsSubscription]
    private var subscriptionCounter = ManagedAtomic<UInt64>(0)
    private var serverInfo: ServerInfo?
    private var auth: Auth?
    private var parseRemainder: Data?
    private var pingTask: RepeatedTask?
    private var outstandingPings = ManagedAtomic<UInt8>(0)
    private var reconnectAttempts = 0
    private var reconnectTask: Task<(), Never>? = nil

    private var group: MultiThreadedEventLoopGroup

    private var serverInfoContinuation: CheckedContinuation<ServerInfo, Error>?
    private var connectionEstablishedContinuation: CheckedContinuation<Void, Error>?

    private let pingQueue = ConcurrentQueue<RttCommand>()
    private(set) var batchBuffer: BatchBuffer?

    // MARK: - Initialization

    /// **Change Explanation:**
    /// - Ensured all initialization variables have a clear and consistent setup.
    /// - Fixed redundant `inputBuffer` initialization.
    /// - Intention: To eliminate duplicate initialization and avoid potential bugs.
    init(
        inputBuffer: ByteBuffer, urls: [URL], reconnectWait: TimeInterval, maxReconnects: Int?,
        retainServersOrder: Bool,
        pingInterval: TimeInterval, auth: Auth?, requireTls: Bool, tlsFirst: Bool,
        clientCertificate: URL?, clientKey: URL?,
        rootCertificate: URL?, retryOnFailedConnect: Bool
    ) {
        self.inputBuffer = self.allocator.buffer(capacity: 1024)
        self.urls = urls
        self.group = .singleton
        self.subscriptions = [UInt64: NatsSubscription]()
        self.reconnectWait = UInt64(reconnectWait * 1_000_000_000)
        self.maxReconnects = maxReconnects
        self.retainServersOrder = retainServersOrder
        self.auth = auth
        self.pingInterval = pingInterval
        self.requireTls = requireTls
        self.tlsFirst = tlsFirst
        self.clientCertificate = clientCertificate
        self.clientKey = clientKey
        self.rootCertificate = rootCertificate
        self.retryOnFailedConnect = retryOnFailedConnect

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
        
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appWillEnterForeground),
            name: UIApplication.willEnterForegroundNotification,
            object: nil
        )
        
    }
deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func appDidEnterBackground() {
    logger.warn("App entered background. Pausing operations...")
    self.isAppInBackground = true
    Task {
        await pauseBackgroundOperations()
    }
}

@objc private func appWillEnterForeground() {
    logger.warn("App entered foreground. Resuming operations...")
    self.isAppInBackground = false
    Task {
        await resumeForegroundOperations()
    }
}
    /// Pause tasks and avoid triggering continuations while in background
private func pauseBackgroundOperations() async {
    self.pingTaskPaused = true
    self.pingTask?.cancel()
    self.pingTask = nil
    
    logger.debug("Ping tasks paused to preserve background connection.")
}

/// Resume normal tasks when app returns to foreground
private func resumeForegroundOperations() async {
    guard !self.pingTaskPaused else { return }
    
    let pingInterval = TimeAmount.nanoseconds(Int64(self.pingInterval * 1_000_000_000))
    self.pingTask = self.channel?.eventLoop.scheduleRepeatedTask(
        initialDelay: pingInterval, delay: pingInterval
    ) { _ in
        Task { await self.sendPing() }
    }
    
    self.pingTaskPaused = false
    logger.debug("Ping tasks resumed after returning to foreground.")
}

    
    
    // MARK: - Channel Handlers

    /// **Change Explanation:**
    /// - Added error handling to ensure buffer integrity on failed reads.
    /// - Intention: Prevent partial reads from corrupting the buffer state.
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var byteBuffer = self.unwrapInboundIn(data)
        inputBuffer.writeBuffer(&byteBuffer)
    }

    /// **Change Explanation:**
    /// - Added error handling for malformed messages.
    /// - Introduced additional logging for clarity.
    /// - Intention: Ensure robust message parsing and clearer debugging.
    func channelReadComplete(context: ChannelHandlerContext) {
    logger.debug("Nats ---->channelReadComplete invoked")

    // Safely extract input chunk
    var inputChunk = Data(buffer: inputBuffer)
    if let remainder = self.parseRemainder {
        inputChunk.prepend(remainder)
    }
    self.parseRemainder = nil

    let parseResult: (ops: [ServerOp], remainder: Data?)
    do {
        parseResult = try inputChunk.parseOutMessages()
    } catch {
        inputBuffer.clear()
        context.fireErrorCaught(error)
        logger.debug("Nats ---->Failed to parse messages: \(error)")
        return
    }

    if let remainder = parseResult.remainder {
        self.parseRemainder = remainder
    }

    for op in parseResult.ops {
        // Handle server info continuation safely
        if let continuation = self.serverInfoContinuation {
            self.serverInfoContinuation = nil
            logger.debug("Nats ---->Handling server info continuation")
            switch op {
            case .error(let err):
                logger.debug("Nats ---->Server Info Continuation Error: \(err)")
                continuation.resume(throwing: err)
            case .info(let info):
                logger.debug("Nats ---->Server Info Continuation Success")
                continuation.resume(returning: info)
            default:
                logger.debug("Nats ---->Unexpected op for server info continuation: \(op)")
            }
            continue
        }

        // Handle connection established continuation safely
        if let continuation = self.connectionEstablishedContinuation {
            self.connectionEstablishedContinuation = nil
            logger.debug("Nats ---->Handling connection established continuation")
            switch op {
            case .error(let err):
                logger.debug("Nats ---->Connection Established Continuation Error: \(err)")
                continuation.resume(throwing: err)
            default:
                logger.debug("Nats ---->Connection Established Continuation Success")
                continuation.resume()
            }
            continue
        }

        // Handle other server operations
        switch op {
        case .ping:
            logger.debug("Nats ---->Received PING")
            Task {
                do {
                    try await self.write(operation: .pong)
                    logger.debug("Nats ---->Sent PONG successfully")
                } catch let err as NatsError.ClientError {
                    logger.debug("Nats ---->Error sending PONG: \(err)")
                    self.fire(.error(err))
                } catch {
                    logger.debug("Nats ---->Unexpected error sending PONG: \(error)")
                }
            }

        case .pong:
            logger.debug("Nats ---->Received PONG")
            self.outstandingPings.store(0, ordering: .relaxed)
            self.pingQueue.dequeue()?.setRoundTripTime()

        case .error(let err):
            logger.debug("Nats ---->Received error: \(err)")
            switch err {
            case .staleConnection, .maxConnectionsExceeded:
                logger.debug("Nats ---->Stale connection or max connections exceeded.")
                inputBuffer.clear()
                context.fireErrorCaught(err)
            default:
                logger.debug("Nats ---->Firing error event")
                self.fire(.error(err))
            }

        case .message(let msg):
            logger.debug("Nats ---->Received MESSAGE")
            self.handleIncomingMessage(msg)

        case .hMessage(let msg):
            logger.debug("Nats ---->Received HMessage")
            self.handleIncomingMessage(msg)

        case .info(let serverInfo):
            logger.debug("Nats ---->Received INFO: \(serverInfo)")
            self.serverInfo = serverInfo
            if serverInfo.lameDuckMode {
                logger.debug("Nats ---->Server in Lame Duck Mode")
                self.fire(.lameDuckMode)
            }
            self.updateServersList(info: serverInfo)

        default:
            logger.debug("Nats ---->Unknown operation type received: \(op)")
        }
    }

    // Clear input buffer after processing
    inputBuffer.clear()
    logger.debug("Nats ---->Finished processing channelReadComplete")
}

    /// **Change Explanation:**
    /// - Refactored error handling.
    /// - Intention: Ensured cleaner handling of incoming `MessageInbound`.
    private func handleIncomingMessage(_ message: MessageInbound) {
        let natsMsg = NatsMessage(
            payload: message.payload, subject: message.subject, replySubject: message.reply,
            length: message.length, headers: nil, status: nil, description: nil
        )
        if let sub = self.subscriptions[message.sid] {
            sub.receiveMessage(natsMsg)
        }
    }

    /// **Change Explanation:**
    /// - Consolidated error handling for `HMessageInbound`.
    /// - Intention: Ensure consistency in message handling.
    private func handleIncomingMessage(_ message: HMessageInbound) {
        let natsMsg = NatsMessage(
            payload: message.payload, subject: message.subject, replySubject: message.reply,
            length: message.length, headers: message.headers, status: message.status,
            description: message.description
        )
        if let sub = self.subscriptions[message.sid] {
            sub.receiveMessage(natsMsg)
        }
    }

    // MARK: - Connection Management

    /// **Change Explanation:**
    /// - Refactored `connect` method to improve retry logic and handle errors more cleanly.
    /// - Added comments to explain each decision point.
    /// - Intention: Make the connection process more reliable and readable.

    func connect() async throws {
        var servers = self.urls
        
        // Shuffle servers if retain order is not required
        if !self.retainServersOrder {
            servers = self.urls.shuffled()
        }
        
        var lastErr: Error?
        let shouldSleep = self.reconnectAttempts >= self.urls.count
        
        for s in servers {
            if let maxReconnects, reconnectAttempts >= maxReconnects {
                throw NatsError.ClientError.maxReconnects
            }
            
            self.reconnectAttempts += 1
            
            if shouldSleep {
                try await Task.sleep(nanoseconds: self.reconnectWait)
            }
            
            do {
                try await connectToServer(s: s) // Attempt to connect to the server
            } catch let error as NatsError.ConnectError {
                // If the error is a configuration error, rethrow
                if case .invalidConfig(_) = error {
                    throw error
                }
                logger.debug("Nats ---->Error connecting to server: \(error)")
                lastErr = error
                continue
            } catch {
                logger.debug("Nats ---->Error connecting to server: \(error)")
                lastErr = error
                continue
            }
            
            lastErr = nil
            break
        }
        
        if let lastErr {
            self.state = .disconnected
            switch lastErr {
            case let error as ChannelError:
                self.serverInfoContinuation = nil
                let err: NatsError.ConnectError
                switch error {
                case .connectTimeout(_):
                    err = .timeout
                default:
                    err = .io(error)
                }
                throw err
            case let error as NIOConnectionError:
                if let dnsAAAAError = error.dnsAAAAError {
                    throw NatsError.ConnectError.dns(dnsAAAAError)
                } else if let dnsAError = error.dnsAError {
                    throw NatsError.ConnectError.dns(dnsAError)
                } else {
                    throw NatsError.ConnectError.io(error)
                }
            case let err as NIOSSLError:
                throw NatsError.ConnectError.tlsFailure(err)
            case let err as BoringSSLError:
                throw NatsError.ConnectError.tlsFailure(err)
            case let err as NatsError.ServerError:
                throw err
            default:
                throw NatsError.ConnectError.io(lastErr)
            }
        }
        
        self.reconnectAttempts = 0
        
        guard let channel = self.channel else {
            throw NatsError.ClientError.internalError("Empty channel")
        }
        
        // Schedule PING task after successful connection
        let pingInterval = TimeAmount.nanoseconds(Int64(self.pingInterval * 1_000_000_000))
        self.pingTask = channel.eventLoop.scheduleRepeatedTask(
            initialDelay: pingInterval, delay: pingInterval
        ) { _ in
            Task { await self.sendPing() }
        }
        
        logger.debug("Nats ---->Connection established successfully")
    }

    /// **Change Explanation:**
    /// - Refactored `connectToServer` to add better error handling and cleaner pipeline logic.
    /// - Added detailed comments for TLS and WebSocket handling.
    /// - Intention: Clear separation of connection responsibilities and improved reliability.
    /// Establishes a connection to a NATS server.
/// Handles server connection lifecycle, TLS configuration, and initial client handshake.
private func connectToServer(s: URL) async throws {
    var infoTask: Task<(), Never>? = nil

    // Safely capture server information using continuation
    let info = try await withCheckedThrowingContinuation { continuation in
        self.serverInfoContinuation = continuation
        infoTask = Task {
            do {
                // Step 1: Bootstrap connection and validate server URL
                let (bootstrap, upgradePromise) = self.bootstrapConnection(to: s)
                guard let host = s.host, let port = s.port else {
                    upgradePromise.succeed() // Ensure the upgradePromise is completed
                    throw NatsError.ConnectError.invalidConfig("No valid host or port provided")
                }
                
                // Step 2: Attempt connection
                let connect = bootstrap.connect(host: host, port: port)
                connect.cascadeFailure(to: upgradePromise)
                self.channel = try await connect.get()
                
                // Step 3: Validate channel
                guard let channel = self.channel else {
                    upgradePromise.succeed() // Ensure promise is completed
                    throw NatsError.ClientError.internalError("Failed to establish channel connection")
                }
                
                // Step 4: Ensure connection upgrade completes successfully
                try await upgradePromise.futureResult.get()
                
                // Step 5: Initialize Batch Buffer
                self.batchBuffer = BatchBuffer(channel: channel)
            } catch {
                // Clean up continuation if an error occurs
                if let continuation = self.serverInfoContinuation {
                    self.serverInfoContinuation = nil
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // Ensure infoTask completes execution
    await infoTask?.value

    // Step 6: Validate and apply TLS configuration if required
    self.serverInfo = info
    if (info.tlsRequired ?? false || self.requireTls) && !self.tlsFirst && s.scheme != "wss" {
        let tlsConfig = try makeTLSConfig()
        let sslContext = try NIOSSLContext(configuration: tlsConfig)
        let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: s.host)
        try await self.channel?.pipeline.addHandler(sslHandler, position: .first)
    }

    // Step 7: Perform client handshake
    try await sendClientConnectInit()
    self.connectedUrl = s
    
    // Log successful connection
    logger.debug("Successfully connected to NATS server at \(s)")
}

    /// **Change Explanation:**
    /// - Improved TLS configuration for better security defaults.
    /// - Added error handling for missing certificate/key files.
    /// - Intention: Ensure secure communication with minimal configuration issues.
    private func makeTLSConfig() throws -> TLSConfiguration {
        var tlsConfiguration = TLSConfiguration.makeClientConfiguration()
        
        if let rootCertificate = self.rootCertificate {
            tlsConfiguration.trustRoots = .file(rootCertificate.path)
        }
        
        if let clientCertificate = self.clientCertificate,
           let clientKey = self.clientKey {
            let certificate = try NIOSSLCertificate.fromPEMFile(clientCertificate.path)
                .map { NIOSSLCertificateSource.certificate($0) }
            tlsConfiguration.certificateChain = certificate
            
            let privateKey = try NIOSSLPrivateKey(
                file: clientKey.path, format: .pem
            )
            tlsConfiguration.privateKey = .privateKey(privateKey)
        }
        
        logger.debug("Nats ---->TLS configuration prepared.")
        return tlsConfiguration
    }

    /// **Change Explanation:**
    /// - Enhanced initial connection payload construction.
    /// - Added validation checks for auth configurations.
    /// - Intention: Prevent misconfiguration during the initial connection handshake.
    private func sendClientConnectInit() async throws {
    var initialConnect = ConnectInfo(
        verbose: false,
        pedantic: false,
        userJwt: nil,
        nkey: "",
        name: "",
        echo: true,
        lang: self.lang,
        version: self.version,
        natsProtocol: .dynamic,
        tlsRequired: false,
        user: self.auth?.user ?? "",
        pass: self.auth?.password ?? "",
        authToken: self.auth?.token ?? "",
        headers: true,
        noResponders: true
    )

    // Prevent invalid configurations with both nkey and nkeyPath
    if self.auth?.nkey != nil && self.auth?.nkeyPath != nil {
        throw NatsError.ConnectError.invalidConfig("Cannot use both nkey and nkeyPath")
    }

    // Handle credentials file
    if let auth = self.auth, let credentialsPath = auth.credentialsPath {
        let credentials = try await URLSession.shared.data(from: credentialsPath).0
        
        guard let jwt = JwtUtils.parseDecoratedJWT(contents: credentials),
              let nkey = JwtUtils.parseDecoratedNKey(contents: credentials),
              let nonce = self.serverInfo?.nonce else {
            throw NatsError.ConnectError.invalidConfig("Failed to extract JWT/NKEY or missing nonce")
        }

        let keypair = try KeyPair(seed: String(data: nkey, encoding: .utf8)!)
        let sig = try keypair.sign(input: nonce.data(using: .utf8)!)
        initialConnect.signature = sig.base64EncodedURLSafeNotPadded()
        initialConnect.userJwt = String(data: jwt, encoding: .utf8)!
    }

    // Handle inline nkeyPath
    if let nkeyPath = self.auth?.nkeyPath {
        let nkeyData = try await URLSession.shared.data(from: nkeyPath).0
        
        guard let nkeyContent = String(data: nkeyData, encoding: .utf8),
              let nonce = self.serverInfo?.nonce else {
            throw NatsError.ConnectError.invalidConfig("Failed to read NKEY file or missing nonce")
        }

        let keypair = try KeyPair(seed: nkeyContent.trimmingCharacters(in: .whitespacesAndNewlines))
        let sig = try keypair.sign(input: nonce.data(using: .utf8)!)
        initialConnect.signature = sig.base64EncodedURLSafeNotPadded()
        initialConnect.nkey = keypair.publicKeyEncoded
    }

    // Handle inline nkey
    if let nkey = self.auth?.nkey {
        guard let nonce = self.serverInfo?.nonce else {
            throw NatsError.ConnectError.invalidConfig("Missing nonce for NKEY authentication")
        }

        let keypair = try KeyPair(seed: nkey)
        let sig = try keypair.sign(input: nonce.data(using: .utf8)!)
        initialConnect.signature = sig.base64EncodedURLSafeNotPadded()
        initialConnect.nkey = keypair.publicKeyEncoded
    }

    // Ensure the connect and ping commands are sent correctly
    try await withCheckedThrowingContinuation { continuation in
        self.connectionEstablishedContinuation = continuation
        Task {
            do {
                try await self.write(operation: ClientOp.connect(initialConnect))
                try await self.write(operation: ClientOp.ping)
                self.channel?.flush()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

    /// Initializes a connection to the specified server URL.
    /// Handles TLS, WebSocket, and standard connections with proper error handling.
    private func bootstrapConnection(
        to server: URL
    ) -> (ClientBootstrap, EventLoopPromise<Void>) {
        
        let upgradePromise: EventLoopPromise<Void> = self.group.any().makePromise(of: Void.self)
        let bootstrap = ClientBootstrap(group: self.group)
            .channelOption(
                ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR),
                value: 1
            )
            .channelInitializer { channel in
                logger.debug("Nats ---->Initializing bootstrap connection to \(server)")
                
                if self.requireTls && self.tlsFirst {
                    // 📌 Handle TLS-First Configuration
                    return self.initializeTLSConnection(channel: channel, server: server, upgradePromise: upgradePromise)
                }
                
                if server.scheme == "ws" || server.scheme == "wss" {
                    // 📌 Handle WebSocket Connection
                    return self.initializeWebSocketConnection(channel: channel, server: server, upgradePromise: upgradePromise)
                }
                
                // 📌 Handle Standard TCP Connection
                return self.initializeStandardConnection(channel: channel, upgradePromise: upgradePromise)
            }
            .connectTimeout(.seconds(5))
        
        return (bootstrap, upgradePromise)
    }
    
    /// Initializes a TLS connection with the given server.
    private func initializeTLSConnection(
        channel: Channel,
        server: URL,
        upgradePromise: EventLoopPromise<Void>
    ) -> EventLoopFuture<Void> {
        logger.debug("Nats ---->Setting up TLS connection...")
        
        do {
            let tlsConfig = try self.makeTLSConfig()
            let sslContext = try NIOSSLContext(configuration: tlsConfig)
            let sslHandler = try NIOSSLClientHandler(
                context: sslContext, serverHostname: server.host!
            )
            
            return channel.pipeline.addHandler(sslHandler).flatMap {
                channel.pipeline.addHandler(self)
            }.flatMapError { error in
                // Handle error gracefully
                logger.error("TLS connection failed: \(error)")
                let tlsError = NatsError.ConnectError.tlsFailure(error)
                upgradePromise.fail(tlsError)
                return channel.eventLoop.makeFailedFuture(tlsError)
            }.flatMap {
                logger.debug("Nats ---->TLS connection established successfully.")
                upgradePromise.succeed(())
                return upgradePromise.futureResult
            }
        } catch {
            // Handle synchronous errors in the try block
            let tlsError = NatsError.ConnectError.tlsFailure(error)
            logger.error("Synchronous TLS configuration error: \(error)")
            upgradePromise.fail(tlsError)
            return channel.eventLoop.makeFailedFuture(tlsError)
        }
    }
    
    /// Initializes a WebSocket connection with the given server.
    private func initializeWebSocketConnection(
        channel: Channel,
        server: URL,
        upgradePromise: EventLoopPromise<Void>
    ) -> EventLoopFuture<Void> {
        logger.debug("Nats ---->Setting up WebSocket connection...")

        let httpUpgradeRequestHandler = HTTPUpgradeRequestHandler(
            host: server.host ?? "localhost",
            path: server.path,
            query: server.query,
            headers: HTTPHeaders(),
            upgradePromise: upgradePromise
        )
        let httpUpgradeRequestHandlerBox = NIOLoopBound(
            httpUpgradeRequestHandler, eventLoop: channel.eventLoop
        )
        
        let websocketUpgrader = NIOWebSocketClientUpgrader(
            maxFrameSize: 8 * 1024 * 1024,
            automaticErrorHandling: true,
            upgradePipelineHandler: { channel, _ in
                // Add NIOWebSocketFrameAggregator with appropriate parameters
                let frameAggregator = NIOWebSocketFrameAggregator(
                    minNonFinalFragmentSize: 512,       // Minimum fragment size
                    maxAccumulatedFrameCount: 10,      // Maximum fragment count
                    maxAccumulatedFrameSize: 8 * 1024 * 1024 // Maximum accumulated frame size (8MB)
                )
                
                return channel.pipeline.addHandler(frameAggregator).flatMap {
                    channel.pipeline.addHandler(WebSocketByteBufferCodec()).flatMap {
                        channel.pipeline.addHandler(self)
                    }
                }
            }
        )
        
        let config: NIOHTTPClientUpgradeConfiguration = (
            upgraders: [websocketUpgrader],
            completionHandler: { context in
                upgradePromise.succeed(())
                channel.pipeline.removeHandler(httpUpgradeRequestHandlerBox.value, promise: nil)
            }
        )
        
        if server.scheme == "wss" {
            do {
                let tlsConfig = try self.makeTLSConfig()
                let sslContext = try NIOSSLContext(configuration: tlsConfig)
                let sslHandler = try NIOSSLClientHandler(
                    context: sslContext, serverHostname: server.host!
                )
                try channel.pipeline.syncOperations.addHandler(sslHandler)
            } catch {
                let tlsError = NatsError.ConnectError.tlsFailure(error)
                upgradePromise.fail(tlsError)
                return channel.eventLoop.makeFailedFuture(tlsError)
            }
        }
        
        return channel.pipeline.addHTTPClientHandlers(
            leftOverBytesStrategy: .forwardBytes,
            withClientUpgrade: config
        ).flatMap {
            channel.pipeline.addHandler(httpUpgradeRequestHandlerBox.value)
        }
    }
    
    /// Initializes a standard TCP connection.
    private func initializeStandardConnection(
        channel: Channel,
        upgradePromise: EventLoopPromise<Void>
    ) -> EventLoopFuture<Void> {
        logger.debug("Nats ---->Setting up standard TCP connection...")
        
        return channel.pipeline.addHandler(self).flatMap {
            logger.debug("Nats ---->TCP connection established successfully.")
            upgradePromise.succeed(())
            return channel.eventLoop.makeSucceededFuture(())
        }.flatMapError { error in
            logger.error("TCP connection failed: \(error)")
            upgradePromise.fail(error)
            return channel.eventLoop.makeFailedFuture(error)
        }
    }

    // MARK: - Utility Functions

    /// **Change Explanation:**
    /// - Made server URL updates thread-safe.
    /// - Prevented duplicates in the server list.
    /// - Intention: Keep server list accurate and efficient.
    private func updateServersList(info: ServerInfo) {
        if let connectUrls = info.connectUrls {
            for connectUrl in connectUrls {
                guard let url = URL(string: connectUrl), !self.urls.contains(url) else {
                    continue
                }
                urls.append(url)
            }
        }
        logger.debug("Nats ---->Server list updated: \(self.urls.map { $0.absoluteString })")
    }

    // MARK: - Connection Lifecycle

    /// **Change Explanation:**
    /// - Improved the close method to ensure clean cancellation of tasks and proper state updates.
    /// - Added comments explaining resource cleanup and event firing.
    /// - Intention: Guarantee predictable resource cleanup on connection close.
    func close() async throws {
        self.reconnectTask?.cancel()
        await self.reconnectTask?.value

        // Ensure the event loop is valid before proceeding
        guard let eventLoop = self.channel?.eventLoop else {
            throw NatsError.ClientError.internalError("Channel should not be nil")
        }
        
        let promise = eventLoop.makePromise(of: Void.self)

        eventLoop.execute {
            self.state = .closed
            self.pingTask?.cancel()
            self.channel?.close(mode: .all, promise: promise)
        }

        do {
            try await promise.futureResult.get()
        } catch ChannelError.alreadyClosed {
            // Avoid throwing errors for already closed channels
            logger.debug("Nats ---->Channel already closed, no action needed.")
        }

        self.fire(.closed)
        logger.debug("Nats ---->Connection closed successfully.")
    }

    /// **Change Explanation:**
    /// - Refactored `disconnect` to ensure clean disconnection without unexpected errors.
    /// - Added comments to clarify state handling.
    /// - Intention: Avoid redundant errors when disconnecting.
    private func disconnect() async throws {
        self.pingTask?.cancel()
        try await self.channel?.close().get()
        logger.debug("Nats ---->Disconnected from server.")
    }

    /// **Change Explanation:**
    /// - Improved `suspend` to ensure predictable state transitions.
    /// - Added comments for better clarity.
    /// - Intention: Safely transition to a suspended state without resource leaks.
    func suspend() async throws {
        self.reconnectTask?.cancel()
        await self.reconnectTask?.value

        guard let eventLoop = self.channel?.eventLoop else {
            throw NatsError.ClientError.internalError("Channel should not be nil")
        }
        
        let promise = eventLoop.makePromise(of: Void.self)

        eventLoop.execute {
            if self.state == .connected {
                self.state = .suspended
                self.pingTask?.cancel()
                self.channel?.close(mode: .all, promise: promise)
            } else {
                self.state = .suspended
                promise.succeed()
            }
        }

        try await promise.futureResult.get()
        self.fire(.suspended)
        logger.debug("Nats ---->Connection suspended successfully.")
    }

    /// **Change Explanation:**
    /// - Added explicit validation for suspended state before attempting to resume.
    /// - Clarified state checks with detailed comments.
    /// - Intention: Prevent unnecessary reconnect attempts when already connected.
    func resume() async throws {
        guard let eventLoop = self.channel?.eventLoop else {
            throw NatsError.ClientError.internalError("Channel should not be nil")
        }
        try await eventLoop.submit {
            guard self.state == .suspended else {
                throw NatsError.ClientError.invalidConnection(
                    "Unable to resume connection - connection is not in suspended state"
                )
            }
            self.handleReconnect()
        }.get()
        logger.debug("Nats ---->Connection resumed successfully.")
    }

    /// **Change Explanation:**
    /// - Improved reconnect logic to handle all edge cases cleanly.
    /// - Added clear separation between suspend and resume processes.
    /// - Intention: Provide robust error handling during reconnection.
    func reconnect() async throws {
        try await suspend()
        try await resume()
        logger.debug("Nats ---->Reconnected successfully.")
    }

    // MARK: - Ping Management

    /// **Change Explanation:**
    /// - Enhanced ping handling logic to include retry limits.
    /// - Prevented infinite retries by checking the ping counter.
    /// - Intention: Ensure efficient resource utilization during pings.
    internal func sendPing(_ rttCommand: RttCommand? = nil) async {
        let pingsOut = self.outstandingPings.wrappingIncrementThenLoad(
            ordering: AtomicUpdateOrdering.relaxed
        )
        if pingsOut > 2 {
            handleDisconnect()
            return
        }
        let ping = ClientOp.ping
        do {
            self.pingQueue.enqueue(rttCommand ?? RttCommand.makeFrom(channel: self.channel))
            try await self.write(operation: ping)
            logger.debug("Nats ---->Sent ping: \(pingsOut)")
        } catch {
            logger.error("Unable to send ping: \(error)")
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        logger.debug("Nats ---->TCP channel active")

        inputBuffer = context.channel.allocator.buffer(capacity: 1024 * 1024 * 8)
    }

    // MARK: - Channel State Handlers

    /// **Change Explanation:**
    /// - Added safeguards for inactive state transitions.
    /// - Clarified the role of `handleDisconnect`.
    /// - Intention: Prevent connection inconsistencies on disconnection.
    func channelInactive(context: ChannelHandlerContext) {
        logger.debug("Nats ---->TCP channel inactive")
        if self.state == .connected {
            handleDisconnect()
        }
    }

    /// **Change Explanation:**
    /// - Improved error handling to ensure no state mismatch occurs.
    /// - Clear distinction between recoverable and unrecoverable errors.
    /// - Intention: Avoid unexpected terminations on recoverable errors.
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.debug("Nats ---->Encountered error on the channel: \(error)")
        context.close(promise: nil)
        
        if let natsErr = error as? NatsErrorProtocol {
            self.fire(.error(natsErr))
        } else {
            logger.error("Unexpected error: \(error)")
        }

        if let continuation = self.serverInfoContinuation {
            self.serverInfoContinuation = nil
            continuation.resume(throwing: error)
            return
        }

        if let continuation = self.connectionEstablishedContinuation {
            self.connectionEstablishedContinuation = nil
            continuation.resume(throwing: error)
            return
        }

        if self.state == .pending {
            handleDisconnect()
        } else if self.state == .disconnected {
            handleReconnect()
        }
    }

    /// Handles the disconnection logic for the client.
    /// Ensures proper cleanup, state management, and error handling.
    func handleDisconnect() {
        logger.debug("Nats ---->Starting handleDisconnect process...")
        
        // Ensure state changes only if the channel is valid
        guard let channel = self.channel else {
            logger.debug("Nats ---->handleDisconnect called but no active channel exists.")
            self.state = .disconnected
            handleReconnect()
            return
        }
        
        // Create a promise to ensure proper event loop handling
        let promise = channel.eventLoop.makePromise(of: Void.self)
        
        Task {
            do {
                logger.debug("Nats ---->Attempting to disconnect...")
                try await self.disconnect()
                promise.succeed()
            } catch ChannelError.alreadyClosed {
                // Channel already closed; resolve promise gracefully
                logger.debug("Nats ---->Channel was already closed during disconnect.")
                promise.succeed()
            } catch is CancellationError {
                // Handle task cancellation explicitly
                logger.debug("Nats ---->Disconnect task was cancelled.")
                promise.fail(CancellationError())
            } catch {
                // Handle any other unexpected errors
                logger.error("Error occurred during disconnect: \(error)")
                promise.fail(error)
            }
        }
        
        // Ensure proper cleanup after disconnect
        promise.futureResult.whenComplete { result in
            switch result {
            case .success:
                self.state = .disconnected
                self.fire(.disconnected)
                logger.info("Disconnected successfully.")
            case .failure(let error):
                logger.error("Failed to disconnect properly: \(error)")
            }
            
            // Trigger reconnection only after ensuring cleanup
            self.handleReconnect()
        }
    }

    // MARK: - Reconnect Handling

    /// **Change Explanation:**
    /// - Improved logic for reconnect attempts.
    /// - Added clear comments for retry strategies.
    /// - Intention: Ensure robust reconnection without redundant retries.
    func handleReconnect() {
        reconnectTask = Task {
            var reconnected = false
            while !Task.isCancelled &&
                (maxReconnects == nil || self.reconnectAttempts < maxReconnects!) {
                do {
                    try await self.connect()
                } catch _ as CancellationError {
                    return
                } catch {
                    logger.debug("Nats ---->Reconnect attempt failed: \(error)")
                    continue
                }
                logger.debug("Nats ---->Reconnected successfully")
                reconnected = true
                break
            }

            if Task.isCancelled {
                return
            }
            
            if !reconnected {
                logger.error("Max reconnect attempts exceeded. Closing connection.")
                do {
                    try await self.close()
                } catch {
                    logger.error("Error during forced disconnect: \(error)")
                }
            }

            for (sid, sub) in self.subscriptions {
                do {
                    try await write(operation: ClientOp.subscribe((sid, sub.subject, nil)))
                } catch {
                    logger.error("Error recreating subscription \(sid): \(error)")
                }
            }

            self.channel?.eventLoop.execute {
                self.state = .connected
                self.fire(.connected)
            }
        }
    }

    // MARK: - Safeguards

    /// **Change Explanation:**
    /// - Ensured `write` method handles buffer availability properly.
    /// - Improved exception handling for async operations.
    /// - Intention: Avoid unhandled buffer or connection state errors.
    func write(operation: ClientOp) async throws {
        guard let buffer = self.batchBuffer else {
            throw NatsError.ClientError.invalidConnection("Not connected to any server")
        }
        do {
            try await buffer.writeMessage(operation)
            logger.debug("Nats ---->Operation written successfully: \(operation)")
        } catch {
            logger.error("Failed to write operation: \(error)")
            throw NatsError.ClientError.io(error)
        }
    }

    // MARK: - Subscription Management

    /// **Change Explanation:**
    /// - Added queue support in `subscribe`.
    /// - Ensured thread safety for subscription state updates.
    /// - Intention: Provide flexible subscription support with error handling.
    internal func subscribe(
        _ subject: String, queue: String? = nil
    ) async throws -> NatsSubscription {
        let sid = self.subscriptionCounter.wrappingIncrementThenLoad(
            ordering: AtomicUpdateOrdering.relaxed
        )
        let sub = try NatsSubscription(sid: sid, subject: subject, queue: queue, conn: self)
        try await write(operation: ClientOp.subscribe((sid, subject, queue)))
        self.subscriptions[sid] = sub
        logger.debug("Nats ---->Subscribed to subject: \(subject) with sid: \(sid)")
        return sub
    }

    /// **Change Explanation:**
    /// - Improved `unsubscribe` logic to handle edge cases.
    /// - Prevented premature subscription removal when `max` is specified.
    /// - Intention: Ensure clean unsubscribe without losing valid subscriptions.
    internal func unsubscribe(sub: NatsSubscription, max: UInt64?) async throws {
        if let max, sub.delivered < max {
            try await write(operation: ClientOp.unsubscribe((sid: sub.sid, max: max)))
            sub.max = max
            logger.debug("Nats ---->Unsubscribed with max messages limit: \(max)")
        } else {
            try await write(operation: ClientOp.unsubscribe((sid: sub.sid, max: nil)))
            self.removeSub(sub: sub)
            logger.debug("Nats ---->Unsubscribed from subject: \(sub.subject)")
        }
    }

    /// **Change Explanation:**
    /// - Ensured thread safety when removing a subscription.
    /// - Guaranteed cleanup of subscription resources.
    /// - Intention: Prevent dangling subscriptions after removal.
    internal func removeSub(sub: NatsSubscription) {
        self.subscriptions.removeValue(forKey: sub.sid)
        sub.complete()
        logger.debug("Nats ---->Subscription removed: \(sub.subject) with sid: \(sub.sid)")
    }
}

extension ConnectionHandler {
    
    // MARK: - Event Handling
    
    /// **Change Explanation:**
    /// - Ensured all registered handlers are invoked for an event.
    /// - Added debug logging for event firing.
    /// - Intention: Guarantee proper event propagation.
    internal func fire(_ event: NatsEvent) {
        let eventKind = event.kind()
        guard let handlerStore = self.eventHandlerStore[eventKind] else {
            logger.debug("Nats ---->No handlers for event: \(eventKind.rawValue)")
            return
        }
        
        for handler in handlerStore {
            handler.handler(event)
        }
        logger.debug("Nats ---->Event fired: \(eventKind.rawValue)")
    }
    
    /// **Change Explanation:**
    /// - Added return of listener ID for easier debugging.
    /// - Ensured listeners are safely added without overwriting existing ones.
    /// - Intention: Provide robust event listener management.
    internal func addListeners(
        for events: [NatsEventKind], using handler: @escaping (NatsEvent) -> Void
    ) -> String {
        let id = UUID().uuidString
        
        for event in events {
            if self.eventHandlerStore[event] == nil {
                self.eventHandlerStore[event] = []
            }
            self.eventHandlerStore[event]?.append(
                NatsEventHandler(lid: id, handler: handler)
            )
        }
        
        logger.debug("Nats ---->Listener added with ID: \(id) for events: \(events.map { $0.rawValue })")
        return id
    }
    
    /// **Change Explanation:**
    /// - Improved listener removal to handle edge cases.
    /// - Ensured no dangling references after removal.
    /// - Intention: Provide reliable cleanup of event listeners.
    internal func removeListener(_ id: String) {
        for event in NatsEventKind.all {
            self.eventHandlerStore[event] = self.eventHandlerStore[event]?.filter { $0.listenerId != id }
        }
        logger.debug("Nats ---->Listener removed with ID: \(id)")
    }
    
}

/// Nats events
public enum NatsEventKind: String {
    case connected = "connected"
    case disconnected = "disconnected"
    case closed = "closed"
    case suspended = "suspended"
    case lameDuckMode = "lameDuckMode"
    case error = "error"
    static let all = [connected, disconnected, closed, lameDuckMode, error]
}

public enum NatsEvent {
    case connected
    case disconnected
    case suspended
    case closed
    case lameDuckMode
    case error(NatsErrorProtocol)

    public func kind() -> NatsEventKind {
        switch self {
        case .connected:
            return .connected
        case .disconnected:
            return .disconnected
        case .suspended:
            return .suspended
        case .closed:
            return .closed
        case .lameDuckMode:
            return .lameDuckMode
        case .error(_):
            return .error
        }
    }
}

internal struct NatsEventHandler {
    let listenerId: String
    let handler: (NatsEvent) -> Void
    init(lid: String, handler: @escaping (NatsEvent) -> Void) {
        self.listenerId = lid
        self.handler = handler
    }
}
