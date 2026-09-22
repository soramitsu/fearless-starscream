//////////////////////////////////////////////////////////////////////////////////////////////////
//
//  HTTPTransport.swift
//  Starscream
//
//  Created by Dalton Cherry on 1/23/19.
//  Copyright © 2019 Vluxe. All rights reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//////////////////////////////////////////////////////////////////////////////////////////////////

#if canImport(Network)
import Foundation
import Network

public enum TCPTransportError: Error {
    case invalidRequest
}

@available(macOS 10.14, iOS 12.0, watchOS 5.0, tvOS 12.0, *)
public class TCPTransport: AuthorizedTransport {
    private var connection: NWConnection?
    private let queue = DispatchQueue(label: "com.vluxe.starscream.networkstream", attributes: [])
    private weak var delegate: TransportEventClient?
    private var isRunning = false
    private var isTLS = false
    private let writeContextLock = NSLock()
    private final class WriteContext {
        let connection: NWConnection
        init(_ connection: NWConnection) { self.connection = connection }
    }
    private var writeContext: WriteContext?
    private var authorizedConnection: NWConnection?
    
    public var usingTLS: Bool {
        return self.isTLS
    }
    
    public init(connection: NWConnection) {
        self.connection = connection
        authorizedConnection = connection
        start()
    }
    
    public init() {
        //normal connection, will use the "connect" method below
    }
    
    public func connect(url: URL, timeout: Double = 10, certificatePinning: CertificatePinning? = nil) {
        guard let parts = url.getParts() else {
            delegate?.connectionChanged(state: .failed(TCPTransportError.invalidRequest))
            return
        }
        self.isTLS = parts.isTLS
        let options = NWProtocolTCP.Options()
        options.connectionTimeout = Int(timeout.rounded(.up))

        let tlsOptions = isTLS ? NWProtocolTLS.Options() : nil
        if let tlsOpts = tlsOptions {
            sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { (sec_protocol_metadata, sec_trust, sec_protocol_verify_complete) in
                let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()
                guard let pinner = certificatePinning else {
                    sec_protocol_verify_complete(true)
                    return
                }
                pinner.evaluateTrust(trust: trust, domain: parts.host, completion: { [weak self] (state) in
                    switch state {
                    case .success:
                        sec_protocol_verify_complete(true)
                    case .failed(let error):
                        sec_protocol_verify_complete(false)
                        self?.delegate?.connectionChanged(state: .failed(error))
                    }
                })
            }, queue)
        }
        let parameters = NWParameters(tls: tlsOptions, tcp: options)
        let conn = NWConnection(host: NWEndpoint.Host.name(parts.host, nil), port: NWEndpoint.Port(rawValue: UInt16(parts.port))!, using: parameters)
        connection = conn
        writeContextLock.lock()
        authorizedConnection = conn
        writeContext = nil
        writeContextLock.unlock()
        start()
    }
    
    public func disconnect() {
        writeContextLock.lock()
        writeContext = nil
        authorizedConnection = nil
        writeContextLock.unlock()
        isRunning = false
        connection?.cancel()
    }
    
    public func register(delegate: TransportEventClient) {
        self.delegate = delegate
    }
    
    public func write(data: Data, completion: @escaping ((Error?) -> ())) {
        connection?.send(content: data, completion: .contentProcessed { (error) in
            completion(error)
        })
    }

    internal func captureWriteContext() -> AnyObject? {
        writeContextLock.lock()
        defer { writeContextLock.unlock() }
        guard let context = writeContext, case .ready = context.connection.state else { return nil }
        return context
    }

    internal func write(data: Data, context: AnyObject, operation: AuthorizedWrite,
                        authorization: WebSocketWriteAuthorizing, completion: @escaping (Error?) -> Void) throws {
        writeContextLock.lock()
        defer { writeContextLock.unlock() }
        guard let current = writeContext, current === context,
              case .ready = current.connection.state else {
            throw AuthorizedWriteError.connectionChanged
        }
        // Lock waits and connection validation precede the final authority
        // clock sample. There is no library queue/serialization after it.
        operation.perform(authorization: authorization) {
            current.connection.send(content: data, completion: .contentProcessed(completion))
        }
    }

    private func invalidateWriteContext(for connection: NWConnection) {
        writeContextLock.lock()
        if writeContext?.connection === connection { writeContext = nil }
        writeContextLock.unlock()
    }
    
    private func start() {
        guard let conn = connection else {
            return
        }
        conn.stateUpdateHandler = { [weak self] (newState) in
            switch newState {
            case .ready:
                if let transport = self {
                    transport.writeContextLock.lock()
                    if transport.authorizedConnection === conn { transport.writeContext = WriteContext(conn) }
                    transport.writeContextLock.unlock()
                }
                self?.delegate?.connectionChanged(state: .connected)
            case let .waiting(error):
                self?.invalidateWriteContext(for: conn)
                switch error {
                 case .posix(let errorCode):
                     if (errorCode == .ETIMEDOUT) {
                         self?.delegate?.connectionChanged(state: .timeout)
                     } else {
                         self?.delegate?.connectionChanged(state: .waiting(error: error))
                     }
                 default:
                    self?.delegate?.connectionChanged(state: .waiting(error: error))
                 }
            case .cancelled:
                self?.invalidateWriteContext(for: conn)
                self?.delegate?.connectionChanged(state: .cancelled)
            case .failed(let error):
                self?.invalidateWriteContext(for: conn)
                self?.delegate?.connectionChanged(state: .failed(error))
            case .setup, .preparing:
                break
            @unknown default:
                break
            }
        }
        
        conn.viabilityUpdateHandler = { [weak self] (isViable) in
            self?.delegate?.connectionChanged(state: .viability(isViable))
        }
        
        conn.betterPathUpdateHandler = { [weak self] (isBetter) in
            self?.delegate?.connectionChanged(state: .shouldReconnect(isBetter))
        }
        
        conn.start(queue: queue)
        isRunning = true
        readLoop()
    }
    
    //readLoop keeps reading from the connection to get the latest content
    private func readLoop() {
        if !isRunning {
            return
        }
        connection?.receive(minimumIncompleteLength: 2, maximumLength: 4096, completion: {[weak self] (data, context, isComplete, error) in
            guard let s = self else {return}
            if let data = data {
                s.delegate?.connectionChanged(state: .receive(data))
            }
            
            // Refer to https://developer.apple.com/documentation/network/implementing_netcat_with_network_framework
            if let context = context, context.isFinal, isComplete {
                return
            }
            
            if error == nil {
                s.readLoop()
            }

        })
    }
}
#else
typealias TCPTransport = FoundationTransport
#endif
