# MPTP Architecture

## System Overview

MPTP (Multipath Transport Protocol) aggregates multiple reliable connections into a single logical tunnel to provide bandwidth aggregation and connection resilience.

```mermaid
graph TD
    subgraph "Local Environment"
        App["User Application<br/>(Browser/Curl)"]
        
        subgraph "MPTP Client"
            S5["SOCKS5 Listener<br/>TCP:1080 / UDP:Bind"]
            SessionMgr_C["Session Manager"]
            
            subgraph "MPTP Stream (Client Side)"
                Splitter_C["Data Splitter"]
                Combiner_C["Data Combiner"]
            end
        end
    end

    subgraph "Internet / Network (Multipath)"
        Relay1["Relay Server A<br/>(e.g., SOCKS5 Proxy)"]
        Relay2["Relay Server B<br/>(e.g., HTTP Proxy)"]
        Direct["Direct Connection"]
    end

    subgraph "Remote Environment"
        subgraph "MPTP Server"
            Listener_S["TCP Listener<br/>0.0.0.0:10000"]
            SessionMgr_S["Session Manager<br/>Map<CID, Session>"]
            
            subgraph "MPTP Stream (Server Side)"
                Combiner_S["Data Combiner"]
                Splitter_S["Data Splitter"]
            end
            
            TargetConn["Target Connector<br/>TCP/UDP Socket"]
        end
        
        Target["Target Server<br/>(e.g., google.com)"]
    end

    %% SOCKS5 Flow
    App <-->|SOCKS5 Protocol| S5
    S5 -->|"New Session"| SessionMgr_C
    
    %% MPTP Session Setup (Multipath Routing)
    SessionMgr_C -- "Sub-conn 1" --> Relay1
    SessionMgr_C -- "Sub-conn 2" --> Relay2
    SessionMgr_C -- "Sub-conn 3" --> Direct
    
    Relay1 -->|"Forward"| Listener_S
    Relay2 -->|"Forward"| Listener_S
    Direct -->|"Forward"| Listener_S

    Listener_S -- "Match CID" --> SessionMgr_S
    
    %% Data Flow (Client -> Server)
    S5 -->|"Raw Data"| Splitter_C
    Splitter_C -->|"Frame (Len+Data)"| Relay1 & Relay2 & Direct
    Relay1 & Relay2 & Direct -->|"Frame"| Combiner_S
    Combiner_S -->|"Reassembled Data"| TargetConn
    
    %% Data Flow (Server -> Client)
    TargetConn -->|"Raw Data"| Splitter_S
    Splitter_S -->|"Frame (Len+Data)"| Relay1 & Relay2 & Direct
    Relay1 & Relay2 & Direct -->|"Frame"| Combiner_C
    Combiner_C -->|"Reassembled Data"| S5
    
    %% Target Connection
    TargetConn <-->|"TCP/UDP"| Target

    classDef component fill:#f9f,stroke:#333,stroke-width:2px;
    classDef network fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
    classDef logic fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;

    class App,Target component;
    class Relay1,Relay2,Direct network;
    class Splitter_C,Combiner_C,Splitter_S,Combiner_S,SessionMgr_C,SessionMgr_S logic;
```

## Protocol Sequence

This diagram details the connection establishment and data transfer phases.

```mermaid
sequenceDiagram
    participant App as User App
    participant Client as MPTP Client
    participant Relay1 as Relay Server A
    participant Relay2 as Relay Server B
    participant Server as MPTP Server
    participant Target as Target Server

    Note over App, Client: SOCKS5 Handshake
    App->>Client: SOCKS5 Init (No Auth)
    Client-->>App: SOCKS5 Choice (No Auth)
    App->>Client: SOCKS5 Request (Connect/UDP, DST)
    
    Note over Client, Server: MPTP Session Establishment
    Client->>Client: Generate CID (UUID)
    
    par Establish multiple sub-connections (Multipath via Relays)
        Note over Client, Relay1: Path 1 (via Relay A)
        Client->>Relay1: Connect
        Relay1->>Server: Connect (Proxy)
        Client->>Server: Handshake [VER, CID, CMD, DST_ADDR, DST_PORT]
    and
        Note over Client, Relay2: Path 2 (via Relay B)
        Client->>Relay2: Connect
        Relay2->>Server: Connect (Proxy)
        Client->>Server: Handshake [VER, CID, CMD, DST_ADDR, DST_PORT]
    and
        Note over Client, Server: Path 3 (Direct)
        Client->>Server: Connect
        Client->>Server: Handshake [VER, CID, CMD, DST_ADDR, DST_PORT]
    end

    Server->>Server: CID lookup, join existing session or create new
    alt TCP mode
        Server->>Target: TCP connect to destination
    else UDP mode
        Server->>Server: Prepare UDP forwarding socket
    end
    Client-->>App: SOCKS5 success reply

    loop Data tunneling with multipath scheduling
        App->>Client: TCP bytes or UDP packet
        Client->>Client: Encapsulate and schedule across sub-connections
        Client->>Server: Send via best available sub-connection(s)
        Server->>Target: Forward to destination
        Target->>Server: Return traffic
        Server->>Client: Return via selected sub-connection(s)
        Client-->>App: Deliver to app
    end

    note over App,Target: Future phases add health probes, scoring, recovery after cuts, and network migration handling.
```
