# About

This project provides an Easy WebSocket Server with JSON-RPC functionality, conforming to WebSocket Protocol Version 13. It is built using libwebsockets, JSON-C, and OpenSSL for secure communication and efficient data handling.

The project is designed to work seamlessly in embedded environments, such as OpenWrt, offering a lightweight and robust solution for WebSocket communication.

# Features

  - WebSocket Server: Implements WebSocket Protocol Version 13.
  - JSON-RPC: Provides a structured way to handle remote procedure calls over WebSocket.
  - Security: Utilizes OpenSSL for encrypted communication.
  - Lightweight: Optimized for performance in embedded systems.

# Build Instructions

To build and install the easy-websockd server, ensure you have the necessary dependencies installed

## Dependencies

  - libwebsockets
  - libjson-c
  - libopenssl

## Build Environment

This project is designed to be built in an OpenWrt SDK environment. The Makefile integrates with OpenWrt's build system.
  - Navigate to your OpenWrt build root directory.
  - Place the source files in package/easy-websockd/src/.
  - Place the Makefile in package/easy-websockd/Makefile.

## Build Steps

Run the following commands in the OpenWrt build environment:
```
make package/easy-websockd/compile
make package/easy-websockd/install
```
The compiled binary will be installed in /bin and the init script in /etc/init.d.


## Installation

After building, install the package on your OpenWrt device:
```
opkg install /path/to/easy-websockd.ipk
```

Start the server using the init script:
```
/etc/init.d/easy-websockd start
```
