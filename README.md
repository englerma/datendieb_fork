# Datendieb

![GitHub repo size](https://img.shields.io/github/repo-size/bananakaba/datendieb)
![GitHub contributors](https://img.shields.io/github/contributors/bananakaba/datendieb)
![GitHub stars](https://img.shields.io/github/stars/bananakaba/datendieb?style=social)
![GitHub forks](https://img.shields.io/github/forks/bananakaba/datendieb?style=social)
![GitHub issues](https://img.shields.io/github/issues/bananakaba/datendieb)

Datendieb is a project focused on client-server communication to gather and manage data. This is a forked project of [bananakaba/datendieb](https://github.com/bananakaba/datendieb).

## Table of Contents

- [General](#general)
- [Client](#client)
- [Server](#server)
- [Usage](#usage)
- [Examples](#Examples)

## General

This project includes two main components: `client.py` and `server.py`. The server script needs to be started first to open a socket and wait for client connections. Once connected, the server instructs the client to perform specified actions and gathers the resulting data.

## Client

### client.py

- **Platform:** Linux and Windows
- **Description:** 
  - The client script communicates with the server to execute commands and send back information.
  - No user interaction is required once the script is started.

## Server

### server.py

- **Description:** 
  - The server script sets up a socket to listen for client connections.
  - It instructs the client on actions to perform and gathers the resulting data.
  - The server remains running, waiting for new client connections even after a client disconnects.

## Usage

### Start client.py

To start the client script, use the following command:

```cmd
python client.py -H <SERVER-IP> -P <SERVER-PORT> -cport <CLIENT-PORT> --cert ./cert/client-cert.pem --key ./cert/client-key.pem --ca-cert ./cert/ca-cert.pem
```

### Start server.py

To start the server script, use the following command:

```sh
sudo python server.py -H <SERVER-IP> -P <SERVER-PORT> --cert ./Source/cert/server-cert.pem --key ./Source/cert/server-key.pem --ca-cert ./Source/cert/ca-cert.pem
```

## Examples

### Start client.py

To start the client script, use the following command:

```cmd
python client.py -H 192.168.91.129 -P 65432 -cport 50000 --cert ./cert/client-cert.pem --key ./cert/client-key.pem --ca-cert ./cert/ca-cert.pem
```

### Start server.py

To start the server script, use the following command:

```sh
sudo python server.py -H 0.0.0.0 -P 65432 --cert ./Source/cert/server-cert.pem --key ./Source/cert/server-key.pem --ca-cert ./Source/cert/ca-cert.pem
```
