# Datendieb

## General

This is a forked project of https://github.com/bananakaba/datendieb

## client.py

File to run on the client.
Should work with Linux and Windows.
No interaction required, just start the file.
Server.py needs to be started before.

## server.py

Communicates with client.py.
Needs to be run first.
Opening socket for connection to client.
Give action to perform on the client.
Creating files with gathered information on server.
Keeps running after client determines connection and waits for new connection.
