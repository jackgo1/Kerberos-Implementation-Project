# Kerberos Implementation Project

This repository contains the implementation of a simplified version of the Kerberos authentication protocol as a part of a university project. The project is structured into several components, including the Authentication Server, Message Service Server, Client Application, and a script to demonstrate a dictionary attack on the protocol.
For more technical details about the project, go to the PDF file "Project Instructions"

## Overview

The project simulates the Kerberos authentication mechanism allowing clients to securely communicate with services through an authentication server. It uses AES encryption for securing the communication channels.

### Components

1. **Auth Server**: The central authentication server responsible for registering users and services, and issuing tickets for secure communication.
2. **MSG Server (Message Service Server)**: A service that clients can communicate with after obtaining a valid ticket from the Auth Server.
3. **Client**: The client application that registers with the Auth Server, requests tickets for services, and communicates with the MSF Server using the tickets.
4. **Dictionary Attack Script**: A demonstration of how a dictionary attack could be performed against the protocol implementation to uncover user passwords.
5. **run.bat**: A simple tool to automaticly run the servers and the client 


## Requirements

- Python 3.x
- PyCryptodome library

