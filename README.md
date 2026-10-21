# CS-128H-Project - HTTP(S) Web Server from Scratch

## Group Names
- Ethan (ethanc14)
- Alex (alexr10)
- Afraz (afrazs2)

## Introduction
Our end goal with this project is to build a basic web server that can support a website with users and login. In order to achieve this, we will need a database, handler for HTTP(S) protocols, and a way to build web pages. We plan to store and read the database information in and from files. We have chosen this project because we are interested in web development, cryptography, and file I/O in Rust.

# Technical Overview

## Front End
### Checkpoint 1
### Checkpoint 2

## Back End
Our back-end will parse requests from the client and query the database from information when relevant. The server will implement either the HTTP/3 or HTTP/1.1 protocol to serve requested data to the client in a timely and efficient manner. The server should also be safe against most common malicious inputs, such as SQL injection and XSS.
### Checkpoint 1
Basic dummy request parsing, should be able to identify which file to serve from dummy requests.
### Checkpoint 2
Integration with the front-end to parse arbitrary requests, handle malformed and malicious inputs.

## Database
Our database will write and read to files which will act as the tables for the database. The name of the file will function as the table name. Every table will be backed by a struct that serves as a reference for how to read data out of the corresponding file. If time permits, we will also implement optimizations such as table indexing.
### Checkpoint 1
Have basic file I/O implemented and one table as a proof of concept.
### Checkpoint 2
Have querying functions implemented and multiple supporting tables.

# Possible Challenges
- Parsing database requests from the  backend.
- Parsing file/data requests from the client.

## References