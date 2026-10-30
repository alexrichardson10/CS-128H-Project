# CS-128H-Project - HTTP(S) Web Server from Scratch

## Group Names
- Ethan (ethanc14)
- Alex (alexr10)
- Afraz (afrazs2)

## Introduction
Our end goal with this project is to build a basic web server that can support a website with users and login. In order to achieve this, we will need a database, handler for HTTP(S) protocols, and a way to build web pages. We plan to store and read the database information in and from files. We have chosen this project because we are interested in web development, cryptography, and file I/O in Rust.

# Technical Overview

## Front End
Our front-end will be written entirely in Rust. Pages will be generated server-side as HTML strings by Rust functions (e.g. `login_page()`, `profile_page()`), with styling stored as a CSS string constant. User input will be sent back to the server through standard HTML forms, so no JavaScript is required. All user-supplied data will be HTML-escaped before being rendered to prevent XSS.
### Checkpoint 1
The front end will contain the UI and display the login screen with a username and password field. Submitting the form sends an HTTP POST request that the Back End parses and handles. This will require:
- A small HTML-building layer (either `format!` templates or a crate like `maud`) and a shared page layout (header, styles).
- A login page with a `<form method="POST" action="/login">` containing username and password inputs.
- A function that turns a rendered page into a full HTTP response (status line, `Content-Type: text/html`, `Content-Length`), shared with the Back End.
- An error/404 page, plus displaying a "wrong username or password" message on the login page.
- An `escape_html` helper, with unit tests, for any text that comes from the user.
### Checkpoint 2
After logging in, the user is able to see some data about them from the database. This will require:
- A sign-up page with a form for creating a new account, which inserts a row into the users table.
- A profile/dashboard page that takes a `User` struct (defined in `shared`) and renders that user's data from the database.
- Session handling: setting a session cookie on successful login and checking it on protected pages, redirecting to `/login` when it is missing or invalid.
- A logout route that clears the session.
- Navigation links between pages and basic styling so the site is usable.


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
