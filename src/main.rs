use CS_128H_Project::views::pages;
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let listner = TcpListener::bind("127.0.0.1:8080").unwrap();

    for stream in listner.incoming() {
        let mut stream = stream.unwrap();

        let mut buf = [0; 4096];
        let n = stream.read(&mut buf).unwrap();

        let request = String::from_utf8_lossy(&buf[..n]);
        println!("{}", request);
        let path = request.split_whitespace().nth(1).unwrap_or("/");
        if path == "/static/7.css" {
            let css = std::fs::read_to_string("static/7.css").unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: {}\r\n\r\n{}",
                css.len(),
                css
            );
            stream.write_all(response.as_bytes()).unwrap();
        } else if path.starts_with("/static/") && path.ends_with(".png") && !path.contains("..") {
            // "/static/images/home.png" -> "static/images/home.png"
            let file_path = &path[1..];
            match std::fs::read(file_path) {
                Ok(image) => {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\n\r\n",
                        image.len()
                    );
                    stream.write_all(headers.as_bytes()).unwrap();
                    stream.write_all(&image).unwrap();
                }
                Err(_) => {
                    stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                        .unwrap();
                }
            }
        } else {
            let body = pages::home::render().into_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    }
}
