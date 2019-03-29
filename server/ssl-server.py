import argparse
import sys
import logging
import socket
import ssl
import pprint

PORT = 13443
HOST = 'u1.bingo.ericsson.se'
server_cert = 'ssl/ses-exp-server-cert-20190326.pem'
server_key = 'ssl/ses-exp-server-private.pem'

def deal_with_client(connstream):
    data = connstream.recv()
    # null data means the client is finished with us
    while data:
        if not reply_client(connstream, data):
            # we'll assume do_something returns False
            # when we're finished with client
            break
        data = connstream.recv()
    # finished with client

def reply_client(conn, data):
    encoding = 'utf-8'
    header = [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json'
    ]
    body = [
      '{"response-id":1001',
      '"status":6005}'
    ]

    response = '\n'.join(header) + '\r\n\r\n' + ','.join(body)

    logger.debug('recieved from client:\n%s' % (str(data, 'utf-8'),))
    conn.sendall(response.encode(encoding))

def start_server(enable_ssl3_0):
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

  if enable_ssl3_0:
    context.options &= ~ssl.OP_NO_SSLv3

  context.load_cert_chain(certfile=server_cert, keyfile=server_key)

  bindsocket = socket.socket()

  bindsocket.bind((HOST, PORT))
  logger.debug('Bound to: %s:%d' % (HOST, PORT))

  bindsocket.listen(5)
  logger.debug('Listening on: %s:%d\n' % (HOST, PORT))

  while True:
    newsocket, fromaddr = bindsocket.accept()
    logger.debug('accepted client socket: %s:%d' % fromaddr)

    connstream = context.wrap_socket(newsocket, server_side=True)
    try:
      deal_with_client(connstream)
    finally:
      connstream.shutdown(socket.SHUT_RDWR)
      connstream.close()

if __name__ == '__main__':
  # Default setting for logging.
  log_level = logging.INFO
  FORMAT = '%(asctime)-15s [%(name)-12s] %(levelname)-8s %(message)s'
  logging.basicConfig(level=log_level, format=FORMAT)
  logger = logging.getLogger(sys.argv[0])

  parser = argparse.ArgumentParser(prefix_chars='-+', \
    formatter_class=argparse.RawTextHelpFormatter, \
    description='Description:\n\tssl/tls server for tests. (EXANTNG)')
    
  parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode.')
  parser.add_argument('--enable-ssl3.0', action='store_true', dest='ssl3_0', help='enable SSLv3.0.')

  args = parser.parse_args()

  if args.debug == True:
    logger.setLevel(logging.DEBUG)
    logger.debug('Debug mode enabled.')

  enable_ssl3_0 = False
  if args.ssl3_0:
    logger.info('insecure SSLv3.0 enabled.')
    enable_ssl3_0 = True

  start_server(enable_ssl3_0)
