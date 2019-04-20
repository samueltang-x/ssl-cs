import argparse
import configparser
import json
import sys
import logging
import socket
import ssl
import pprint


VERSION_MAP = {
  'tls1.0': ssl.TLSVersion.TLSv1,
  'tls1.1': ssl.TLSVersion.TLSv1_1,
  'tls1.2': ssl.TLSVersion.TLSv1_2,
  'tls1.3': ssl.TLSVersion.TLSv1_3,
}

HTTP_STATUS = {
  100: 'Continue',
  101: 'Switching Protocols',
  200: 'OK',
  201: 'Created',
  202: 'Accepted',
  203: 'Non-Authoritative Information',
  204: 'No Content',
  205: 'Reset Content',
  206: 'Partial Content',
  300: 'Multiple Choices',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  304: 'Not Modified',
  305: 'Use Proxy',
  307: 'Temporary Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  402: 'Payment Required',
  403: 'Forbidden',
  404: 'Not Found',
  405: 'Method Not Allowed',
  406: 'Not Acceptable',
  407: 'Proxy Authentication Required',
  408: 'Request Timeout',
  409: 'Conflict',
  410: 'Gone',
  411: 'Length Required',
  412: 'Precondition Failed',
  413: 'Payload Too Large',
  414: 'URI Too Long',
  415: 'Unsupported Media Type',
  416: 'Range Not Satisfiable',
  417: 'Expectation Failed',
  426: 'Upgrade Required',
  500: 'Internal Server Error',
  501: 'Not Implemented',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
  505: 'HTTP Version Not Supported'
}

def load_config():
  config = configparser.ConfigParser()
  config.read(config_file)

  return (
    config['server']['host'],
    config['server'].getint('port'),
    config['server']['server_cert'],
    config['server']['server_key']
    )


def deal_with_client(ssl_socket):
    data = ssl_socket.recv()
    # null data means the client is finished with us
    while data:
        if not reply_client(ssl_socket, data):
            # finished with client
            break
        data = ssl_socket.recv()


def reply_client(conn, client_data):
    encoding = 'utf-8'
    
    logger.info('request from client:\n%s' % (str(client_data, encoding),))

    with open(r'data/response.json') as data_file:
      data = json.load(data_file)

    status = data['status']
    body = data['body']
    header = [
      'HTTP/1.1 {0} {1}'.format(status, HTTP_STATUS[status])
    ]

    header = header + data['header']

    response = '\n'.join(header) + '\r\n\r\n' + json.dumps(body)

    conn.sendall(response.encode(encoding))


def start_server(args):

  HOST, PORT, server_cert, server_key = load_config()
  logger.debug(
    'config loaded, host: %s, port: %d, cert: %s, key: %s' %
    (HOST, PORT, server_cert, server_key) )

  ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

  if args.ssl3_0:
    logger.info('insecure SSLv3.0 enabled.')
    ssl_ctx.options &= ~ssl.OP_NO_SSLv3

  if args.max_version:
    logger.info('set the highest supported tls version to: ' + args.max_version)
    ssl_ctx.maximum_version = VERSION_MAP[args.max_version]

  if args.min_version:
    logger.info('set the lowest supported tls version to: ' + args.min_version)
    ssl_ctx.minimun_version = VERSION_MAP[args.min_version]

  if args.ciphers:
    logger.info('set ciphers list: %s', args.ciphers)
    ssl_ctx.set_ciphers(args.ciphers)

  ssl_ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)

  bindsocket = socket.socket()

  bindsocket.bind((HOST, PORT))
  logger.info('bound to: %s:%d' % (HOST, PORT))

  bindsocket.listen(5)
  logger.info('listening on: %s:%d' % (HOST, PORT))

  cipher_tuples = ssl_ctx.get_ciphers()
  cipher_names = [c['name'] for c in cipher_tuples]
  versions = [c['protocol'] for c in cipher_tuples]

  logger.debug('versions enabled: %s', ', '.join(set(versions)))
  logger.debug('ciphers enabled: %s', ':'.join(cipher_names))

  while True:
    logger.info('waiting for incoming connection...')
    incoming_socket, fromaddr = bindsocket.accept()
    logger.info('accepted client tcp socket: %s:%d' % fromaddr)

    try:
      ssl_socket = ssl_ctx.wrap_socket(incoming_socket, server_side=True)
    except ssl.SSLError as ssl_err:
      logger.error('SSL connection failed: %s', str(ssl_err))
      ssl_socket.close()
      continue
    except Exception as e:
      logger.error('connection failed due to unknown error, %s: %s', type(e), str(e))
      continue 

    logger.info('ssl handshake done with client %s:%d' % fromaddr)
    logger.info('cipher: %s, version: %s' % ssl_socket.cipher()[:2])

    try:
      deal_with_client(ssl_socket)
    except Exception as err:
      logger.error( '{0}: {1}'.format(type(err), str(err)) )
    finally:
      try:
        ssl_socket.shutdown(socket.SHUT_RDWR)
      except Exception as e:
        logger.error( 'ssl teardown error, {0}: {1}'.format(type(e), str(e)) )
      ssl_socket.close()


if __name__ == '__main__':

  config_file = r'server.conf'

  # Default setting for logging.
  log_level = logging.INFO
  FORMAT = '%(asctime)-15s [%(name)-12s] %(levelname)-8s %(message)s'
  logging.basicConfig(level=log_level, format=FORMAT)
  logger = logging.getLogger(sys.argv[0])

  parser = argparse.ArgumentParser(prefix_chars='-+', \
    formatter_class=argparse.RawTextHelpFormatter, \
    description='Description:\n\tssl/tls server for tests. (EXANTNG)')
    
  parser.add_argument(
    '-d', '--debug', action='store_true', help='Enable debug mode.')
  parser.add_argument(
    '--enable-ssl3.0', action='store_true', dest='ssl3_0', help='Enable SSLv3.0.')
  parser.add_argument(
    '-M', '--max-version', action='store', metavar='<version>',
    choices=['tls1.3', 'tls1.2', 'tls1.1', 'tls1.0'],
    help='Set the highest supported TLS version.\nAvailable values: tls1.3, tls1.2, tls1.1, tls1.0')
  parser.add_argument(
    '-m', '--min-version', action='store', metavar='<version>',
    choices=['tls1.3', 'tls1.2', 'tls1.1', 'tls1.0'],
    help='Set the lowest supported TLS version.\nAvailable values: tls1.3, tls1.2, tls1.1, tls1.0')
  parser.add_argument(
    '-c', '--ciphers',
    action='store', metavar='<ciphers>',
    help='String in the OpenSSL cipher list format,\nNote: OpenSSL default TLS 1.3 ciphers will be always enabled.')

  args = parser.parse_args()

  if args.debug == True:
    logger.setLevel(logging.DEBUG)
    logger.debug('debug mode enabled.')

  start_server(args)
