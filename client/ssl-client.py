
import argparse
import configparser
import logging
import json
import ssl
import socket
import pprint
import sys

def build_request(args, config):
  encoding = config['content']['encoding']
  path = '/entitlement'

  server_host = args.host

  header = [
    'POST %s HTTP/1.1' % (path,),
    'Host: %s' % (server_host,),
    'Charset: %s' % (encoding,)
  ]

  with open(r'data/ue-request.json') as data_file:
    data = json.load(data_file)

  body = data['body']
  header = header + data['header']
  request = '\n'.join(header) + '\r\n\r\n' + json.dumps(body)

  return request.encode(encoding)

def parse_ssl_options(args):
  options = 0

  if args.tls1_0:
    logger.info('set to TLSv1.0 only')
    options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3)
  if args.tls1_1:
    logger.info('set to TLSv1.1 only')
    options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3)
  if args.tls1_2:
    logger.info('set to TLSv1.2 only')
    options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3)
  if args.tls1_3:
    logger.info('set to TLSv1.3 only')
    options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
  if args.ssl2_0:
    logger.info('set to SSLv2.0 only')
    options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3)
  if args.ssl3_0:
    logger.info('set to SSLv3.0 only')
    options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3)

  return options

def get_ssl_ctx(args):
  options = parse_ssl_options(args)

  ca_cert = config['client']['ca_cert']

  context = ssl.SSLContext(ssl.PROTOCOL_TLS)
  context.verify_mode = ssl.CERT_REQUIRED
  context.check_hostname = True
  context.load_verify_locations(ca_cert)

  context.options |= options

  if args.ciphers:
    logger.info('set client ciphers: %s', args.ciphers)
    context.set_ciphers(args.ciphers)

  return context

def connect_server(args, config):

  server_host = args.host
  server_port = args.port

  ssl_ctx = get_ssl_ctx(args)
  
  conn = ssl_ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server_host, do_handshake_on_connect=False)
  logger.debug('check_hostname: %s' % (str(ssl_ctx.check_hostname),))

  try:
    conn.connect((server_host, server_port))
    logger.info('tcp connected to %s:%d successfully.' % (server_host, server_port))
    conn.do_handshake()
  except ssl.CertificateError as ce:
    logger.error('ssl certificate error:', ce)
    sys.exit()
  except Exception as e:
    logger.error('Unexpected error:')
    print(sys.exc_info()[0])
    print(e)
    sys.exit()
  
  logger.info('SSL handshark succeed with server %s:%d' % (server_host, server_port))
  logger.info('cipher: %s, version: %s, number of secret bits: %d' % conn.cipher())
  
  cert = conn.getpeercert()
  logger.debug('server certificate recieved: ' + json.dumps(cert))

  return conn

def start_client(args, config):
  encoding = config['content']['encoding']

  conn = connect_server(args, config)
  
  logger.debug('sending request')
  conn.sendall(build_request(args, config))
  logger.debug('request sent')
  
  data = conn.recv()
  logger.info('response from server:\n%s' % (str(data, encoding),))
  logger.debug('all finished.')

  conn.shutdown(socket.SHUT_RDWR)
  conn.close()


if __name__ == '__main__':
  CONFIG_FILE = r'client.conf'
  # Default setting for logging.
  log_level = logging.INFO
  FORMAT = '%(asctime)-15s [%(name)-12s] %(levelname)-8s %(message)s'
  logging.basicConfig(level=log_level, format=FORMAT)
  logger = logging.getLogger(sys.argv[0])

  parser = argparse.ArgumentParser(prefix_chars='-+', \
    formatter_class=argparse.RawTextHelpFormatter, \
    description='Description:\n\tssl/tls client for tests. (EXANTNG)')
    
  parser.add_argument(
    '-d', '--debug', action='store_true', help='enable debug mode.')
  parser.add_argument(
    '-H', '--host', action='store', required=True, help='Specify the server host.')
  parser.add_argument(
    '-p', '--port', action='store', required=True, type=int, help='Specify the server port.')
  parser.add_argument(
    '-c', '--ciphers',
    action='store', metavar='<ciphers>',
    help='String in the OpenSSL cipher list format')
  
  group = parser.add_mutually_exclusive_group()
  group.add_argument('-0', '--tls1.0', action='store_true', dest='tls1_0', help='use TLSv1.1 only.')
  group.add_argument('-1', '--tls1.1', action='store_true', dest='tls1_1', help='use TLSv1.1 only.')
  group.add_argument('-2', '--tls1.2', action='store_true', dest='tls1_2', help='use TLSv1.2 only.')
  group.add_argument('-3', '--tls1.3', action='store_true', dest='tls1_3', help='use TLSv1.3 only.')
  group.add_argument('-s2', '--ssl2.0', action='store_true', dest='ssl2_0', help='use SSLv2.0 only.')
  group.add_argument('-s3', '--ssl3.0', action='store_true', dest='ssl3_0', help='use SSLv3.0 only.')

  args = parser.parse_args()

  if args.debug == True:
    logger.setLevel(logging.DEBUG)
    logger.debug('Debug mode enabled.')

  config = configparser.ConfigParser()
  config.read(CONFIG_FILE)

  start_client(args, config)
