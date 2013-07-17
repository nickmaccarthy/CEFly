import socket
import splunk
import splunk.appserver.mrsparkle.lib.util as app_util
import os, sys

APPS_DIR = app_util.get_apps_dir()
APP_NAME = 'cefly'
APP_PATH = os.path.join(APPS_DIR, APP_NAME)

if not os.path.join(APPS_DIR, APP_NAME, 'bin') in sys.path:
   sys.path.append(os.path.join(APPS_DIR, APP_NAME, 'bin'))

import cefly.logger as logger 

class syslog(object):
    
    def __init__(self, proto='tcp', host='localhost', port=514, level=5, facility=8, log_instance=''):

        self.proto = proto
        self.host = host
        self.port = int( port )
        self.level = int( level )
        self.facility = int( facility )

        self.bytes_sent = 0

        if not log_instance:
            self.logging = logger.logger()
            self.logger = self.logging.get_logger(self.__class__.__name__)
        else:
            self.logger = log_instance


        if proto == 'tcp':
            self.setup_tcp()
            self.logger.info('message="opened TCP connection" destination_host="%s" destination_port="%s" proto="%s"' % ( self.host, self.port, proto ) )
        elif proto == 'udp':
            self.setup_udp()
            self.logger.info('message="opened UDP connection" destination_host="%s" destination_port="%s proto="%s"' % ( self.host, self.port, proto ) )
        else:
            self.setup_udp()
            self.logger.info('message="opened UDP connection" destination_host="%s" destination_port="%s proto="%s""' % ( self.host, self.port, 'udp' ) )

    def setup_tcp(self):
    
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.connect ( ( self.host, self.port) )

    def setup_udp(self):
        
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )


    def close_connection(self):
        
        self.socket.close()

    def send(self, message):
        
        # formats our syslog message
        data = "<%d> %s" % ( self.level + self.facility*8, message )

        if self.proto == 'tcp':
            sent = self.socket.send(data + '\n')
        elif self.proto == 'udp':
            sent = self.socket.sendto( data, ( self.host, self.port) )
            self.socket.close()

        self.bytes_sent = self.bytes_sent + sent

        return True
       
    def __del__(self):
   
        self.logger.info('message="connection closed" bytes_sent=%s destination_host="%s" destination_port="%s"' % ( self.bytes_sent, self.host, self.port )) 
        self.close_connection()  
