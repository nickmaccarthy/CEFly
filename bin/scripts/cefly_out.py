#!/usr/bin/env python
#
#   CEFly output script
#
#   Written by:
#       Nick MacCarthy
#       nickmaccarthy@gmail.com
#
#   Description:
#       Output script to use in your saved search
#
#   How to use:
#       Define your cefly outputs in local/cefly.conf.  
#       Note that Cefly.conf label must match the name/label of the saved search.  
#       Saved search action.script.filename should be this script/file.
#
#

import splunk
import splunk.appserver.mrsparkle.lib.util as app_util
import logging
import logging.handlers as logging_handler
import optparse
import os
import re
import socket
import sys
import time
import csv
import gzip
import random
import hashlib

APPS_DIR = app_util.get_apps_dir()
APP_NAME = 'cefly'
APP_PATH = os.path.join(APPS_DIR, APP_NAME)

#find out cefly.conf in <app>/local
CEFLY_OUTPUTS = os.path.join(APP_PATH, 'local', 'cefly')

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')

# to be safe, we will add the <app>/bin path to syspath so we can import any modules specific to this app
if not os.path.join(APPS_DIR, APP_NAME, 'bin') in sys.path:
   sys.path.append(os.path.join(APPS_DIR, APP_NAME, 'bin'))

import cefly.syslog as syslog
import cefly.logger as logger

def load_conf(app):

    '''
        Loads our cefly.conf and gets the stanza for our app/search we are currently working with
    '''

    try:
        output = splunk.clilib.cli_common.getConfStanza(CEFLY_OUTPUTS, app)
    except Exception, e:
        logger.error('message="Unable to open stanza in cefly.conf for app/search", app="%s"' % app)
        logger.exception(e)

    return output

def make_transid():

    '''
        Sets a 'transaction id' so we can track the entire cefly run as one transaction in the logs.  
    '''
    ip = socket.gethostbyname(socket.gethostname())
    random_num = random.randrange(0, 10000, 5)
    rightnow = time.strftime("%Y-%m-%d %H:%M:%S %Z")

    hash_this = "%s%s%s" % ( rightnow, ip, random_num )
    m = hashlib.sha1( hash_this ).hexdigest()

    return m


def make_cef(data):

    prefix_maps = data['prefix_map']
    custom_maps = data['field_map']
    custom_labels = data['labels']
    splunk_meta = data['splunk_meta']

    cef_prefix = []
    output = []

    cef_prefix.append("CEF:0")

    if not 'd_vendor' in prefix_maps.keys():
       cef_prefix.append("Splunk CEFly")
    else:
       cef_prefix.append(str(prefix_maps['d_vendor']))

    if not 'd_product' in prefix_maps.keys():
       cef_prefix.append(splunk_meta['sourcetype'])
    else:
       cef_prefix.append(str(prefix_maps['d_product']))

    if not 'd_version' in prefix_maps:
       cef_prefix.append("1.0")
    else:
       cef_prefix.append(str(prefix_maps['d_version']))

    if not 'sig_id' in prefix_maps.keys():
       cef_prefix.append("100000")
    else:
       cef_prefix.append(prefix_maps['sig_id'])

    if not 'name' in prefix_maps:
        cef_prefix.append("generic event -- address me ASAP")
    else:
        cef_prefix.append(str(prefix_maps['name']))

    if not 'severity' in prefix_maps:
        cef_prefix.append('5')
    else:
        cef_prefix.append( ("%s %s") % (prefix_maps['severity'], "|") )

    ''' 
        map our custom CEF static maps - 
        
        format: <splunk_field>:CEF_field, <another_splunk_field>:another_CEF_field
        
        example: outcome:/Success, _time:end, host:src

    '''
    my_s_maps = []
    for k,v in cef_static_map.iteritems():
        my_s_maps.append( ( "%s=%s " ) % (k,v) )


    '''
        map our Custom String Labels
        
        format: <cef_field>:<string>, <cef_field>:<string>
        
        example: cslabel1:some_custom_string, cslabel2:some other string 

    '''
    my_cs_maps = []
    for k,v in custom_labels.iteritems():
        my_cs_maps.append( ( "%s=%s " ) % ( k,v ) )

    # map our custom cef fields
    my_data = []
    for item in custom_maps:

        if item['data']:
            my_data.append( ( "%s=%s ") % ( item['as_cef_field'], escape_cef_chars(item['data']) ) )

    # for debugging
    if not my_data:
        logger.error( 'message="not everything is here", custom_maps="%s", my_s_maps="%s", my_cs_maps="%s"' % ( custom_maps, my_s_maps, my_cs_maps ) )

        #  If we were not able to map our custom CEF fields, then there was an issue
        return False

    try:
        cef_msg = "|".join(cef_prefix) + " ".join(my_cs_maps) + " ".join(my_s_maps) + " ".join(my_data)
    except Exception, e:
        logger.error('message="Unable to create CEF message", cef_prefix="%s", cs_maps="%s", s_maps="%s", my_data="%s"' % ( cef_prefix, my_cs_maps, my_s_maps, my_data ))

    return cef_msg

def escape_cef_chars(text):

    '''
        escapes those special chars we cannot have in CEF messages
    '''
    escape_these = '\=\n\r'

    for char in escape_these:
        text = text.replace( char, '\\' + char)
    return text


## Lets get the party started!
if __name__ == "__main__":

    logging = logger.logger()
    logger = logging.get_logger('cefly')

    logger.info('message=CEFly initialized')
    try:
        parser = optparse.OptionParser()
        (OPTIONS, ARGS) = parser.parse_args()
        search_name = ARGS[3]
        search_results = ARGS[7]
    except Exception, e:
        logger.error("Unable to arguments for search_name and search result location: %s" % (e) )

    try:

        output = load_conf(search_name)
        output_host = output['output_host']
        output_port = int(output['output_port'].strip())
        output_protocol = output['output_protocol']
        device_vendor = output['device_vendor']
        device_product = output['device_product']
        device_version = output['device_version']
        signature_id = output['signature_id']
        name = output['name']
        severity = output['severity']

        cef_prefix_map = { "d_vendor":device_vendor, "d_product":device_product, "d_version":device_version, "sig_id":signature_id, "name":name, "severity":severity }

        cef_static_map = dict((p.strip().split(':') for p  in output['cef_static_map'].split(',')))
        cef_custom_labels = dict((p.strip().split(':') for p in output['cef_custom_labels'].split(',')))
        cef_field_map = dict((p.strip().split(':') for p in output['cef_field_map'].split(',')))

        logger.info('message="config loaded", app_name="%s", config="%s"' % ( search_name, output ))

    except Exception, e:
        logger.error('message="Unable to load stanzas cefly.conf" exception=%s, cefly_config="%s"' % (e, output) )
        logger.exception(e)

    
    # sets for cef maps for intersection later  (sets hash and intersect faster than stright dicts)
    cef_static_set = set(cef_static_map)
    cef_label_set = set(cef_custom_labels)
    cef_field_set = set(cef_field_map)

    # set up our syslog class
    try:
        syslog = syslog.syslog( output_protocol, output_host, output_port, 5, 8, logger )
    except Exception, e:
        logger.error('message="Unable to init syslog class" reason="%s"' % ( e ) )
        logger.exception(e)

    # open our results.csv for the alert
    try:
        reader = csv.DictReader(gzip.open(search_results, "rb"))   
    except Exception, e:
        logger.error('message="Unable to open results.csv.gz for reading" csv_location="%s", exception="%s"' % ( search_results, e ))


    # loop through the results, map our cef fields from cefly.conf, and CEF out each message via syslog to our destination server

    result_count = 0 
    no_count = 0

    for row in reader:

        our_map = []
        row_keys = row.keys()
        myset = set(row)
        splunk_meta = {"sourcetype":row['sourcetype'], "index":row['index'], "source":row['source'], "splunk_server":row['splunk_server']}

        # intersect our cef_field_map and our current row in the Splunk CSV results and turn it into a set
        intersection = set.intersection(cef_field_set, myset)

        # If we were not able to make an intersection, then lets skip to the next log so we dont spam our destination
        # with empty custom_maps, and device_custom maps
        if not intersection:
            no_count = no_count + 1
            continue

        # Get your map on 
        for item in intersection:
            our_map.append( { "splunk_field":item, "as_cef_field":cef_field_map[item], "data":row[item] } )

        all_mapped = { "prefix_map":cef_prefix_map, "static_maps":cef_static_map, "labels":cef_custom_labels, "field_map":our_map, 'splunk_meta':splunk_meta }

        # Lets make our CEF msg 
        cef_msg = make_cef(all_mapped)

        # Now lets send via syslog to our destination
        try:

            try:
                if output['debug']:
                    logger.info('message=cefly_event format=CEF, CEF="%s"' % ( cef_msg ))
            except:
                pass

            sent_events = syslog.send(cef_msg)
        except Exception, e:
            logger.error('message="Unable to send CEF message via syslog" app="%s" destination_server="%s" destination_port="%s", destination_protocol="%s" reason="%s"' % ( search_name, output_host, output_port, output_protocol, e ))   
            logger.exception(e)

        result_count = result_count + 1

    # log our metrics
    if sent_events:
        logger.info('cefly_metrics events_sent=%s no_intersection=%s cefly_app="%s" device_vendor="%s" device_product="%s" cef_name="%s" destination_server="%s" destination_port="%s" destination_protocol="%s"' % ( result_count, no_count, search_name, device_vendor, device_product, name, output_host, output_port, output_protocol) )
    else: 
        logger.info('cefly_metrics events_sent=%s no_intersection=%s cefly_app="%s" device_vendor="%s" device_product="%s" cef_name="%s" destination_server="%s" destination_port="%s" destination_protocol="%s"' % ( result_count, no_count, search_name, device_vendor, device_product, name, output_host, output_port, output_protocol) )
        sys.exit(0)
