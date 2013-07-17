import controllers.module as module

import splunk, splunk.search, splunk.util, splunk.entity
import lib.util as util
import lib.i18n as i18n
import logging


logger = logging.getLogger('splunk.module.CEFlyController')

import math
import re

class cefly_controller(module.ModuleHandler):

    

