#!/usr/bin/env python
# Jay Smith
# jay.smith@mandiant.com
# 
########################################################################
# Copyright 2012 Mandiant
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
########################################################################
#
# 
#
########################################################################

import struct
import logging
import os.path
import binascii
import warnings

import idc
import idaapi
import idautils

from PySide import QtCore, QtGui

import flare.jayutils as jayutils

from . import idaui
from . import analysis
from . import vfunc_markup

class RejectionException(Exception):
    pass
################################################################################
class Launcher(object):
    def __init__(self):
        self.logger = jayutils.getLogger('facet.Launcher')

    def runMarkupFunction(self, doDialog=False):
        if doDialog:
            self.runDialog()
        else:
            self.runForm()

    def runMarkupVtable(self, doDialog=False):
        runner = vfunc_markup.VfuncMarkupRunner()
        runner.run()

    def runBrowseClasses(self, doDialog=False):
        self.logger.info('runBrowseClasses: Not yet implemented')

    def runDialog(self):
        try:
            self.logger.debug('Trying to run dialog now')
            filePath = jayutils.getInputFilepath()
            if filePath is None:
                self.logger.info('No input file provided. Stopping')
                return
            vw = jayutils.loadWorkspace(filePath)
            objStuff = analysis.FacetObjectAnalyzer(vw)
            dlg = idaui.ClassInfoDialog(objStuff)
            oldTo = idaapi.set_script_timeout(0)
            res = dlg.exec_()
            idaapi.set_script_timeout(oldTo)
            if res == QtGui.QDialog.DialogCode.Accepted:
                self.logger.debug('Dialog result: accepted')
                objStuff.runFunction()
            elif res == QtGui.QDialog.DialogCode.Rejected:
                self.logger.debug('Dialog result: rejected')
                raise RejectionException()
            else:
                self.logger.debug('Unknown result')
                raise RuntimeError('Dialog unknown result')
        except RejectionException, err:
            self.logger.debug('User canceled. Stopping')
        except Exception, err:
            self.logger.exception('Error in runDialog: %s', str(err))

    def runForm(self):
        try:
            #run as an IDA form
            plg = MyPluginFormClass()
            plg.Show("ClassStuff")
        except Exception, err:
            self.logger.exception('Error in runForm: %s', str(err))


################################################################################

def runMarkupFunction(doDialog=False):
    launcher =  Launcher()
    launcher.runMarkupFunction(doDialog)

def runMarkupVtable(doDialog=False):
    launcher =  Launcher()
    launcher.runMarkupVtable(doDialog)

def runBrowseClasses(doDialog=False):
    launcher =  Launcher()
    launcher.runBrowseClasses(doDialog)

#if __name__ == '__main__':
#    logger = jayutils.configLogger('', logging.DEBUG)
#    #runStuff(True)
#    runStuff(False)
