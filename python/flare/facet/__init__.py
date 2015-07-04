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

################################################################################

class RejectionException(Exception):
    pass
################################################################################
class Launcher(object):
    def __init__(self):
        self.logger = jayutils.getLogger('facet.Launcher')

    #def runMarkupFunction(self):
    #    self.runDialog('new')

    #def runMarkupVtable(self):
    #    #runner = vfunc_markup.VfuncMarkupRunner()
    #    #runner.run()

    #def runBrowseClasses(self):
    #    self.logger.info('runBrowseClasses: Not yet implemented')

    def runDialog(self, tabName):
        try:
            self.logger.debug('Trying to run %s dialog now', tabName)
            filePath = jayutils.getInputFilepath()
            if filePath is None:
                self.logger.info('No input file provided. Stopping')
                return
            vw = jayutils.loadWorkspace(filePath)
            objStuff = analysis.FacetObjectAnalyzer(vw)
            dlg = idaui.FacetMainDialog(objStuff)
            dlg.setActiveTab(tabName)
            oldTo = idaapi.set_script_timeout(0)
            res = dlg.exec_()
            idaapi.set_script_timeout(oldTo)
            if res == QtGui.QDialog.DialogCode.Accepted:
                self.logger.debug('Dialog result: accepted')
                objStuff.runAnalysis()
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
        raise RuntimeError('runForm not supported')
        #try:
        #    #run as an IDA form
        #    plg = MyPluginFormClass()
        #    plg.Show("ClassStuff")
        #except Exception, err:
        #    self.logger.exception('Error in runForm: %s', str(err))


################################################################################
def runCreateStruct():
    launcher =  Launcher()
    launcher.runDialog('new')

def runMarkupExistingStruct():
    launcher =  Launcher()
    launcher.runDialog('existing')

def runMarkupVtable():
    launcher =  Launcher()
    launcher.runDialog('vfunc')

def runBrowseClasses():
    launcher =  Launcher()
    launcher.runDialog('relations')

def runBrowseHelp():
    launcher =  Launcher()
    launcher.runDialog('help')

#if __name__ == '__main__':
#    logger = jayutils.configLogger('', logging.DEBUG)
#    #runStuff(True)
#    runStuff(False)
