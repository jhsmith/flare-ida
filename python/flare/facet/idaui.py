
from PySide import QtGui, QtCore

import idc
import idaapi
import idautils
from idaapi import PluginForm

from . import facet_ui

import flare.jayutils as jayutils

################################################################################

class ClassGuiWidget(QtGui.QWidget):
    def __init__(self, parent=None, idaform=None, data=None, objStuff=None):
        QtGui.QWidget.__init__(self, parent)
        self.logger = jayutils.getLogger('facet.ClassGuiWidget')
        try:
            self.ui = facet_ui.Ui_facetui()
            self.ui.setupUi(self)
            self.idaform = idaform
            self.objStuff = objStuff

            #initialize stuff
            self.objStuff.updateStateFromDisplay()
            self.setFields()
            self.updateFields()

            self.ui.combo_objPtrReg.setCurrentIndex(self.objStuff.selectedRegIdx)
            self.setFocusPolicy(QtCore.Qt.StrongFocus)

            #connect stuf here
            self.ui.pb_cancel.clicked.connect(self.onRejected)
            self.ui.pb_run.clicked.connect(self.onAccepted)
            self.ui.cb_filterUserClass.clicked.connect(self.onFilterUserClassClicked)

        except Exception, err:
            self.logger.exception('Error during init: %s', str(err))

    accepted = QtCore.Signal()  
    rejected = QtCore.Signal()

    def updateFields(self):
        '''Used to update display fields with updated values that may change'''
        self.ui.line_funcStart.setText('0x%08x' % self.objStuff.funcStart)
        self.ui.line_startLocation.setText('0x%08x' % self.objStuff.currentAddress)
        self.ui.line_delta.setText('0x%02x' % self.objStuff.pointerDelta)
        self.ui.combo_existingClasses.clear()
        self.ui.combo_existingClasses.addItems(self.objStuff.userStructs)
        self.ui.line_className.setText(self.objStuff.defaultNewStructName)

    def setFields(self):
        '''Used to init display field'''
        self.ui.combo_objPtrReg.addItems(self.objStuff.registers)
        self.ui.cb_filterUserClass.setChecked(self.objStuff.filterUserClass)
        self.ui.cb_createVtable.setChecked(self.objStuff.createVtable)
        self.ui.cb_modifyExisting.setChecked(self.objStuff.modifyExisting)
        self.ui.line_className.setText(self.objStuff.defaultNewStructName)

    def storeState(self):
        #grab the state of the gui & store in the objStuff container
        self.objStuff.useExisting = self.ui.rb_existingClass.isChecked()
        self.objStuff.createNew = self.ui.rb_newClass.isChecked()
        self.objStuff.filterUserClass = self.ui.cb_filterUserClass.isChecked()
        self.objStuff.createVtable = self.ui.cb_createVtable.isChecked()
        self.objStuff.modifyExisting = self.ui.cb_modifyExisting.isChecked()
        self.objStuff.useFunctionStart = self.ui.rb_funcStart.isChecked()
        self.objStuff.useCurrentAddress = self.ui.rb_startLocation.isChecked()
        self.objStuff.selectedRegIdx = self.ui.combo_objPtrReg.currentIndex()
        self.objStuff.existingStructName = str(self.ui.combo_existingClasses.currentText())

        ########################################
        if (self.ui.line_className.text() is not None) and len(self.ui.line_className.text()) > 0:
            self.objStuff.newStructName = str(self.ui.line_className.text())
        else:
            #orange TODO: raise error message
            pass
        ########################################
        if (self.ui.line_startLocation.text() is not None) and len(self.ui.line_startLocation.text()) > 0:
            try:
                self.objStuff.currentAddress = int(self.ui.line_startLocation.text(), 0)
            except:
                self.ui.line_startLocation.setText('0x%08x' % self.objStuff.currentAddress)
                pass
        elif self.objStuff.useCurrentAddress:
            #orange TODO: raise error message
            pass

        ########################################
        if (self.ui.line_objectSize.text() is not None) and len(self.ui.line_objectSize.text()) > 0:
            try:
                self.objStuff.structSize = int(self.ui.line_objectSize.text(), 0)
            except:
                self.objStuff.structSize = 0
                self.ui.line_objectSize.setText('0x00', )
        else:
            self.objStuff.structSize = 0
        ########################################
        if (self.ui.line_delta.text() is not None) and len(self.ui.line_delta.text()) > 0:
            try:
                self.objStuff.pointerDelta = int(self.ui.line_delta.text(), 0)
            except:
                self.objStuff.pointerDelta = 0
                self.ui.line_delta.setText('0x%02x' % self.objStuff.pointerDelta)
        else:
            self.objStuff.pointerDelta = 0

    def onFilterUserClassClicked(self):
        try:
            self.ui.combo_existingClasses.clear()
            if self.ui.cb_filterUserClass.isChecked():
                self.ui.combo_existingClasses.addItems(self.objStuff.userStructs)
            else:
                self.ui.combo_existingClasses.addItems(self.objStuff.existingStructNames)
        except Exception, err:
            self.logger.exception('Error in onFilterUserClassClicked: %s', str(err))

    def onAccepted(self):
        try:
            self.logger.info('Accepted!')
            self.storeState()
            if self.idaform is not None:
                #HACK TODO: only run the function if in an IDA form....
                self.objStuff.runFunction()
            self.accepted.emit()  
        except Exception, err:
            self.logger.exception('Error in onAccepted: %s', str(err))

    def onRejected(self):
        try:
            self.logger.info('Rejected!')
            if self.idaform is not None:
                #HACK TODO: only run the function if in an IDA form....
                self.doClose()
            self.rejected.emit()
        except Exception, err:
            self.logger.exception('Error in onRejected: %s', str(err))

    def doClose(self):
        doneFailed = False
        if self.idaForm is None:
            return
        try:
            self.idaform.Close(0) 
            self.logger.debug('Top level close worked')
        except Exception, err:
            doneFailed = True
            self.logger.debug('Top level close failed')
            #self.logger.exception('Error in onRejected: %s', str(err))

        if doneFailed:
            try:
                idaapi._idaapi.plgform_close(self.idaform.__clink__, 0)
                self.logger.debug('Manual close worked')
            except Exception, err:
                self.logger.exception('Error in onRejected 2nd try: %s', str(err))

################################################################################

class MyPluginFormClass(PluginForm):
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        self.logger = jayutils.getLogger('facet.MyPluginFormClass')

        # Get parent widget
        self.logger.debug('Doing OnCreate now')
        self.parent = self.FormToPySideWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        try:
            self.logger.debug('Doing PopulateForm now')
            filePath = jayutils.getInputFilepath()
            if filePath is None:
                self.logger.info('No input file provided. Stopping')
                return
            vw = jayutils.loadWorkspace(filePath)
            layout = QtGui.QVBoxLayout()
            self.objStuff = ObjectBodyStuff(vw)
            self.widg = ClassGuiWidget(idaform=self, objStuff = self.objStuff)
            layout.addWidget(self.widg)
            self.parent.setLayout(layout)
        except Exception, err:
            self.logger.exception('Error populating form: %s', str(err))

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        pass
        self.logger.debug('Doing OnClose now')

################################################################################

class ClassInfoDialog(QtGui.QDialog):
    def __init__(self, objStuff):
        QtGui.QDialog.__init__(self, None)
        self.logger = jayutils.getLogger('facet.ClassInfoDialog')
        try:
            self.objStuff = objStuff
            self.createWidgets()
            self.widg.accepted.connect(self.accept)
            self.widg.rejected.connect(self.reject)

        except Exception, err:
            self.logger.exception('Error in init: %s', str(err))

    def createWidgets(self):
        self.widg = ClassGuiWidget(self, objStuff = self.objStuff)
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.widg)
        self.setLayout(layout)

################################################################################


