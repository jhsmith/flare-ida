
from PySide import QtGui, QtCore

#import idc
#import idaapi
#import idautils
#from idaapi import PluginForm

from . import facet_ui

import flare.jayutils as jayutils

################################################################################
#map action ID to tab object name
TAB_MAP = {
    'new'       : 'newClassTab',
    'existing'  : 'existingClassTab',
    'vfunc'     : 'vfuncMarkupTab',
    'relations' : 'relationshipsTab',
    'help'      : 'helpTab',
}
INV_TAB_MAP = {}
for k,v in TAB_MAP.items():
    INV_TAB_MAP[v] = k

################################################################################
g_HelpHtml = '''
<html>
<body>
<h1>Help!</h1>
<p>TODO!!!</p>
</body>
</html>
'''


################################################################################
class FacetUiWidget(QtGui.QWidget):
    def __init__(self, parent=None, data=None, objStuff=None):
        QtGui.QWidget.__init__(self, parent)
        self.logger = jayutils.getLogger('facet.FacetUiWidget')

        try:
            self.ui = facet_ui.Ui_facetWidget()
            self.ui.setupUi(self)
            self.objStuff = objStuff

            #initialize stuff
            self.objStuff.updateStateFromDisplay()
            self.loadState()
            #self.installEventFilter(self)
            #self.ui.line_className.installEventFilter(self)

            #self.ui.combo_objPtrReg.setCurrentIndex(self.objStuff.selectedRegIdx)
            #self.setFocusPolicy(QtCore.Qt.StrongFocus)

            #connect stuff
            self.ui.buttonBox.accepted.connect(self.onAccepted)
            self.ui.buttonBox.rejected.connect(self.onRejected)
            self.ui.existing_cbFilterFacetClasses.stateChanged.connect(self.onFilterFacetStructsChanged)

        except Exception, err:
            self.logger.exception('Error during init: %s', str(err))

    accepted = QtCore.Signal()  
    rejected = QtCore.Signal()

    def loadState(self):
        '''Used to update display fields with updated values that may change'''
        self.ui.new_pointerDeltaLineEdit.setText('0x%02x' % self.objStuff.pointerDelta)
        self.ui.existing_pointerDeltaLineEdit.setText('0x%02x' % self.objStuff.pointerDelta)

        self.ui.existing_nameComboBox.clear()
        self.ui.existing_nameComboBox.addItems(self.objStuff.existingStructNames)

        self.ui.existing_sizeLineEdit.setEnabled(False)
        self.ui.existing_parentLineEdit.setEnabled(False)

        self.ui.new_parentComboBox.clear()
        self.ui.new_parentComboBox.addItems(self.objStuff.validParents)

        self.ui.new_nameLineEdit.setText(self.objStuff.defaultNewStructName)

        self.ui.new_pointerComboBox.addItems(self.objStuff.registers)
        self.ui.existing_pointerComboBox.addItems(self.objStuff.registers)

        self.ui.new_pointerComboBox.setCurrentIndex(self.objStuff.registers.index(self.objStuff.selectedReg))
        self.ui.existing_pointerComboBox.setCurrentIndex(self.objStuff.registers.index(self.objStuff.selectedReg))

        self.ui.new_locationLineEdit.setText('0x%08x' % self.objStuff.currentAddress)
        self.ui.existing_locationLineEdit.setText('0x%08x' % self.objStuff.currentAddress)

        if self.objStuff.funcStart:
            self.ui.new_funcStartLineEdit.setText('0x%08x' % self.objStuff.funcStart)
            self.ui.existing_funcStartLineEdit.setText('0x%08x' % self.objStuff.funcStart)
        else:
            #we're not in a function, so disable start of function stuff
            self.ui.new_funcStartLineEdit.setEnabled(False)
            self.ui.new_funcStartRButton.setEnabled(False)
            self.ui.existing_funcStartLineEdit.setEnabled(False)
            self.ui.existing_funcStartRButton.setEnabled(False)
            
        self.ui.existing_cbFilterFacetClasses.setCheckState(QtCore.Qt.CheckState.Checked)
        self.ui.existing_cbAssociateFunction.setCheckState(QtCore.Qt.CheckState.Checked)

        self.loadVfuncValues()
        self.ui.relations_nameComboBox.addItems(self.objStuff.userStructs)

        self.ui.help_textBrowser.setHtml(g_HelpHtml)
        #orange TODO: left off here

        #self.ui.line_startLocation.setText('0x%08x' % self.objStuff.currentAddress)
        #self.ui.line_delta.setText('0x%02x' % self.objStuff.pointerDelta)
        #self.ui.combo_existingClasses.clear()
        #self.ui.combo_existingClasses.addItems(self.objStuff.userStructs)
        #self.ui.line_className.setText(self.objStuff.defaultNewStructName)
    def loadVfuncValues(self):
        self.logger.info('TODO: implement loadVfuncValues')

    def onAccepted(self):
        try:
            self.logger.info('Accepted!')
            self.storeState()
            self.accepted.emit()  
        except Exception, err:
            self.logger.exception('Error in onAccepted: %s', str(err))

    def onRejected(self):
        try:
            self.logger.info('Rejected!')
            self.rejected.emit()
        except Exception, err:
            self.logger.exception('Error in onRejected: %s', str(err))

    def onFilterFacetStructsChanged(self, state):
        if state == QtCore.Qt.CheckState.Checked:
            self.logger.debug('Hide non-FACET structs changed: checked')
        else:
            self.logger.debug('Hide non-FACET structs changed: not checked')

    #def setDefaultFieldValues(self):
    #    '''Used to init display field'''
    #    self.ui.combo_objPtrReg.addItems(self.objStuff.registers)
    #    self.ui.cb_filterUserClass.setChecked(self.objStuff.filterUserClass)
    #    self.ui.cb_createVtable.setChecked(self.objStuff.createVtable)
    #    self.ui.cb_modifyExisting.setChecked(self.objStuff.modifyExisting)
    #    self.ui.line_className.setText(self.objStuff.defaultNewStructName)

    def getCurrentTab(self):
        currTab = self.ui.tabWidget.currentWidget()
        if currTab is None:
            raise RuntimeError('tabWidget.currentWidget() is None')
        tabName = currTab.objectName()
        actionName = INV_TAB_MAP.get(tabName)
        if actionName is None:
            raise RuntimeError('Could not map active tab to action name')
        return actionName

    def storeState(self):
        actionName = self.getCurrentTab()
        self.logger.info('Store state: %s', actionName)

        self.objStuff.action = actionName
        ################################################################################
        if actionName == 'new':
            if (self.ui.new_nameLineEdit.text() is not None) and len(self.ui.new_nameLineEdit.text()) > 0:
                self.objStuff.newStructName = str(self.ui.new_nameLineEdit.text())
                self.logger.debug('Using new: %s', self.objStuff.newStructName)
            else:
                raise RuntimeError('Empty class name not allowed')
            ########################################
            if (self.ui.new_sizeLineEdit.text() is not None) and len(self.ui.new_sizeLineEdit.text()) > 0:
                try:
                    self.objStuff.structSize = int(self.ui.new_sizeLineEdit.text(), 0)
                except:
                    self.objStuff.structSize = 0
            else:
                self.objStuff.structSize = 0
            ########################################
            if len(self.objStuff.validParents) > 0 :
                parentIdx = self.ui.new_parentComboBox.currentIndex()
                parentName = self.objStuff.validParents[parentIdx]
                if len(parentName) != 0:
                    self.newStructParentName = parentName
            ########################################
            self.objStuff.selectedReg = str(self.ui.new_pointerComboBox.currentText())
            ########################################
            if (self.ui.new_pointerDeltaLineEdit.text() is not None) and len(self.ui.new_pointerDeltaLineEdit.text()) > 0:
                try:
                    self.objStuff.pointerDelta = int(self.ui.new_pointerDeltaLineEdit.text(), 0)
                except:
                    self.objStuff.pointerDelta = 0
            else:
                self.objStuff.pointerDelta = 0
            ########################################
            self.objStuff.useFunctionStart = self.ui.new_funcStartRButton.isChecked()
            self.objStuff.useCurrentAddress = self.ui.new_locationRButton.isChecked()
            ########################################
            if (self.ui.new_locationLineEdit.text() is not None) and len(self.ui.new_locationLineEdit.text()) > 0:
                try:
                    self.objStuff.currentAddress = int(self.ui.new_locationLineEdit.text(), 0)
                except:
                    self.objStuff.currentAddress = None
            ################################################################################
        elif actionName == 'existing':
            nameidx = self.ui.existing_nameComboBox.currentIndex()
            self.objStuff.existingStructName = self.objStuff.existingStructNames[nameidx]
            ########################################
            self.objStuff.selectedReg = str(self.ui.existing_pointerComboBox.currentText())
            ########################################
            if (self.ui.existing_pointerDeltaLineEdit.text() is not None) and len(self.ui.existing_pointerDeltaLineEdit.text()) > 0:
                try:
                    self.objStuff.pointerDelta = int(self.ui.existing_pointerDeltaLineEdit.text(), 0)
                except:
                    self.objStuff.pointerDelta = 0
            else:
                self.objStuff.pointerDelta = 0
            ########################################
            self.objStuff.useFunctionStart = self.ui.existing_funcStartRButton.isChecked()
            self.objStuff.useCurrentAddress = self.ui.existing_locationRButton.isChecked()
            ########################################
            if (self.ui.existing_locationLineEdit.text() is not None) and len(self.ui.existing_locationLineEdit.text()) > 0:
                try:
                    self.objStuff.currentAddress = int(self.ui.existing_locationLineEdit.text(), 0)
                except:
                    self.objStuff.currentAddress = None
            ########################################
            self.objStuff.associateFunctionWithClass = self.ui.existing_cbAssociateFunction.isChecked()
            self.objStuff.modifyExisting = self.ui.existing_cbModifyExisting.isChecked()

            ################################################################################
        elif actionName == 'vfunc':
            self.logger.info('action vfunc: TODO')
            ################################################################################
        elif actionName == 'relations':
            self.logger.info('action relations: TODO')
            ################################################################################
        elif actionName == 'help':
            #nothing to do
            pass
        else:
            raise RuntimeError('Unknown action to store state')

#        #grab the state of the gui & store in the objStuff container
#        self.objStuff.useExisting = self.ui.rb_existingClass.isChecked()
#        self.objStuff.createNew = self.ui.rb_newClass.isChecked()
#        self.objStuff.filterUserClass = self.ui.cb_filterUserClass.isChecked()
#        self.objStuff.createVtable = self.ui.cb_createVtable.isChecked()
#        self.objStuff.modifyExisting = self.ui.cb_modifyExisting.isChecked()
#        self.objStuff.useFunctionStart = self.ui.rb_funcStart.isChecked()
#        self.objStuff.useCurrentAddress = self.ui.rb_startLocation.isChecked()
#        self.objStuff.selectedRegIdx = self.ui.combo_objPtrReg.currentIndex()
#        self.objStuff.existingStructName = str(self.ui.combo_existingClasses.currentText())
#
#        ########################################
#        if (self.ui.line_className.text() is not None) and len(self.ui.line_className.text()) > 0:
#            self.objStuff.newStructName = str(self.ui.line_className.text())
#        else:
#            #orange TODO: raise error message
#            pass
#        ########################################
#        if (self.ui.line_startLocation.text() is not None) and len(self.ui.line_startLocation.text()) > 0:
#            try:
#                self.objStuff.currentAddress = int(self.ui.line_startLocation.text(), 0)
#            except:
#                self.ui.line_startLocation.setText('0x%08x' % self.objStuff.currentAddress)
#                pass
#        elif self.objStuff.useCurrentAddress:
#            #orange TODO: raise error message
#            pass
#
#        ########################################
#        if (self.ui.line_objectSize.text() is not None) and len(self.ui.line_objectSize.text()) > 0:
#            try:
#                self.objStuff.structSize = int(self.ui.line_objectSize.text(), 0)
#            except:
#                self.objStuff.structSize = 0
#                self.ui.line_objectSize.setText('0x00', )
#        else:
#            self.objStuff.structSize = 0
#        ########################################
#        if (self.ui.line_delta.text() is not None) and len(self.ui.line_delta.text()) > 0:
#            try:
#                self.objStuff.pointerDelta = int(self.ui.line_delta.text(), 0)
#            except:
#                self.objStuff.pointerDelta = 0
#                self.ui.line_delta.setText('0x%02x' % self.objStuff.pointerDelta)
#        else:
#            self.objStuff.pointerDelta = 0
#
# 
################################################################################
#class ClassGuiWidget_mark1(QtGui.QWidget):
#    def __init__(self, parent=None, idaform=None, data=None, objStuff=None):
#        QtGui.QWidget.__init__(self, parent)
#        self.logger = jayutils.getLogger('facet.ClassGuiWidget')
#        try:
#            self.ui = facet_ui.Ui_facetui()
#            self.ui.setupUi(self)
#            self.idaform = idaform
#            self.objStuff = objStuff
#
#            #initialize stuff
#            self.objStuff.updateStateFromDisplay()
#            self.setFields()
#            self.updateFields()
#            self.installEventFilter(self)
#            self.ui.line_className.installEventFilter(self)
#
#            self.ui.combo_objPtrReg.setCurrentIndex(self.objStuff.selectedRegIdx)
#            self.setFocusPolicy(QtCore.Qt.StrongFocus)
#
#            #connect stuf here
#            #self.ui.pb_cancel.clicked.connect(self.onRejected)
#            #self.ui.pb_run.clicked.connect(self.onAccepted)
#            #self.ui.cb_filterUserClass.clicked.connect(self.onFilterUserClassClicked)
#
#        except Exception, err:
#            self.logger.exception('Error during init: %s', str(err))
#
#    #accepted = QtCore.Signal()  
#    #rejected = QtCore.Signal()
#
#    def updateFields(self):
#        '''Used to update display fields with updated values that may change'''
#        self.ui.line_funcStart.setText('0x%08x' % self.objStuff.funcStart)
#        self.ui.line_startLocation.setText('0x%08x' % self.objStuff.currentAddress)
#        self.ui.line_delta.setText('0x%02x' % self.objStuff.pointerDelta)
#        self.ui.combo_existingClasses.clear()
#        self.ui.combo_existingClasses.addItems(self.objStuff.userStructs)
#        self.ui.line_className.setText(self.objStuff.defaultNewStructName)
#
#    def setFields(self):
#        '''Used to init display field'''
#        self.ui.combo_objPtrReg.addItems(self.objStuff.registers)
#        self.ui.cb_filterUserClass.setChecked(self.objStuff.filterUserClass)
#        self.ui.cb_createVtable.setChecked(self.objStuff.createVtable)
#        self.ui.cb_modifyExisting.setChecked(self.objStuff.modifyExisting)
#        self.ui.line_className.setText(self.objStuff.defaultNewStructName)
#
#    def storeState(self):
#        #grab the state of the gui & store in the objStuff container
#        self.objStuff.useExisting = self.ui.rb_existingClass.isChecked()
#        self.objStuff.createNew = self.ui.rb_newClass.isChecked()
#        self.objStuff.filterUserClass = self.ui.cb_filterUserClass.isChecked()
#        self.objStuff.createVtable = self.ui.cb_createVtable.isChecked()
#        self.objStuff.modifyExisting = self.ui.cb_modifyExisting.isChecked()
#        self.objStuff.useFunctionStart = self.ui.rb_funcStart.isChecked()
#        self.objStuff.useCurrentAddress = self.ui.rb_startLocation.isChecked()
#        self.objStuff.selectedRegIdx = self.ui.combo_objPtrReg.currentIndex()
#        self.objStuff.existingStructName = str(self.ui.combo_existingClasses.currentText())
#
#        ########################################
#        if (self.ui.line_className.text() is not None) and len(self.ui.line_className.text()) > 0:
#            self.objStuff.newStructName = str(self.ui.line_className.text())
#        else:
#            #orange TODO: raise error message
#            pass
#        ########################################
#        if (self.ui.line_startLocation.text() is not None) and len(self.ui.line_startLocation.text()) > 0:
#            try:
#                self.objStuff.currentAddress = int(self.ui.line_startLocation.text(), 0)
#            except:
#                self.ui.line_startLocation.setText('0x%08x' % self.objStuff.currentAddress)
#                pass
#        elif self.objStuff.useCurrentAddress:
#            #orange TODO: raise error message
#            pass
#
#        ########################################
#        if (self.ui.line_objectSize.text() is not None) and len(self.ui.line_objectSize.text()) > 0:
#            try:
#                self.objStuff.structSize = int(self.ui.line_objectSize.text(), 0)
#            except:
#                self.objStuff.structSize = 0
#                self.ui.line_objectSize.setText('0x00', )
#        else:
#            self.objStuff.structSize = 0
#        ########################################
#        if (self.ui.line_delta.text() is not None) and len(self.ui.line_delta.text()) > 0:
#            try:
#                self.objStuff.pointerDelta = int(self.ui.line_delta.text(), 0)
#            except:
#                self.objStuff.pointerDelta = 0
#                self.ui.line_delta.setText('0x%02x' % self.objStuff.pointerDelta)
#        else:
#            self.objStuff.pointerDelta = 0
#
#    def eventFilter(self, widget, event):
#        if ((event.type() == QtCore.QEvent.KeyPress) and (event.key() == QtCore.Qt.Key_Enter)):
#            #(widget == self.ui.line_funcStart) or (widget == self.ui.line_startLocation) or 
#            #(widget == self.ui.line_className) or
#            #(widget == self.ui.line_objectSize))):
#                self.logg.debug('Caught an enter on a line edit. Accepting')
#                self.accepted.emit()  
#                return True
#        return False
#
#    def onFilterUserClassClicked(self):
#        try:
#            self.ui.combo_existingClasses.clear()
#            if self.ui.cb_filterUserClass.isChecked():
#                self.ui.combo_existingClasses.addItems(self.objStuff.userStructs)
#            else:
#                self.ui.combo_existingClasses.addItems(self.objStuff.existingStructNames)
#        except Exception, err:
#            self.logger.exception('Error in onFilterUserClassClicked: %s', str(err))
#
#    def onAccepted(self):
#        try:
#            self.logger.info('Accepted!')
#            self.storeState()
#            if self.idaform is not None:
#                #HACK TODO: only run the function if in an IDA form....
#                self.objStuff.runFunction()
#            self.accepted.emit()  
#        except Exception, err:
#            self.logger.exception('Error in onAccepted: %s', str(err))
#
#    def onRejected(self):
#        try:
#            self.logger.info('Rejected!')
#            if self.idaform is not None:
#                #HACK TODO: only run the function if in an IDA form....
#                self.doClose()
#            self.rejected.emit()
#        except Exception, err:
#            self.logger.exception('Error in onRejected: %s', str(err))
#
#    def doClose(self):
#        doneFailed = False
#        if self.idaForm is None:
#            return
#        try:
#            self.idaform.Close(0) 
#            self.logger.debug('Top level close worked')
#        except Exception, err:
#            doneFailed = True
#            self.logger.debug('Top level close failed')
#            #self.logger.exception('Error in onRejected: %s', str(err))
#
#        if doneFailed:
#            try:
#                idaapi._idaapi.plgform_close(self.idaform.__clink__, 0)
#                self.logger.debug('Manual close worked')
#            except Exception, err:
#                self.logger.exception('Error in onRejected 2nd try: %s', str(err))

################################################################################
#
#class MyPluginFormClass(PluginForm):
#    def OnCreate(self, form):
#        """
#        Called when the plugin form is created
#        """
#        self.logger = jayutils.getLogger('facet.MyPluginFormClass')
#
#        # Get parent widget
#        self.logger.debug('Doing OnCreate now')
#        self.parent = self.FormToPySideWidget(form)
#        self.PopulateForm()
#
#    def PopulateForm(self):
#        try:
#            self.logger.debug('Doing PopulateForm now')
#            filePath = jayutils.getInputFilepath()
#            if filePath is None:
#                self.logger.info('No input file provided. Stopping')
#                return
#            vw = jayutils.loadWorkspace(filePath)
#            layout = QtGui.QVBoxLayout()
#            self.objStuff = ObjectBodyStuff(vw)
#            self.widg = ClassGuiWidget(idaform=self, objStuff = self.objStuff)
#            layout.addWidget(self.widg)
#            self.parent.setLayout(layout)
#        except Exception, err:
#            self.logger.exception('Error populating form: %s', str(err))
#
#    def OnClose(self, form):
#        """
#        Called when the plugin form is closed
#        """
#        pass
#        self.logger.debug('Doing OnClose now')
#
################################################################################

class FacetMainDialog(QtGui.QDialog):
    def __init__(self, objStuff):
        QtGui.QDialog.__init__(self, None)
        self.logger = jayutils.getLogger('facet.FacetMainDialog')
        try:
            self.objStuff = objStuff
            self.createWidgets()
            self.widg.accepted.connect(self.accept)
            self.widg.rejected.connect(self.reject)

        except Exception, err:
            self.logger.exception('Error in init: %s', str(err))

    def createWidgets(self):
        self.widg = FacetUiWidget(self, objStuff = self.objStuff)
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.widg)
        self.setLayout(layout)

    def setActiveTab(self, tabName):
        attrname = TAB_MAP.get(tabName)
        if attrname is None:
            raise RuntimeError('No tab by ID %s' % tabName)
        tab = getattr(self.widg.ui, attrname)
        if tab is None:
            raise RuntimeError('No tab by name %s' % attrname)
        self.widg.ui.tabWidget.setCurrentWidget(tab)
        self.logger.debug('Set new tab to %s', tabName)

################################################################################


