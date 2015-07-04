#!/usr/bin/env python
# Jay Smith
# jay.smith@mandiant.com
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2012 Mandiant
# Copyright 2015 FireEye
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
# FACET: FLARE Automated Class Examination Tool
#
########################################################################


import logging
import traceback

import idc 
import idautils  
import idaapi


#orange TODO: backwards-compatible menu stuff
########################################
class FacetAction_CreateStruct(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.logger = flare.jayutils.getLogger('facet.FacetAction_CreateStruct')

    def activate(self, ctx):
        try:
            self.logger.debug("Hello from FacetAction_CreateStruct")
            flare.facet.runCreateStruct()
        except Exception, err:
            self.logger.exception('Error in activate: %s', str(err))
        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM 
        return idaapi.AST_DISABLE_FOR_FORM

class FacetAction_MarkupExistingStruct(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.logger = flare.jayutils.getLogger('facet.FacetAction_MarkupExistingStruct')

    def activate(self, ctx):
        try:
            self.logger.debug("Hello from FacetAction_MarkupExistingStruct")
            flare.facet.runMarkupExistingStruct()
        except Exception, err:
            self.logger.exception('Error in activate: %s', str(err))
        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM 
        return idaapi.AST_DISABLE_FOR_FORM

class FacetAction_MarkupVtable(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.logger = flare.jayutils.getLogger('facet.FacetAction_MarkupVtable')

    def activate(self, ctx):
        try:
            self.logger.debug("Hello from FacetAction_MarkupVtable")
            flare.facet.runMarkupVtable()
        except Exception, err:
            self.logger.exception('Error in activate: %s', str(err))
        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM 
        return idaapi.AST_DISABLE_FOR_FORM

class FacetAction_BrowseClassHierarchy(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.logger = flare.jayutils.getLogger('facet.FacetAction_BrowseClassHierarchy')

    def activate(self, ctx):
        try:
            self.logger.debug("Hello from FacetAction_BrowseClassHierarchy")
            flare.facet.runBrowseClasses()
        except Exception, err:
            self.logger.exception('Error in activate: %s', str(err))
        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM 
        return idaapi.AST_DISABLE_FOR_FORM

class FacetAction_BrowseHelp(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.logger = flare.jayutils.getLogger('facet.FacetAction_BrowseHelp')

    def activate(self, ctx):
        try:
            self.logger.debug("Hello from FacetAction_BrowseHelp")
            flare.facet.runBrowseHelp()
        except Exception, err:
            self.logger.exception('Error in activate: %s', str(err))
        return 1

    def update(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_FORM 
        return idaapi.AST_DISABLE_FOR_FORM


########################################
#the hook object needs to be global apparently - i guess ida wasn't keeping a ref to it
# when i was creating it within a function... i guess. who knows with this
g_Hooks = None

def initActions():
    global g_Hooks

    newaction = idaapi.action_desc_t(
        'facet:runCreateStruct',
        'Create struct',
        FacetAction_CreateStruct(),
        'Alt-0',
        'Automatically create new struct/class',
        199)
    idaapi.register_action(newaction)
    ########################################
    markupExistingAction = idaapi.action_desc_t(
        'facet:runMarkupExisting',
        'Markup existing',
        FacetAction_MarkupExistingStruct(),
        'Alt-9',
        'Markup existing struct/class',
        199)
    idaapi.register_action(markupExistingAction)
    ########################################
    newaction = idaapi.action_desc_t(
        'facet:runMarkupVtable',
        'Markup vtbl ref',
        FacetAction_MarkupVtable(),
        'Alt-8',
        'Marks up vtable use',
        199)
    idaapi.register_action(newaction)
    ########################################
    newaction = idaapi.action_desc_t(
        'facet:runBrowseClassHierarchy',
        'Browse Classes',
        FacetAction_BrowseClassHierarchy(),
        #'Alt-8',
        '',
        'Browse FACET annotated classes',
        199)
    idaapi.register_action(newaction)
    ########################################
    newaction = idaapi.action_desc_t(
        'facet:runBrowseHelp',
        'View HELP',
        FacetAction_BrowseHelp(),
        '',
        'View FACET Help Information',
        199)
    idaapi.register_action(newaction)
    ########################################
    idaapi.attach_action_to_menu(
        'Edit/FACET/',
        'facet:runCreateStruct',
        idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        'Edit/FACET/',
        'facet:runMarkupExisting',
        idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        'Edit/FACET/',
        'facet:runMarkupVtable',
        idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        'Edit/FACET/',
        'facet:runBrowseClassHierarchy',
        idaapi.SETMENU_APP
    )
    idaapi.attach_action_to_menu(
        'Edit/FACET/',
        'facet:runBrowseHelp',
        idaapi.SETMENU_APP
    )
    ########################################
    class FacetUIHook(idaapi.UI_Hooks):
        def populating_tform_popup(self, form, popup):
            # You can attach here.
            pass
            print 'FacetUIHook: populating'
            idaapi.msg("FacetUIHook: populating\n")

        def finish_populating_tform_popup(self, form, popup):
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                print 'Found FacetUIHook for BWN_DISASM'
                idaapi.attach_action_to_popup(form, popup, 'facet:runCreateStruct', 'FACET/')
                idaapi.attach_action_to_popup(form, popup, 'facet:runMarkupExisting', 'FACET/')
                idaapi.attach_action_to_popup(form, popup, 'facet:runMarkupVtable', 'FACET/')
            else:
                print 'Skipping FacetUIHook: %d' % idaapi.get_tform_type(form)
    ########################################

    g_Hooks = FacetUIHook()
    g_Hooks.hook()
    print 'Done with FacetUIHook install'


class facet_plugin_t(idaapi.plugin_t):
    #flags = 0
    flags = idaapi.PLUGIN_KEEP
    comment = "FACET: FLARE Automated Class Examination Tool"
    help = "This is help"
    wanted_name = "FACET"
    #wanted_hotkey = "Alt-0"
    wanted_hotkey = ""

    def init(self):
        try:
            idaapi.msg("FACET init() called!\n")
            idaapi.require('flare')
            idaapi.require('flare.jayutils')
            idaapi.require('flare.facet')

            #logger = flare.jayutils.configLogger('facet', logging.INFO)
            logger = flare.jayutils.configLogger('facet', logging.DEBUG)
            initActions()
            idaapi.msg("FACET done with initActions()\n")

            return idaapi.PLUGIN_OK
        except Exception, err:
            idaapi.msg("Exception during init: %s\n%s\n" % (str(err), traceback.format_exc()))
        
        return idaapi.PLUGIN_SKIP


    def run(self, arg):
        #try:
        #    idaapi.msg("FACET run() called with %d!\n" % arg)
        #    idaapi.require('flare')
        #    idaapi.require('flare.jayutils')
        #    idaapi.require('flare.facet')


        #    #logger = jayutils.configLogger('facet', logging.DEBUG)
        #    logger = flare.jayutils.configLogger('facet', logging.INFO)
        #    flare.facet.run(True)
        #    idaapi.msg("FACET run() done\n")

        #except Exception, err:
        #    idaapi.msg("Exception during run: %s\n%s\n" % (str(err), traceback.format_exc()))
            
        idaapi.msg("FACET run() complete!\n")

    def term(self):
        idaapi.msg("FACET term() called!\n")
        #global g_Hooks
        #try:
        #    idaapi.msg("FACET term() called!\n")
        #    if g_Hooks is not None:
        #        g_Hooks.unhook()
        #        g_Hooks = None
        #except Exception, err:
        #    idaapi.msg("Exception during run: %s\n%s\n" % (str(err), traceback.format_exc()))


def PLUGIN_ENTRY():
    return facet_plugin_t()




