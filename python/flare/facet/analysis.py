import idc
import idaapi
import idautils

import re
import copy
import json
import pprint
import struct
import logging
import os.path
import binascii
import warnings

import flare.jayutils as jayutils

with warnings.catch_warnings():
    #filter out deprecation warnings
    warnings.filterwarnings("ignore",category=DeprecationWarning)

    import vivisect
    import envi.bits as e_bits
    import envi.archs.i386 as e_i386
    import envi.archs.amd64.disasm as e_amd64
    from visgraph import pathcore as vg_path
    import vivisect.impemu.monitor as viv_imp_monitor

#FACET_USER_STRUCTS_NODE = 'facet_user_structs'
FACET_USER_STRUCTS_NODE = '$ facet_user_structs'
FACET_USER_STRUCTS_NODE_BLOB_ID = (0, 'J')

#maps # of bits to a tuple of (IDA_TYPE, NUMBER_BYTES)
IDA_DATA_SIZES = {
    1:      (idc.FF_BYTE, 1),
    2:      (idc.FF_WORD, 2),
    4:      (idc.FF_DWRD, 4),
    8:      (idc.FF_QWRD, 8),
}

X86_REGISTERS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
X64_REGISTERS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


################################################################################
g_addreRegExp = re.compile(r'FACET: (0x[\dA-Fa-f]{8,16})')

################################################################################

class StructInfo(object):
    def __init__(self, name):
        self.logger = jayutils.getLogger('facet.StructInfo')
        self.name = str(name)
        self.tid = idaapi.get_struc_id(name)
        if self.tid == idc.BADADDR:
            raise ValueError("Unknown struct: %s" % name)
        self.struc = idaapi.get_struc(self.tid)
        if (self.struc == 0) or (self.struc is None):
            raise ValueError("Known struct, but bad struc_t: %s" % self.name)
        self.idx = idc.GetStrucIdByName(str(self.name))
        self.members = []
        self.loadMembers()
        #self.logger.debug("Loaded struct %s: 0x%08x. tid: 0x%x: idx: 0x%x", 
        #    self.name, idc.GetStrucSize(self.idx), self.tid, self.idx)

    def loadMembers(self):
        off = idaapi.get_struc_first_offset(self.struc) 
        while off != idc.BADADDR:
            member = idaapi.get_member(self.struc, off)
            if (member == 0) or (member is None):
                #not really an error, i guess
                pass
            else:
                self.members.append(MemberInfo(self.struc, member, off))

            off = idaapi.get_struc_next_offset(self.struc, off) 
        #members should be sorted as-is, but make sure it is sorted by offset
        self.members.sort(key = lambda mem: mem.offset)

    def isStructOffset(self, offset):
        '''
        Returns True if the given offset is a defined offset within this struct,
        or if it is in a contained structure.
        '''
        #self.logger.debug("Trying to find %08x in list: %s", offset, ' '.join([hex(i.offset) for i in self.members]))
        for mem in self.members:
            if mem.offset == offset:
                return True
            elif mem.offset > offset:
                #passed the point where <offset> would have been found in sorted list
                return False
            elif mem.isStruc() and (offset < (mem.offset + mem.size)):
                #recurse to the contained struct
                return mem.selfStructInfo.isStructOffset(offset-mem.offset)
        return False

    def addNewOffset(self, offset, size=1):
        #look through the members, checking to see if the new field should be added to a contained struct
        doLocalAdd = True
        for mem in self.members:
            if mem.offset == offset:
                raise ValueError("Trying to add offset to struct where it is already defined: %s %08x" % (self.name, offset))
            elif mem.offset > offset:
                #passed the point where <offset> would have been found in sorted list
                # go ahead & add the new field
                doLocalAdd = True
            elif mem.isStruc() and (offset < (mem.offset + mem.size)):
                #recurse to the contained struct
                doLocalAdd = False
                mem.selfStructInfo.addNewOffset(offset-mem.offset, size)
        #if get here, the existing struct isn't large enough... will IDA auto-extend?
        #go ahead & add i guess
        if doLocalAdd:
            self.logger.debug("Adding new offset: %02x", offset)
            idc.AddStrucMember(self.idx, 'f_%02x' % offset, offset, idc.FF_DATA|idc.FF_BYTE, -1, 1)
            self.addMember(offset)

    def addMember(self, offset):
        member = idaapi.get_member(self.struc, offset)
        if (member == 0) or (member is None):
            raise RuntimeError("ERROR: Could not retrieve struct member immediately after adding it!")
        self.members.append(MemberInfo(self.struc, member, offset))        
        self.members.sort(key = lambda mem: mem.offset)

################################################################################

class MemberInfo(object):
    def __init__(self, struc, memPtr, offset):
        #struc is the containing/parent struct for this member
        self.logger = jayutils.getLogger('facet.MemberInfo')
        if (struc == 0) or (struc is None):
            raise RuntimeError("Bad struc_t pointer")
        if (memPtr == 0) or (memPtr is None):
            raise RuntimeError("Bad member_t pointer")
        self.struc = struc
        self.memPtr = memPtr
        self.offset = offset
        
        self.name = idaapi.get_member_name(self.memPtr.id)
        self.size = idaapi.get_member_size(self.memPtr)
        #if this member itself is a struct
        self.selfStruc = idaapi.get_sptr(self.memPtr)
        self.selfStructInfo = None
        if self.isStruc():
            self.selfStructInfo = StructInfo(idaapi.get_struc_name(self.selfStruc.id))
            #self.logger.debug("Found member struct: %s: %02x %s %s", 
            #    idaapi.get_struc_name(self.struc.id), 
            #    self.offset,
            #    self.name,
            #    self.selfStructInfo.name
            #)

    def isStruc(self):
        return (self.selfStruc != 0) and (self.selfStruc is not None)

################################################################################

class ObjectTracker(object):
    def __init__(self):
        self.logger = jayutils.getLogger('facet.ObjectTracker')
        self.refs = {}
        self.objWrites = {}
        self.objReads = {}

    def addObjRef(self, eip, objOff, opIdx, delta):
        if not self.refs.has_key(objOff):
            self.refs[objOff] = []
        self.refs[objOff].append( (eip, objOff, opIdx, delta) )

    def addObjRead(self, eip, objOff, sz):
        oldBytes = self.objReads.get(objOff)
        if oldBytes is None:
            self.objReads[objOff] = [(eip, objOff, sz) ]
        else:
            oldBytes.append( (eip, objOff, sz) )

    def addObjWrite(self, eip, objOff, bytes=''):
        oldBytes = self.objWrites.get(objOff)
        if oldBytes is None:
            self.objWrites[objOff] = [(eip, objOff, bytes) ]
        else:
            oldBytes.append( (eip, objOff, bytes) )

    def getMemberSize(self, objOff):
        '''Returns the observed size of the member at the given offset'''
        #the readlist & writelist are slightly different -> readlist has the size,
        # writelist has the actual written bytes
        max1 = 1
        max2 = 1
        entryList1 = self.objWrites.get(objOff, [])
        entryList2 = self.objReads.get(objOff, [])
        if len(entryList1) != 0: 
            max1 = max([len(log[2]) for log in entryList1])
        if len(entryList2) != 0:
            max2 = max([log[2] for log in entryList2])
        return max([max1, max2])

    def getDataWriteByOff(self, queryOff):
        ''' 
        Returns an (eip, objOff, bytes) tuple for the last write to the given
        object offset.
        Returns None if no write found
        '''
        wlog = self.objWrites.get(0, None)
        if wlog is None:
            return None
        return wlog[-1]
  
################################################################################

class X86ObjectMonitor(viv_imp_monitor.EmulationMonitor):
    def __init__(self, objStuff, track):
        viv_imp_monitor.EmulationMonitor.__init__(self)
        self.logger = jayutils.getLogger('facet.X86ObjectMonitor')
        self.objStuff = objStuff
        self.track = track

    def cacheRegs(self, emu, op, starteip):
        self._cachedRegs = emu.getRegisters()
        self._startEip = starteip

    def getModifiedRegs(self, emu, op, endeip):
        curRegs = emu.getRegisters()
        modDict = {}
        for name, val in curRegs.items():
            #if name in self.regs and self.cachedRegs.has_key(name) and (self.cachedRegs[name] != val):
            if self._cachedRegs[name] != val:
                modDict[name] = val
                #self.logger.debug('Found overwritten reg: %s:=0x%x', name, val)
        return modDict

    def prehook(self, emu, op, starteip):
        """
        This monitor hook gets called back prior to the execution of
        each instruction in the emulator.
        """
        #print 'Processing'
        try:
            #self.logger.debug('prehook 0x%08x', starteip)
            for i, opnd in enumerate(op.getOperands()):
                #annoying -> lea's isDeref is turned off, so wee need to do -> do lots of type checks
                if (isinstance(opnd, e_i386.i386RegMemOper) or isinstance(opnd, e_i386.i386ImmMemOper) or isinstance(opnd, e_i386.i386SibOper)):
                    addr = opnd.getOperAddr(op, emu)
                    if self.objStuff.isObjPointer(addr):
                        delta = 0
                        if isinstance(opnd, e_i386.i386RegMemOper):
                            rval = emu.getRegister(opnd.reg)
                            delta = rval - self.objStuff.obj_pointer
                            #self.logger.debug('i386RegMemOper: 0x%x - 0x%x: %x', rval, self.objStuff.obj_pointer, delta)
                        if isinstance(opnd, e_i386.i386SibOper):
                            rval = emu.getRegister(opnd.reg)
                            delta = rval - self.objStuff.obj_pointer
                            #self.logger.debug('i386SibOper: 0x%x - 0x%x: %x', rval, self.objStuff.obj_pointer, delta)
                        #self.logger.debug('prehook obj ref: 0x%08x %d: 0x%04x (0x%x)', starteip, i, self.objStuff.getObjOffset(addr), delta)
                        self.track.addObjRef(starteip, self.objStuff.getObjOffset(addr), i, delta)
                elif (isinstance(opnd, e_i386.i386RegOper) or isinstance(opnd, e_i386.i386ImmOper) or isinstance(opnd, e_i386.i386PcRelOper)):
                    #pass??
                    pass
                elif (isinstance(opnd, e_amd64.Amd64RipRelOper)):
                    pass
                else:
                    self.logger.info('Unknown prehook opnd type: 0x%08x %d, %s', starteip, i, repr(opnd))
            
            #special case for "add <objPtr>, <offset>" -> any other special cases???
            if op.mnem.startswith('add') and (len(op.getOperands()) == 2):
                oper0, oper1  = op.getOperands()
                if isinstance(oper0, e_i386.i386RegOper) and isinstance(oper1, e_i386.i386ImmOper):
                    delta = 0
                    base = oper0.getOperValue(op, emu)
                    off = oper1.getOperValue(op, emu)
                    addr = base+off
                    if isinstance(oper0, e_i386.i386RegMemOper):
                        rval = emu.getRegister(op.reg)
                        delta = rval - self.objStuff.obj_pointer

                    if self.objStuff.isObjPointer(addr):
                        #self.logger.debug('HACK!!! prehook obj ref: 0x%08x %d: 0x%04x (0x%x)', starteip, i, self.objStuff.getObjOffset(addr), delta)
                        self.track.addObjRef(starteip, self.objStuff.getObjOffset(addr), 1, delta)
        except Exception, err:
            self.logger.exception('Error in prehook: %s', str(err))

################################################################################

def obj_path_visitor(node, **kwargs):
    track = kwargs.get('track')
    emu = kwargs.get('emu')
    objStuff = kwargs.get('objStuff')
    objVa = kwargs.get('objVa')
    logger = kwargs.get('logger')
    if track is None or emu is None or objStuff is None:
        return
    for logname in ['writelog', ]:
        wlog = vg_path.getNodeProp(node, logname)
        for eip, va, logBytes in wlog:
            if objStuff.isObjPointer(va):
                #logger.debug('Examining: %s 0x%08x: 0x%08x: Yes', logname, eip, va)
                off = objStuff.getObjOffset(va)
                track.addObjWrite(eip, off, logBytes)
            else:
                #logger.debug('Examining: %s 0x%08x: 0x%08x: No', logname, eip, va)
                pass
                
    for logname in ['readlog', ]:
        wlog = vg_path.getNodeProp(node, logname)
        for eip, va, logSz in wlog:
            if objStuff.isObjPointer(va):
                #logger.debug('Examining: %s 0x%08x: 0x%08x: Yes', logname, eip, va)
                off = objStuff.getObjOffset(va)
                track.addObjRead(eip, off, logSz)
            else:
                #logger.debug('Examining: %s 0x%08x: 0x%08x: No', logname, eip, va)
                pass

################################################################################

class FacetObjectAnalyzer(object):
    def __init__(self, vw):
        self.logger = jayutils.getLogger('facet.FacetObjectAnalyzer')
        try:
            self.vw = vw
            self.initState()
        except Exception, err:
            self.logger.exception('Error performing init: %s', str(err))

    def initState(self):
        if idaapi.ph_get_id() != idaapi.PLFM_386:
            raise RuntimeError('Only supports x86 and x64 currently')
        self.codesize = jayutils.getx86CodeSize()
        self.codesizeBytes = self.codesize/8
        if self.codesize == 32:
            self.registers = X86_REGISTERS
            #self.defRegisterIdx = self.registers.index('ecx')
            self.defRegister = 'ecx'
        elif self.codesize == 64:
            self.registers = X64_REGISTERS
            #self.defRegisterIdx = self.registers.index('rcx')
            self.defRegister = 'rcx'
        else:
            raise RuntimeError('Only x86 32-bit or x64 64-bit supported')
        self.action = None
        self.classData = None
        self.selectedReg = self.defRegister
        self.filterFacetClass = True
        self.createVtable = True
        self.modifyExisting = False 
        self.pointerDelta = 0
        self.funcStart = None
        self.currentAddress = None
        self.structSize = 0
        self.parentOffset = None
        self.useExisting = False
        self.useFunctionStart = False
        self.useCurrentAddress = False
        self.useRegisterPointer = True
        self.existingStructName = None
        self.newStructName = None
        self.defaultNewStructName = ''
        self.newStructParentName = None
        self.associateFunctionWithClass = True
        # userStructNames: list of facet defined structs names (no vtbls)
        self.userStructNames = []
        # list of user struct names, with entry 0 empty (for no parent)
        self.newValidParents = []
        self.existingStructInfo = []

        self.structNameToSid = {}

        #orange TODO: possibleVfuncs -> needs to include parent/child relations
        # list of tuples: (struct_id, struct_name, field_name, address, addrname)
        self.possibleVfuncs = []
        self.selectedVfuncs = []
        
        #existingStructNames -> names of all structs loaded by current idb
        self.existingStructNames = []

        #uses current cursor location to set various values
        self.updateStateFromDisplay()

        self.loadUserStructs()
        self.loadVfuncs()
        self.loadStructInfo()

    def initEmptyClassData(self):
        self.classData = {
            #each entry in 'structs' is keyed by struct ID (not IDX!)
            # each struct has the following keys:
            # 'id': ida struct ID (same as the key)
            # 'size': size of the struct -> is this needed???
            # 'name': current struct name (can be changed by user! but hopefully doesn't too often)
            # 'parent': id of parent class, or None
            # 'children': list of ids of child classes
            # 'vtable' : id of associated vtable struct if any, or None
            # 'functions' : list of EAs for associated member functions for this class
            'structs' : { },

            # each entry in 'vtables' is keyed by vtable struct ID
            # each has the following keys:
            # 'id'      : ida struct ID (same as the key)
            # 'class' : id of associated class, else None
            # 'name': current struct name (can be changed by user! but hopefully doesn't too often)
            # 'parent' : id of parent vtable (if any), or None
            # 'children': list of ids of child vtables
            'vtables' : { },

            # each entry in 'functions' is a list, keyed by function ea
            #  each item in the list is the struct ID the function is associated with
            #  NOTE: functions can be 1-to-many, hence the list.
            'functions' : { },
        }

    #def setChildClass(self, parent, child)
    #    '''
    #    Given an ID for a parent & child, associates those two
    #    '''

    def initEmu(self):
        '''
        Returns an emulator ready to track an object memory
        '''
        emu = self.vw.getEmulator(True, True)
        # Pre-initialize a obj memory bytes
        self.init_obj_map = ''
        self.obj_map_size = 0x8000
        self.psize = emu.getPointerSize()
        #TODO: better selection of memory range to use?
        self.obj_map_mask = e_bits.sign_extend(0xfff00000, 4, self.psize)
        self.obj_map_base = e_bits.sign_extend(0xcfc00000, 4, self.psize)
        self.obj_pointer = self.obj_map_base + 0x1000
        tracker = ObjectTracker()
        mon = X86ObjectMonitor(self, tracker)
        emu.setEmulationMonitor(mon)

        #continue emulating even if unsupported instructions are encountered
        emu.strictops = False

        # Map in a memory map for the object
        objfiller = e_bits.sign_extend(0xfefe0000, 4, self.psize)
        if self.codesize == 32:
            for i in xrange(self.obj_map_size/self.psize):
                self.init_obj_map += struct.pack("<I", objfiller+(i*self.psize))
        elif self.codesize == 64:
            for i in xrange(self.obj_map_size/self.psize):
                self.init_obj_map += struct.pack("<Q", objfiller+(i*self.psize))
        else:
            raise RuntimeError('bad codesize')
        emu.addMemoryMap(self.obj_map_base, 6, "[obj]", self.init_obj_map)

        return emu

    def isObjPointer(self, va):
        return (va & self.obj_map_mask) == self.obj_map_base
    
    def getObjOffset(self, va):
        return (va - self.obj_pointer)

    def runAnalysis(self):
        if self.action == 'new':
            self.runActionNew()
        elif self.action == 'existing':
            self.runActionExisting()
        elif self.action == 'vfunc':
            self.runActionVfunc()
        elif self.action == 'relations':
            self.runActionRelations()
        elif self.action == 'help':
            self.runActionHelp()
        elif self.action == 'dumpjson':
            self.runDumpJson()
        elif self.action == 'loadjson':
            self.runLoadJson()
        else:
            raise RuntimeError('Action analysis not implmented: %s' % action)

    def runActionNew(self):
        self.logger.debug('runActionNew')
        self.dumpRunAnalysisConfig()
        tracker = self.emulateFunction()
        #reload struct after creation
        self.createStruct(self.newStructName, self.newStructParentName, tracker)
        self.loadUserStructs()
        self.loadStructInfo()
        self.markupStructUse(self.newStructName, tracker)

    def runActionExisting(self):
        self.logger.debug('runActionExisting')
        self.dumpRunAnalysisConfig()
        tracker = self.emulateFunction()
        self.markupStructUse(self.existingStructName, tracker)

    def runActionVfunc(self):
        self.logger.debug('runActionVfunc')
        try:
            self.handleSelectedVtblRefs(self.currEa, self.selectedVfuncs)
        except Exception, err:
            self.logger.exception("Exception caught: %s", str(err))

    def runActionRelations(self):
        #self.logger.info('runActionRelations: nothing to do')
        pass

    def runActionHelp(self):
        #self.logger.info('runActionHelp: nothing to do')
        pass

    def runDumpJson(self):
        try:
            with file(self.dumpJsonFile, 'wb') as ofile:
                json.dump(self.classData, ofile, indent=4)
            self.logger.info('runDumpJson: wrote to %s', self.dumpJsonFile)
        except Exception, err:
            self.logger.exception('Error in runDumpJson: %s', str(err))

    def runLoadJson(self):
        try:
            with file(self.loadJsonFile, 'rb') as ifile:
                self.classData = json.load(ifile)
            #TODO: other validation?
            if not self.classData.has_key('structs'):
                raise RuntimeError('Missing structs key')
            if not self.classData.has_key('vtables'):
                raise RuntimeError('Missing vtables key')
            if not self.classData.has_key('functions'):
                raise RuntimeError('Missing functions key')
            #save it to the idb
            self.storeDataToIdb()
            self.logger.info('runLoadJson: Loaded from %s', self.loadJsonFile)
        except Exception, err:
            self.logger.exception('Error in runDumpJson: %s', str(err))

    def dumpRunAnalysisConfig(self):
        if self.useCurrentAddress:
            self.logger.info('Start address 0x%08x (explicit)', self.currentAddress)
        else:
            self.logger.info('Start address 0x%08x (function start)', self.funcStart)
        if self.action == 'new':
            self.logger.info('Class name: %s', self.newStructName)
            self.logger.info('Class size: 0x%x', self.structSize)
            self.logger.info('Parent class: %r', self.newStructParentName)
        else:
            self.logger.info('Class name: %s', self.existingStructName)
        self.logger.info('Object register: %s', self.selectedReg)
        self.logger.info('Pointer delta: 0x%x', self.pointerDelta)

        if self.action != 'new':
            self.logger.info('Modify existing: %r', self.modifyExisting)
            self.logger.info('Associate function with class: %r', self.associateFunctionWithClass)

    def emulateFunction(self):
        '''
        Returns an ObjectTracker for the function
        '''
        emu = self.initEmu()
        #orange TODO: it would be better to run from the start of the function regardless,
        # and just take results starting at 
        startEa = self.funcStart
        if self.useCurrentAddress:
            startEa = self.currentAddress

        if self.useRegisterPointer:
            self.logger.debug('Following register: %s', self.selectedReg)
            #account for specified user delta
            emu.setRegisterByName(self.selectedReg, self.obj_pointer+self.pointerDelta)
            self.logger.debug('Followed regiser value: %s 0x%08x', self.selectedReg, emu.getRegisterByName(self.selectedReg))
        else:
            raise RuntimeError('Only register following supported at this time')

        self.logger.debug('Running function 0x%08x now. Following %s', startEa, self.selectedReg)

        emu.runFunction(startEa, maxhit=1, maxloop=1)
        tracker = emu.emumon.track
        #self.logger.debug('Done. Examining emu paths now')
        jayutils.path_bfs(emu.path, obj_path_visitor, track=tracker, emu=emu, logger=self.logger, objStuff=self, objVa=self.obj_pointer)
        #self.logger.debug('Logged info:') 
        #for key in sorted(tracker.refs.keys()):
        #    for i, entry in enumerate(tracker.refs[key]):
        #        eip, offset, opIdx, delta = entry
        #        pad = '----'
        #        if i != 0:
        #            pad = '    '
        #        self.logger.debug('%s0x%04x: 0x%08x %d 0x%x', pad, offset, eip, opIdx, delta)
        return tracker

    def updateStateFromDisplay(self):
        #grab 'transient' state, for use during focus-in events
        self.currEa = idc.here()
        self.funcStart = idc.GetFunctionAttr(idc.here(), idc.FUNCATTR_START)
        self.currentAddress = idc.here()

    def loadVfuncs(self):
        try:
            srcxref = self.getVtblSourceRef(self.currEa)
            if srcxref is None:
                self.logger.info('Skipping runActionVfunc: could not find source of vtable')
                return
            items = self.getVtblDerefs(self.currEa)
            #TODO: figure out parent-child relationships!
            self.possibleVfuncs = items
        except Exception, err:
            self.logger.exception("loadVfuncs exception caught: %s", str(err))
        
    def loadUserStructs(self):
        self.idbNetnode = idaapi.netnode()
        isnew = self.idbNetnode.create(FACET_USER_STRUCTS_NODE)
        self.initEmptyClassData()
        if isnew:
            self.logger.debug('No user structs found, starting from scratch')
            self.writeDataToNetnode(self.classData)
            self.defaultNewStructName = 'cls1'
            return
        data = self.loadDataFromNetnode()
        data = json.loads(data)
        # integer keys in json are converted to strings, so change back to ints here
        for k,v in data['structs'].items():
            self.classData['structs'][int(k)] = v
        for k,v in data['functions'].items():
            self.classData['functions'][int(k)] = v
        for k,v in data['vtables'].items():
            self.classData['vtables'][int(k)] = v

        self.checkUserIdaStructChanges()
        #now load the user struct names to use
        for sid, struc in self.classData['structs'].items():
            self.userStructNames.append(struc['name'])
        classCount = len(self.classData['structs'])
        vtableCount = len(self.classData['vtables'])
        self.defaultNewStructName = 'cls%d' % (classCount+1)
        self.userStructNames.sort()
        self.newValidParents = copy.copy(self.userStructNames)
        self.newValidParents.insert(0, '')
        self.logger.debug('Loaded %d user structs, %d vtables', classCount, vtableCount)

    def checkUserIdaStructChanges(self):
        '''
        Iterates over the known user structs in the dict, checking if the user has renamed 
        them or deleted any, and if so updates the class dict & resyncs back to the idb.
        '''
        isDirty = False
        toRemoveClasses = set()
        toRemoveVtables = set()
        for sid, struc in self.classData['structs'].items():
            idaname = idc.GetStrucName(sid)
            if idaname is None:
                self.logger.debug('Detected deleted user struct: 0x%08x %s', sid, struc['name'])
                isDirty = True
                # user deleted the structure, so delete it
                # vtable *should* be deleted as well... right?
                if struc['vtable'] is not None:
                    toRemoveVtables.add(struc['vtable'])
                #remove reference to parents list of children
                if struc['parent'] is not None:
                    parent = self.classData['structs'].get(struc['parent'], None)
                    if parent is None:
                        raise RuntimeError("Data sync issue: unknown parent")
                    pchildren = set(parent['children'])
                    pchildren.discard(sid)
                    self.classData['structs'][struc['parent']]['children'] = list(pchildren)
                #remove reference to this for each child class
                for childid in struc['children']:
                    child = self.classData['structs'].get(childid, None)
                    if child is None:
                        raise RuntimeError("Data sync issue: child doesn't exist")
                    if child['parent'] != sid:
                        raise RuntimeError("Data sync issue: child thinks parent is someone else! call maury")
                    child['parent'] = None
                #defer changing the dict since we're iterating over it
                toRemoveClasses.append(sid)
            elif struc['name'] != idaname:
                # user renamed the structure
                self.logger.debug('Detected renamed user struct: 0x%08x %s -> %s', sid, struc['name'], idaname)
                struc['name'] = idaname
                isDirty = True
            #elif idc.GetStrucSize(sid) != struc['
        for sid, vtable in self.classData['vtables'].items():
            idaname = idc.GetStrucName(sid)
            if idaname is None:
                self.logger.debug('Detected deleted vtable: 0x%08x %s', sid, vtable['name'])
                isDirty = True
                toRemoveVtables.add(sid)
            elif idaname != vtable['name']:
                self.logger.debug('Detected renamed vtable: 0x%08x %s -> %s', sid, vtable['name'], idaname)
                vtable['name'] = idaname
                isDirty = True
            
        for sid in toRemoveClasses:
            funcs = self.classData['structs']['functions']
            self.classData['structs'].pop(sid, None)
            for funcEa in funcs:
                funcList = self.classData['functions'].get(funcEa)
                if funcList:
                    #filter out any reference to the struct sid being removed
                    newFuncList = [a for a in funcList if a != sid]
                    self.classData['functions'][funcEa] = newFuncList

        for sid in toRemoveVtables:
            self.classData['vtables'].pop(sid, None)

        if isDirty:
            #self.idbNetnode.setblob(json.dumps(self.classData), *FACET_USER_STRUCTS_NODE_BLOB_ID)
            self.writeDataToNetnode(self.classData)

    def storeDataToIdb(self):
        self.writeDataToNetnode(self.classData)

    def writeDataToNetnode(self, data):
        self.idbNetnode.setblob(json.dumps(data), *FACET_USER_STRUCTS_NODE_BLOB_ID)

    def loadDataFromNetnode(self):
        return self.idbNetnode.getblob(*FACET_USER_STRUCTS_NODE_BLOB_ID) 

    #def loadUserStructs_old(self):
    #    #store user structs as a ';' delimited string
    #    # actual struct info will/should be loaded along with other structs
    #    # in loadStructInfo
    #    curr = jayutils.queryIdbNetnode(FACET_USER_STRUCTS_NODE)
    #    if curr is None:
    #        self.logger.debug('No user structs found')
    #        self.defaultNewStructName = 'cls1'
    #    else:
    #        self.logger.debug('Got existing user strings: <%s>', curr)
    #        #self.userStructs = curr.split(';')
    #        self.userStructs = []
    #        loadedStructs = curr.split(';')
    #        for name in loadedStructs:
    #            if idc.GetStrucIdByName(name) == idc.BADADDR:
    #                self.logger.debug('Detected deleted user struct: %s', name)
    #            else:
    #                self.logger.debug('User struct 0x%x: %s', idc.GetStrucIdByName(name), name)
    #                self.userStructs.append(name) 
    #        #check if a user deleted a struct: update the built-in list
    #        if len(loadedStructs) != len(self.userStructs):
    #            cur = ';'.join(self.userStructs)
    #            jayutils.setIdbNetnode(FACET_USER_STRUCTS_NODE, curr)
    #        i = 1
    #        nextName = 'cls%d' % i
    #        while any([name.startswith(nextName) for name in self.userStructs]):
    #            if i > 1000:
    #                raise RuntimeError('No default name could be found!')
    #            i += 1
    #            nextName = 'cls%d' % i
    #        self.defaultNewStructName = nextName

    #def addUserStruct_old(self, name):
    #    curr = jayutils.queryIdbNetnode(FACET_USER_STRUCTS_NODE)
    #    if curr is None:
    #        curr = name
    #    else:
    #        curr = curr + ';' + name
    #    self.logger.debug('new user structs: %s', curr)
    #    jayutils.setIdbNetnode(FACET_USER_STRUCTS_NODE, curr)

    def loadStructInfo(self):
        '''
        Load all of the structs the current IDB has loaded
        '''
        idx = idaapi.get_first_struc_idx()

        while idx != idc.BADADDR:
            tid = idaapi.get_struc_by_idx(idx)
            name = idaapi.get_struc_name(tid)
            self.existingStructInfo.append(StructInfo(name))
            idx = idaapi.get_next_struc_idx(idx)
            self.structNameToSid[str(name)] = tid
        self.existingStructNames = [h.name for h in self.existingStructInfo]
        self.existingStructNames.sort()
        self.logger.debug('Loaded %d existing IDA structs', len(self.existingStructNames))

    def createStruct(self, name, parentName, tracker):
        usedOffsets = []
        parentSid = None
        if (parentName is not None):
            self.logger.debug('Trying to lookup parentName %s:<%r>', type(parentName), parentName)
            parentSid = idc.GetStrucIdByName(str(parentName))
            if parentSid == idc.BADADDR:
                raise RuntimeError('Bad parent name: %s' % parentName)
        self.logger.debug("Trying to create struct: %s %s", type(name), str(name))
        if idc.GetStrucIdByName(str(name)) != idc.BADADDR:
            raise ValueError("StructureName already used: %s" % name)
        structId = idc.AddStrucEx(idc.BADADDR, name, 0)
        if structId == idc.BADADDR:
            raise ValueError("Could not create structure: %s" % name)
    
        #check if a specific size was set. if so create a byte member
        # at that location to force the size... is there a better way??
        if self.structSize != 0:
            self.logger.debug('Setting struct size to 0x%02x', self.structSize)
            off = self.structSize -1
            idc.AddStrucMember(structId, 'f_%02x' % off, off, idc.FF_DATA|idc.FF_BYTE, -1, 1)

        off0_entry = None

        for keyOff, entries in tracker.refs.items():
            #only need the first entry for the struct creation
            eip, off, opIdx, delta = entries[0]
            #filter out offsets already processed
            if off not in usedOffsets:
                #self.logger.debug("Trying to add %02x: %02x", structId, off)
                size, numBytes = IDA_DATA_SIZES.get(tracker.getMemberSize(off))
                idc.AddStrucMember(structId, 'f_%02x' % off, off, idc.FF_DATA|size, -1, numBytes)
                usedOffsets.append(off)
        strucSize = idc.GetStrucSize(structId)

        #orange TODO: if specified a
        if self.parentOffset is not None:
            self.logger.info('TODO: set parent type at offset: 0x%x', self.objStuff.parentOffset)

        
        newStruct = {
            'id'        : structId,
            #'size'     : strucSize, 
            'name'      : name,
            'parent'    : parentSid,
            'children'  : [],
            'vtable'    : None,
            'vclass'    : None,
            'functions' : [],
        }

        #check for setting function pointers as well
        #self.logger.debug('Starting up check for funcpointer members now. %d writelog entries', len(tracker.objWrites))
        for off, writelogs in tracker.objWrites.items():
            #self.logger.debug('Checking offset 0x%02x writes (%d entries)', off, len(writelogs))
            ealist = []
            for eip, objOff, bytes in writelogs:
                codeptr = None
                if (len(bytes) == 4) and (self.codesize == 32):
                    codeptr = struct.unpack_from('<I', bytes)[0]
                elif (len(bytes) == 4) and (self.codesize == 64):
                    codeptr = struct.unpack_from('<Q', bytes)[0]
                else:
                    #self.logger.debug('Skipping writebytes at 0x%08x', eip)
                    continue
                #self.logger.debug('Examining possible member function pointer: 0x%08x (0x%08x)', eip, codeptr)
                flags = idaapi.getFlags(codeptr)
                if idc.isLoaded(codeptr) and idc.isCode(flags):
                    #self.logger.debug('Found member funcpointer: 0x%08x (0x%08x)', eip, codeptr)
                    if not idc.hasName(flags): 
                        funcName = '%s_fptr_%08x' % (name, codeptr)
                        idc.MakeName(codeptr, funcName)
                    ealist.append(codeptr)
                    self.addFuncAssociation(codeptr, structId)
                else:
                    #self.logger.debug('Nope, not loaded or not code: 0x%08x', codeptr)
                    pass
            if len(ealist) > 0:
                commentList = []
                for ea in ealist:
                    commentList.append('FACET: 0x%08x' % ea)
                idc.SetMemberComment(structId, off, '\n'.join(commentList), 1)
                idc.SetMemberName(structId, off, 'f_%02x_fptr' % off)

        #handle vtable stuff here
        if self.createVtable:
            #self.logger.debug('Starting up vtable stuff now')
            entry = tracker.getDataWriteByOff(0)
            if entry is None:
                self.logger.error('User requested vtable creation, but no offset 0 writes found')
            else:
                eip, objOff, bytes = entry
                #self.logger.info('Examining writeentry: 0x%08x(0x%02x): %s', eip, objOff, bytes.encode('hex'))
                #TODO64: vtbale check for qword write
                if len(bytes) >= 4:
                    if self.codesize == 32:
                        vtablePtr = struct.unpack_from('<I', bytes)[0]
                    elif self.codesize == 64:
                        vtablePtr = struct.unpack_from('<Q', bytes)[0]
                    else:
                        raise RuntimeError('bad codesize')
                    if idc.isLoaded(vtablePtr) and idc.isData(idaapi.getFlags(vtablePtr)):
                        vtblSid, vtbleFunctions = self.makeVtableStuff(structId, name, vtablePtr)
                        if vtblSid:
                            self.logger.debug('Created vtable %r', vtblSid)
                            newStruct['vtable'] = vtblSid
                            newStruct['functions'].extend(vtbleFunctions)
                            for funcEa in vtbleFunctions:
                                self.addFuncAssociation(funcEa, structId)
                            newVtable = {
                                'id'        : vtblSid,
                                'name'      : idc.GetStrucName(vtblSid),
                                'class'     : structId,
                                'children'  : [],
                                'parent'    : None,
                            }
                            if parentSid is not None:
                                #it's ok if the parent's vtable is None
                                parentVtblId = self.classData['structs'][parentSid]['vtable']
                                if parentVtblId:
                                    newVtable['parent'] = parentVtblId
                                    self.classData['vtables'][parentVtblId]['children'].append(newVtable)
                            self.classData['vtables'][vtblSid] = newVtable
                        else:
                            self.logger.debug('Looked like a vtable may be present, but creation failed: 0x%08x', vtablePtr)
                    else:
                        #self.logger.debug('User requested vtable creation, but offset 0 write not a valid pointer (0x%08x)', vtablePtr)
                        pass
        else:
            #self.logger.debug('Nope. User does not want a vtable')
            pass

        if parentSid:
            parentStruc = self.classData['structs'][parentSid]
            parentStruc['children'].append(structId)

        #finally, insert the struct dict & store the new data
        self.classData['structs'][structId] = newStruct
        self.writeDataToNetnode(self.classData)

    def addFuncAssociation(self, ea, sid):
        if not self.classData['functions'].has_key(ea):
            self.classData['functions'][ea] = []
        if sid not in self.classData['functions'][ea]:
            self.classData['functions'][ea].append(sid)

    def markupStructUse(self, name, tracker):
        structId = idc.GetStrucIdByName(str(name))
        if structId == idc.BADADDR:
            raise ValueError("StructureName not found: %s" % name)
        for keyOff, entries in tracker.refs.items():
            for eip, off, opIdx, delta in entries:
                self.logger.debug("Marking (ea)0x%08x: (opIdx)%d (off)0x%02x (delta)0x%x (id)0x%x", eip, opIdx, off, delta, structId)
                idc.OpStroffEx(eip, opIdx, structId, delta)

    def calcVtableSize(self, startEa):
        '''
        Iterate over DWORD/QWORDS's starting at startEA until either:
        1) The DWORD/QWORD is not a valid pointer
        2) A xref to the EA is seen

        TODO: If there's a trailing non-code pointer entry, that will get marked too...
            Check if code or not
        '''
        for i in xrange(1000):
            ea = startEa + self.codesizeBytes*i
            if self.codesize == 32:
                val = idc.Dword(ea)
            elif self.codesize == 64:
                val = idc.Qword(ea)
            else:
                raise RuntimeError('Bad codesize')
            if not idc.isLoaded(val):
                self.logger.debug('Found non-loaded vtbl entry: 0x%08x 0x%08x', ea, val)
                return self.codesizeBytes*i
            if (ea != startEa) and (len([x for x in idautils.XrefsTo(ea)]) > 0):
                self.logger.debug('Found xrefs to ea 0x%08x', ea)
                return self.codesizeBytes*i
        raise RuntimeError('Weird vtable -> exhausted table: 0x%08x' % startEa)

    def makeVtableStuff(self, classSid, name, startEa):
        '''
        Returns the tuple (vtblSid, [assoc_functions]), 
        '''
        try:
            vtblFunctions = set()
            vtableName = '%s_vtbl' % name
            fakeName = '%s_vtable' % name
            self.logger.debug('Trying to make vtable: %s, 0x%08x', vtableName, startEa)
            vtableSize = self.calcVtableSize(startEa)
            if vtableSize == 0:
                self.logger.info('Skipping vtable creation as no valid vtable could be found (size=0)')
                return (None, [])
            structId = idc.AddStrucEx(idc.BADADDR, vtableName, 0)
            if structId == idc.BADADDR:
                raise ValueError("Could not create structure: %s" % vtableName)

            #name the vtable if not already done
            if not idc.hasName(idaapi.getFlags(startEa)):
                idc.MakeName(startEa, fakeName)

            #print 'Using selection: 0x%08x - 0x%08x' % (selStart, selEnd)
            count = 0

            for i in range(vtableSize/self.codesizeBytes):
                off  = self.codesizeBytes*i
                self.logger.debug('Adding vtable member offset (%d) %d', i, off)
                idc.AddStrucMember(structId, 'func_%02x' % count, off, idc.FF_DATA|idc.FF_DWRD, -1, 4)
                if self.codesize == 32:
                    val = idc.Dword(startEa + off)
                elif self.codesize == 64:
                    val = idc.Qword(startEa + off)
                else:
                    raise RuntimeError('Bad codesize')
                idc.SetMemberComment(structId, off, 'FACET: 0x%08x' % val, 1)
                flags = idaapi.getFlags(val)
                if idc.isLoaded(val) and idc.isCode(flags):
                    if not idc.hasName(flags):
                        #if it's a valid address & doesn't have a name, make it
                        funcName = '%s_vfunc%02d' % (name, i)
                        idc.MakeName(val, funcName)
                        self.logger.debug('Making vtbl function name: 0x%08x %s', val, funcName)
                    else:
                        self.logger.debug('Skipping vtbl function name: 0x%08x', val)
                    vtblFunctions.add(val)
                else:
                    self.logger.debug('Skipping vtbl entry 0x%08x', val)
                count += 1
            return (structId, vtblFunctions)
        except Exception, err:
            self.logger.exception('Error while trying to create vtable: %s', str(err))
        return (None, [])

    def getPossibleStructFuncPtrs(self, stroff, regexp = g_addreRegExp):
        '''
        Returns a list of (struct_id, struct_name, field_name, address, addrname) tuples
        for structs that have a member at offset <stroff> that has a comment
        containing <regexp>.
        '''
        ret = []
        strucidx = idc.GetFirstStrucIdx()
        while strucidx != idc.BADADDR:
            sid = idc.GetStrucId(strucidx)
            memcom = idc.GetMemberComment(sid, stroff, True)
            if memcom is not None:
                for m1 in regexp.finditer(memcom):
                    commea = m1.group(1)
                    strucname = idc.GetStrucName(sid)
                    memname = idc.GetMemberName(sid, stroff)
                    addrname = idc.Name(int(commea, 0))
                    item = (sid, strucname, memname, commea, addrname)
                    ret.append(item)
                    self.logger.debug('Found possible FACET struct: (0x%x, %s, 0x%02x, %s, %s, %s)', sid, strucname, stroff, memname, commea, addrname)
            strucidx = idc.GetNextStrucIdx(strucidx)
        return ret

    def getVtblDerefs(self, ea):
        mnem = idc.GetMnem(ea)
        vtbloff = None
        #TODO: other types of vtbl data accesses?
        if mnem.startswith('call'):
            #  call [<reg> + offset]
            if idc.GetOpType(ea, 0) == idc.o_displ:
                vtbloff = idc.GetOperandValue(ea, 0)
            elif idc.GetOpType(ea, 0) == idc.o_phrase:
                #o_phrase: no immediate values -> hoping always 0 for this
                vtbloff = 0
            else:
                self.logger.error('call: Not at o_displ call: 0x%08x', ea)
        elif mnem.startswith('mov'):
            #  mov <targ>, [<reg> + offset]
            if idc.GetOpType(ea, 1) == idc.o_displ:
                vtbloff = idc.GetOperandValue(ea, 1)
            elif idc.GetOpType(ea, 1) == idc.o_phrase:
                #o_phrase: no immediate values -> hoping always 0 for this
                vtbloff = 0
            else:
                self.logger.error('mov: Not at o_displ mov: 0x%08x', ea)
        if vtbloff is None:
            return []
        return self.getPossibleStructFuncPtrs(vtbloff)

    def getVtblSourceRef(self, ea):
        '''
        In case the script is called at a mov instruction to load the vtbl offset,
        search forward for the next call
        '''
        count = 0
        while count < 10:
            mnem = idc.GetMnem(ea)
            if mnem.startswith('call'):
                self.logger.debug('Founce sourceRef: %x', ea)
                return ea
            count += 1
            ea = idc.NextHead(ea)
        #raise RuntimeError('Could not find source call ref')
        return None

    def handleSelectedVtblRefs(self, ea, selected):
        self.clearCurrentNonNormalCodeRefs(ea)
        prefix = ''
        #search for an existing 'FACET autogen' comment, and remove it
        comm = idc.CommentEx(ea, False)
        if comm is not None:
            idx = comm.find('FACET autogenerated code xrefs:')
            if idx >= 0:
                prefix = comm[:idx].rstrip()
        if len(selected) == 0:
            self.logger.info('Skipping setting vfunc refs: empty selection')
            idc.MakeComm(ea, prefix)
            return
        comments = [prefix, '', 'FACET autogenerated code xrefs:',]
        for (sid, strucname, memname, commea, addrname) in selected:
            idc.AddCodeXref(ea, commea, idc.fl_CN)
            comments.append('0x%08x: %s.%s (%s)' % (commea, strucname, memname, addrname))
        comment = str('\n    '.join(comments))
        #self.logger.debug('Trying to make comment: 0x%08x: %s', ea, pprint.pformat(comment))
        idc.MakeComm(ea, comment)

    def clearCurrentNonNormalCodeRefs(self, ea):
        #clear all of the current code refs from ea (ignoring normal flows)
        refs = [ref for ref in idautils.CodeRefsFrom(ea, False)]
        for ref in refs: 
            self.logger.info('Deleting existing code xref 0x%08x -> 0x%08x', ea, ref)
            idc.DelCodeXref(ea, ref, False)

    def getAllDescendents(self, psid):
        '''
        Returns a list of sids for all descendent classes of the given sid
        '''
        desc = set()
        que = []
        que.extend(self.classData['structs'][psid]['children'])
        while len(que) > 0:
            sid = que.pop(0) 
            desc.add(sid)
            que.extend(self.classData['structs'][sid]['children'])
        return list(desc)

