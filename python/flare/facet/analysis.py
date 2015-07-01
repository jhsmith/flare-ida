import idc
import idaapi
import idautils

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

USER_STRUCT_INFO = 'facet_user_structs'

#maps # of bits to a tuple of (IDA_TYPE, NUMBER_BYTES)
IDA_DATA_SIZES = {
    1:      (idc.FF_BYTE, 1),
    2:      (idc.FF_WORD, 2),
    4:      (idc.FF_DWRD, 4),
    8:      (idc.FF_QWRD, 8),
}

X86_REGISTERS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
X64_REGISTERS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

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
        self.idx = idc.GetStrucIdByName(self.name)
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
            self.logger.debug("Found member struct: %s: %02x %s %s", 
                idaapi.get_struc_name(self.struc.id), 
                self.offset,
                self.name,
                self.selfStructInfo.name
            )

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
                self.logger.debug('Found overwritten reg: %s:=0x%x', name, val)
        return modDict

    def prehook(self, emu, op, starteip):
        """
        This monitor hook gets called back prior to the execution of
        each instruction in the emulator.
        """
        #print 'Processing'
        try:
            self.logger.debug('prehook 0x%08x', starteip)
            for i, opnd in enumerate(op.getOperands()):
                #annoying -> lea's isDeref is turned off, so wee need to do -> do lots of type checks
                if (isinstance(opnd, e_i386.i386RegMemOper) or isinstance(opnd, e_i386.i386ImmMemOper) or isinstance(opnd, e_i386.i386SibOper)):
                    addr = opnd.getOperAddr(op, emu)
                    if self.objStuff.isObjPointer(addr):
                        delta = 0
                        if isinstance(opnd, e_i386.i386RegMemOper):
                            rval = emu.getRegister(opnd.reg)
                            delta = rval - self.objStuff.obj_pointer
                            self.logger.debug('i386RegMemOper: 0x%x - 0x%x: %x', rval, self.objStuff.obj_pointer, delta)
                        if isinstance(opnd, e_i386.i386SibOper):
                            rval = emu.getRegister(opnd.reg)
                            delta = rval - self.objStuff.obj_pointer
                            self.logger.debug('i386SibOper: 0x%x - 0x%x: %x', rval, self.objStuff.obj_pointer, delta)
                        self.logger.debug('prehook obj ref: 0x%08x %d: 0x%04x (0x%x)', starteip, i, self.objStuff.getObjOffset(addr), delta)
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
                        self.logger.debug('HACK!!! prehook obj ref: 0x%08x %d: 0x%04x (0x%x)', starteip, i, self.objStuff.getObjOffset(addr), delta)
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
                logger.debug('Examining: %s 0x%08x: 0x%08x: Yes', logname, eip, va)
                off = objStuff.getObjOffset(va)
                track.addObjWrite(eip, off, logBytes)
            else:
                logger.debug('Examining: %s 0x%08x: 0x%08x: No', logname, eip, va)
                
    for logname in ['readlog', ]:
        wlog = vg_path.getNodeProp(node, logname)
        for eip, va, logSz in wlog:
            if objStuff.isObjPointer(va):
                logger.debug('Examining: %s 0x%08x: 0x%08x: Yes', logname, eip, va)
                off = objStuff.getObjOffset(va)
                track.addObjRead(eip, off, logSz)
            else:
                logger.debug('Examining: %s 0x%08x: 0x%08x: No', logname, eip, va)

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
            self.defRegisterIdx = self.registers.index('ecx')
        elif self.codesize == 64:
            self.registers = X64_REGISTERS
            self.defRegisterIdx = self.registers.index('rcx')
        else:
            raise RuntimeError('Only x86 32-bit or x64 64-bit supported')
        self.selectedRegIdx = self.defRegisterIdx
        self.filterUserClass = True
        self.createVtable = True
        self.modifyExisting = False 
        self.pointerDelta = 0
        self.funcStart = 0
        self.currentAddress = 0
        self.structSize = 0
        self.useExisting = False
        self.useFunctionStart = False
        self.useCurrentAddress = False
        self.createNew = False
        self.useRegisterPointer = True
        self.existingStructName = None
        self.newStructName = None
        self.defaultNewStructName = ''
        self.userStructs = []
        self.existingStructInfo = []
        self.existingStructNames = []
        self.loadUserStructs()
        self.loadStructInfo()

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

    def runFunction(self):
        emu = self.initEmu()
        #orange TODO: it would be better to run from the start of the function regardless,
        # and just take results starting at 
        startEa = self.funcStart
        if self.useCurrentAddress:
            startEa = self.currentAddress

        if self.useRegisterPointer:
            self.logger.debug('Following register: %s', self.registers[self.selectedRegIdx])
            #account for specified user delta
            emu.setRegisterByName(self.registers[self.selectedRegIdx], self.obj_pointer+self.pointerDelta)
            regName = self.registers[self.selectedRegIdx]
            self.logger.debug('Followed regiser value: %s 0x%08x', regName, emu.getRegisterByName(regName))
        else:
            raise RuntimeError('Only register following supported at this time')

        self.logger.debug('Running function 0x%08x now. Following %s', startEa, self.registers[self.selectedRegIdx])

        emu.runFunction(startEa, maxhit=1, maxloop=1)
        tracker = emu.emumon.track
        self.logger.debug('Done. Examining emu paths now')
        jayutils.path_bfs(emu.path, obj_path_visitor, track=tracker, emu=emu, logger=self.logger, objStuff=self, objVa=self.obj_pointer)
        self.logger.debug('Logged info:') 
        for key in sorted(tracker.refs.keys()):
            for i, entry in enumerate(tracker.refs[key]):
                eip, offset, opIdx, delta = entry
                pad = '----'
                if i != 0:
                    pad = '    '
                self.logger.debug('%s0x%04x: 0x%08x %d 0x%x', pad, offset, eip, opIdx, delta)

        if self.createNew:
            self.createStruct(self.newStructName, tracker)
            #reload struct after creation
            self.loadUserStructs()
            self.loadStructInfo()
            self.markupStructUse(self.newStructName, tracker)
        else:
            self.markupStructUse(self.existingStructName, tracker)

    def updateStateFromDisplay(self):
        #grab 'transient' state, for use during focus-in events
        self.currEa = idc.here()
        self.funcStart = idc.GetFunctionAttr(idc.here(), idc.FUNCATTR_START)
        self.currentAddress = idc.here()
        
    def loadUserStructs(self):
        #store user structs as a ';' delimited string
        # actual struct info will/should be loaded along with other structs
        # in loadStructInfo
        curr = jayutils.queryIdbNetnode(USER_STRUCT_INFO)
        if curr is None:
            self.logger.debug('No user structs found')
            self.defaultNewStructName = 'cls1'
        else:
            self.logger.debug('Got existing user strings: <%s>', curr)
            #self.userStructs = curr.split(';')
            self.userStructs = []
            loadedStructs = curr.split(';')
            for name in loadedStructs:
                if idc.GetStrucIdByName(name) == idc.BADADDR:
                    self.logger.debug('Detected deleted user struct: %s', name)
                else:
                    self.logger.debug('User struct 0x%x: %s', idc.GetStrucIdByName(name), name)
                    self.userStructs.append(name) 
            #check if a user deleted a struct: update the built-in list
            if len(loadedStructs) != len(self.userStructs):
                cur = ';'.join(self.userStructs)
                jayutils.setIdbNetnode(USER_STRUCT_INFO, curr)
            i = 1
            nextName = 'cls%d' % i
            while any([name.startswith(nextName) for name in self.userStructs]):
                if i > 1000:
                    raise RuntimeError('No default name could be found!')
                i += 1
                nextName = 'cls%d' % i
            self.defaultNewStructName = nextName

    def addUserStruct(self, name):
        curr = jayutils.queryIdbNetnode(USER_STRUCT_INFO)
        if curr is None:
            curr = name
        else:
            curr = curr + ';' + name
        self.logger.debug('new user structs: %s', curr)
        jayutils.setIdbNetnode(USER_STRUCT_INFO, curr)

    def loadStructInfo(self):
        idx = idaapi.get_first_struc_idx()

        while idx != idc.BADADDR:
            tid = idaapi.get_struc_by_idx(idx)
            name = idaapi.get_struc_name(tid)
            self.existingStructInfo.append(StructInfo(name))
            idx = idaapi.get_next_struc_idx(idx)
        self.existingStructNames = [h.name for h in self.existingStructInfo]
        self.existingStructNames.sort()

    def createStruct(self, name, tracker):
        usedOffsets = []
        self.logger.debug("Trying to create struct: %s %s", type(name), str(name))
        if idc.GetStrucIdByName(name) != idc.BADADDR:
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
                self.logger.debug("Trying to add %02x: %02x", structId, off)
                size, numBytes = IDA_DATA_SIZES.get(tracker.getMemberSize(off))
                idc.AddStrucMember(structId, 'f_%02x' % off, off, idc.FF_DATA|size, -1, numBytes)
                usedOffsets.append(off)
        self.addUserStruct(name)

        #check for setting function pointers as well
        self.logger.debug('Starting up check for funcpointer members now. %d writelog entries', len(tracker.objWrites))
        for off, writelogs in tracker.objWrites.items():
            self.logger.debug('Checking offset 0x%02x writes (%d entries)', off, len(writelogs))
            ealist = []
            for eip, objOff, bytes in writelogs:
                codeptr = None
                if (len(bytes) == 4) and (self.codesize == 32):
                    codeptr = struct.unpack_from('<I', bytes)[0]
                elif (len(bytes) == 4) and (self.codesize == 64):
                    codeptr = struct.unpack_from('<Q', bytes)[0]
                else:
                    self.logger.debug('Skipping writebytes at 0x%08x', eip)
                    continue
                self.logger.debug('Examining possible member function pointer: 0x%08x (0x%08x)', eip, codeptr)
                flags = idaapi.getFlags(codeptr)
                if idc.isLoaded(codeptr) and idc.isCode(flags):
                    self.logger.debug('Found member funcpointer: 0x%08x (0x%08x)', eip, codeptr)
                    if not idc.hasName(flags): 
                        funcName = '%s_fptr_%08x' % (name, codeptr)
                        idc.MakeName(codeptr, funcName)
                    ealist.append(codeptr)
                else:
                    self.logger.debug('Nope, not loaded or not code: 0x%08x', codeptr)
            if len(ealist) > 0:
                commentList = []
                for ea in ealist:
                    commentList.append('0x%08x' % ea)
                idc.SetMemberComment(structId, off, '\n'.join(commentList), 1)
                idc.SetMemberName(structId, off, 'f_%02x_fptr' % off)

        #handle vtable stuff here
        if self.createVtable:
            self.logger.debug('Starting up vtable stuff now')
            entry = tracker.getDataWriteByOff(0)
            if entry is None:
                self.logger.error('User requested vtable creation, but no offset 0 writes found')
            else:
                eip, objOff, bytes = entry
                self.logger.info('Examining writeentry: 0x%08x(0x%02x): %s', eip, objOff, bytes.encode('hex'))
                #TODO64: vtbale check for qword write
                if len(bytes) >= 4:
                    if self.codesize == 32:
                        vtablePtr = struct.unpack_from('<I', bytes)[0]
                    elif self.codesize == 64:
                        vtablePtr = struct.unpack_from('<Q', bytes)[0]
                    else:
                        raise RuntimeError('bad codesize')
                    if idc.isLoaded(vtablePtr):
                        self.makeVtableStuff(name, vtablePtr)
                    else:
                        self.logger.debug('User requested vtable creation, but offset 0 write not a valid pointer (0x%08x)', vtablePtr)
        else:
            self.logger.debug('Nope. User does not want a vtable')

    def markupStructUse(self, name, tracker):
        structId = idc.GetStrucIdByName(name)
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

    def makeVtableStuff(self, name, startEa):
        try:
            vtableName = '%s_vtbl' % name
            fakeName = '%s_vtable' % name
            #vtableStructName = '%s_vtbl' % name
            self.logger.debug('Trying to make vtable: %s, 0x%08x', vtableName, startEa)
            vtableSize = self.calcVtableSize(startEa)
            if vtableSize == 0:
                self.logger.info('Skipping vtable creation as no valid vtable could be found (size=0)')
                return
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
                idc.SetMemberComment(structId, off, '0x%08x' % val, 1)
                flags = idaapi.getFlags(val)
                if idc.isLoaded(val) and idc.isCode(flags) and not idc.hasName(flags):
                    #if it's a valid address & doesn't have a name, make it
                    funcName = '%s_vfunc%02d' % (name, i)
                    idc.MakeName(val, funcName)
                    self.logger.debug('Making vtbl function name: 0x%08x %s', val, funcName)
                else:
                    self.logger.debug('Skipping vtbl function name: 0x%08x', val)
                count += 1
        except Exception, err:
            self.logger.exception('Error while trying to create vtable: %s', str(err))


