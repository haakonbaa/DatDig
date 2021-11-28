# Program for automation of codeunderstanding-tasks in the course TDT4160 -
# 'Datamaskiner og Digitalteknikk (DatDig)'. The program is meant to emulate
# and explain IJVM and simplified assembly instructions.

# Håkon Bårsaune - 28.11.21

import abc
from os import EX_CANTCREAT

def _to_imm(imm : str):
    try:
        if imm.startswith('0X'):
            return int(imm[2:],16)
        elif imm.startswith('#'):
            return int(imm[1:])
        else:
            return int(imm)
    except:
        return None

def _is_imm(val : str):
    return _to_imm(val) != None 

class AsmReg():
    def is_valid( val : str ):
        return val in Asm._REGISTERS

class AsmImm():
    def is_valid( val : str):
        return _is_imm(val)

class Asm():
    _REGISTERS = tuple(f'R{i}' for i in range(32))
    _ISA = {
        'LOAD'  : [AsmReg,AsmReg],
        'STORE' : [AsmReg,AsmReg],
        'ADD'   : [AsmReg,AsmReg,AsmReg],
        'NAND'  : [AsmReg,AsmReg,AsmReg],
        'OR'    : [AsmReg,AsmReg,AsmReg],
        'INV'   : [AsmReg,AsmReg],
        'INC'   : [AsmReg,AsmReg],
        'DEC'   : [AsmReg,AsmReg],
        'MUL'   : [AsmReg,AsmReg,AsmReg],
        'CMP'   : [AsmReg,AsmReg],
        'NOP'   : [],
        'MOVC'  : [AsmReg,AsmImm],
        'CP'    : [AsmReg,AsmReg],
        'BZ'    : [AsmReg],
        'BNZ'   : [AsmReg],
        'RT'    : []}

    def __init__(self):
        self.inst_mem = dict()
        self.data_mem = dict()
        self.reg = dict((reg,0) for reg in Asm._REGISTERS)
        self.pc = 0
        self.Z = True

    # Sets (appends and/or overwrites) data memory 
    def set_memory(self, memory : list | dict):
        try:
            if isinstance(memory,list):
                for location, value in memory:
                    self.data_mem[location] = value 
            elif isinstance(memory,dict):
                # validate
                for location,value in memory.items():
                    assert(isinstance(location,int))
                    assert(isinstance(value,int))
                    self.data_mem[location] = value
        except Exception as e:
            raise Exception(f'Invalid memory: {memory}')

    # Checks if an instruction is valid
    def decode_instruc(self, instruc : str, exec = False):
        if not instruc[0] in Asm._ISA.keys():
            return False
        params = Asm._ISA[instruc[0]]
        if len(params) != len(instruc)-1:
            return False
        for argtype, value in zip(params,instruc[1:]):
            if not argtype.is_valid(value):
                return False
        return True
    
    # Sets (appends and/or overwrites) instruction memory
    def set_instrucs(self, instrucs : str, pg_begin = 0, inc_loc = False):
        instrucs = instrucs.upper().replace(';','').replace(':','').replace(',','')
        for instruc in instrucs.split('\n'):
            if instruc == '':
                continue
            mem_loc = pg_begin
            pg_begin += 1
            instruc = instruc.strip().split(' ')
            if len(instruc) == 0:
                continue
            if inc_loc:
                if not _is_imm(mem_loc := instruc.pop(0)):
                    raise Exception(f'Invalid memory location in ' + \
                        f'instruction: {mem_loc} {instruc}')
                mem_loc = _to_imm(mem_loc)
            if len(instruc) == 0:
                raise Exception(f'Encountered bad command: is "{mem_loc}" a' + \
                    ' memory location?')
            if self.decode_instruc(instruc):
                self.inst_mem[mem_loc] = instruc
            else:
                raise Exception(f'Unknown command: {mem_loc}: {instruc}')
    
    def set_registers(self, regvals : list):
        try:
            if isinstance(regvals,list):
                for reg, val in regvals:
                    assert(isinstance(val,int))
                    assert(reg in Asm._REGISTERS)
                    self.reg[reg.upper()] = val
            elif isinstance(regvals,dict):
                for reg, val in regvals.items():
                    assert(isinstance(val,int))
                    assert(reg in Asm._REGISTERS)
                    self.reg[reg.upper()] = val
        except Exception as e:
            raise Exception(f'Could not set registers!: {e}')
    
    def __str__(self):
        lines = ["Memory:"]
        for memloc, value in sorted(self.data_mem.items(), key=lambda item: item[0]):
            lines.append(f'0x{memloc:08X}: 0x{value:08X}')
        lines.append('\nRegisters not 0:')
        for regname, value in sorted(self.reg.items(), key=lambda item: item[0][1:].rjust(4,'0')):
            if value != 0:
                lines.append(f'{regname:3}: 0x{value:08X}')
        lines.append("\nProgram:")
        for memloc, cmd in sorted(self.inst_mem.items(), key=lambda item: item[0]):
            lines.append(f'0x{memloc:08X}: {", ".join(cmd)}')
        return '\n'.join(lines)

    # Executes an already validated instruction
    def execute_instruc(self, *args ) -> str:
        desc = '' # description
        match args:
            case ['LOAD' ,ri,rj]:
                self.reg[ri] = self.data_mem[self.reg[rj]]
                return f'{ri} = 0x{self.reg[ri]:08X}'
            case ['STORE',ri,rj]:
                self.data_mem[self.reg[rj]] = self.reg[ri]
                return f'{self.reg[rj]} -> 0x{self.reg[ri]:08X}'
            case ['ADD'  ,ri,rj,rk]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj + rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} + 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['MUL'   ,ri,rj,rk]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj * rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} * 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['NAND' ,ri,rj,rk]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj & rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} & 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['OR'   ,ri,rj,rk]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj | rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} | 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['INV'  ,ri,rj]:
                rj = self.reg[rj]
                self.reg[ri] = ~rj
                self.Z = self.reg[ri] == 0
                return f'{ri} = ~{rj:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['INC'   ,ri,rj]:
                rj = self.reg[rj]
                self.reg[ri] = rj + 1
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} + 1 = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['DEC'   ,ri,rj]:
                rj = self.reg[rj]
                self.reg[ri] = rj - 1
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} - 1 = 0x{self.reg[ri]:08X} | z = {self.Z}'
            case ['CMP'   ,ri,rj]:
                if self.reg[ri] == self.reg[rj]:
                    self.Z = True
                return f'0x{self.reg[ri]:08X} ?= 0x{self.reg[rj]:08X} | z = {self.Z}'
            case ['CP'    ,ri,rj]:
                rj = self.reg[rj]
                self.reg[ri] = rj
                return f'{ri} = 0x{self.reg[ri]:08X}'
            case ['NOP']:
                pass
            case ['MOVC',ri,imm]:
                self.reg[ri] = _to_imm(imm)
                return f'{ri} = {_to_imm(imm)}'
            case ['BZ',ri]:
                if self.Z:
                    self.PC = self.reg[ri]-1
                return f'PC = {self.PC+1}'
            case ['BNZ',ri]:
                if not self.Z:
                    self.PC = self.reg[ri]-1
                return f'PC = {self.PC+1}'
            case ['RT']:
                Exception('RT not implemented')
            case _:
                raise Exception(f'Invalid command: {", ".join(args)}')


    def __call__( self , PC : int = 0, out : bool = False ):
        self.Z = 0
        self.N = 0
        self.PC = PC
        done = False
        if self.PC not in self.inst_mem:
            raise Exception(f'PC not pointing to an instruction!: {self.PC}')
        while not done:
            if self.PC in self.inst_mem:
                res = self.execute_instruc(*self.inst_mem[self.PC])
                if out:
                    cmd = ', '.join(self.inst_mem[self.PC])
                    print(f'{cmd.ljust(25)} {res}')
                self.PC += 1
            else:
                done = True

    def is_register(val:str):
        return val in Asm._REGISTERS

class IJVM():
    _REGISTERS = ('MAR','MDR','PC','MBR','SP','LV','CPP','TOS','OPC','H')

    def __init__( self ):
        pass

__all__ = ['Asm', 'IJVM']

if __name__ == '__main__':
    data = {0xFFFF0000:0x00000001,
        0xFFFF0001:0x00000002,
        0xFFFF0002:0x00000003,
        0xFFFF0003:0x00000004,
        0xFFFF0004:0xFFFF0005}

    registers = {'R0':0xFFFF0000, 
        'R1':0xFFFF0001, 
        'R3':0xFFFF0002, 
        'R4':0xFFFF0003, 
        'R5':0x00000004}
    
    code = r'''
0x0000FFFE: LOAD R8, R0; 
0x0000FFFF: INC R0, R0; 
0x00010000: LOAD R9, R0; 
0x00010001: INC R0, R0; 
0x00010002: LOAD R10, R0; 
0x00010003: INC R0, R0; 
0x00010004: LOAD R11, R0; 
0x00010005: MUL R8, R8, R9; 
0x00010006: MUL R9, R9, R10; 
0x00010007: MUL R10, R10, R11; 
0x00010008: ADD R8, R8, R9; 
0x00010009: ADD R8, R8, R10;'''

    emulator = Asm()
    emulator.set_memory(data)
    emulator.set_instrucs(code,inc_loc=True)
    emulator.set_registers(registers)
    print(emulator)
    emulator(PC=0x0000FFFE,out = True)
    print('\n\n',emulator)