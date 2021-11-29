# Program for automation of codeunderstanding-tasks in the course TDT4160 -
# 'Datamaskiner og Digitalteknikk (DatDig)'. The program is meant to emulate
# and explain IJVM and simplified assembly instructions.

# Håkon Bårsaune - 28.11.21

class AsmType():    
    def __init__(self):
        self.value = 0
    
    def __str__(self):
        return f'0x{self.value:08X}'
    
    def __repr__(self):
        return f'{self.__class__.__name__} \'{self.__str__()}\''

class AsmReg(AsmType):
    REGISTERS = tuple(f'R{i}' for i in range(32))

    def __init__(self, value : str):
        assert(value in AsmReg.REGISTERS)
        self. value = value
    
    def make(value : str) -> tuple[bool,AsmType]:
        if value not in AsmReg.REGISTERS:
            return False, AsmReg("R0")
        return True, AsmReg(value)

    def __str__(self):
        return f'{self.value}'

    
class AsmImm(AsmType):
    def __init__(self, value : int ):
        assert(isinstance(value,int))
        self.value = value

    def make(value : str) -> tuple[bool,AsmType]:
        value = value.upper()
        try:
            if value.startswith('0X'):
                return True, AsmImm(int(value[2:],16))
            elif value.startswith('#'):
                return AsmImm.make((value[1:]))
            else:
                return True, AsmImm(int(value))
        except Exception as e:
            return False,AsmImm(0)

class Asm():
    _ISA = (
        ('LOAD'  , (AsmReg,AsmReg)),
        ('LDR'   , (AsmReg,AsmReg)),
        ('STORE' , (AsmReg,AsmReg)),
        ('STR'   , (AsmReg,AsmReg)),
        ('ADD'   , (AsmReg,AsmReg,AsmReg)),
        ('ADD'   , (AsmReg,AsmReg,AsmImm)),
        ('ADD'   , (AsmReg,AsmImm)),
        ('SUB'   , (AsmReg,AsmReg,AsmReg)),
        ('SUB'   , (AsmReg,AsmReg,AsmImm)),
        ('SUB'   , (AsmReg,AsmImm)),
        ('NAND'  , (AsmReg,AsmReg,AsmReg)),
        ('OR'    , (AsmReg,AsmReg,AsmReg)),
        ('INV'   , (AsmReg,AsmReg)),
        ('INC'   , (AsmReg,AsmReg)),
        ('DEC'   , (AsmReg,AsmReg)),
        ('MUL'   , (AsmReg,AsmReg,AsmReg)),
        ('CMP'   , (AsmReg,AsmReg)),
        ('CMP'   , (AsmReg,AsmImm)),
        ('NOP'   , tuple()),
        ('MOVC'  , (AsmReg,AsmImm)),
        ('MOV'   , (AsmReg,AsmImm)),
        ('MOV'   , (AsmReg,AsmReg)),
        ('CP'    , (AsmReg,AsmReg)),
        ('BZ'    , (AsmReg,)),
        ('BNZ'   , (AsmReg,)),
        ('BEQ'   , (AsmImm,)),
        ('BEQPC' , (AsmImm,)),
        ('BNEQPC', (AsmImm,)),
        ('RT'    , tuple()))
    _OPCODES = tuple(code for code, _ in _ISA)

    def __init__(self):
        self.inst_mem = dict()
        self.data_mem = dict()
        self.reg = dict((reg,0) for reg in AsmReg.REGISTERS)
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

    # Checks if an instruction is valid and reeturns parameters
    def decode_instruc(self, instruc : list) -> tuple[bool,tuple]:
        if instruc[0] not in Asm._OPCODES:
            return False, tuple()
        for opcode, asmtypes in Asm._ISA:
            if (instruc[0] == opcode) and (len(asmtypes) == len(instruc)-1):
                decoded_instruc = [opcode]
                valid = False
                for i,asmtype in enumerate(asmtypes):
                    valid, value = asmtype.make(instruc[1+i])
                    if valid:
                        decoded_instruc.append(value)
                    else:
                        break
                if valid:
                    return True, tuple(decoded_instruc)
        return False, tuple()
    
    # Sets (appends and/or overwrites) instruction memory
    def set_instrucs(self, instrucs : str, pg_begin = 0, inc_loc = False) -> None:
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
                if not AsmImm.make(mem_loc := instruc.pop(0))[0]:
                    raise Exception(f'Invalid memory location in ' + \
                        f'instruction: {mem_loc} {instruc}')
                mem_loc = AsmImm.make(mem_loc)[1].value
            if len(instruc) == 0:
                raise Exception(f'Encountered bad command: is "{mem_loc}" a' + \
                    ' memory location?')
            valid, decoded_instruc = self.decode_instruc(instruc)
            if valid:
                self.inst_mem[mem_loc] = decoded_instruc
            else:
                raise Exception(f'Unknown command: {mem_loc}: {instruc}')
    
    def set_registers(self, regvals : list):
        try:
            if isinstance(regvals,list):
                for reg, val in regvals:
                    assert(isinstance(val,int))
                    assert(reg in AsmReg.REGISTERS)
                    self.reg[reg.upper()] = val
            elif isinstance(regvals,dict):
                for reg, val in regvals.items():
                    assert(isinstance(val,int))
                    assert(reg in AsmReg.REGISTERS)
                    self.reg[reg.upper()] = val
        except Exception as e:
            raise Exception(f'Could not set registers!: {e}')
    
    def __str__(self):
        lines = self.print_memory(return_str=True)
        lines.append("\nProgram:")
        for memloc, cmd in sorted(self.inst_mem.items(), key=lambda item: item[0]):
            lines.append(f'0x{memloc:08X}: {", ".join(str(arg) for arg in cmd)}')
        return '\n'.join(lines)

    def print_memory(self,return_str = False):
        lines = ["Memory:"]
        for memloc, value in sorted(self.data_mem.items(), key=lambda item: item[0]):
            lines.append(f'0x{memloc:08X}: 0x{value:08X}')
        lines.append('\nRegisters not 0:')
        for regname, value in sorted(self.reg.items(), key=lambda item: item[0][1:].rjust(4,'0')):
            if value != 0:
                lines.append(f'{regname:3}: 0x{value:08X}')
        lines.append('')
        if return_str:
            return lines
        else:
            print('\n'.join(lines))

    # Executes an already validated instruction
    def execute_instruc(self, *args ) -> str:
        match args:
            case ['LOAD' | 'LDR',AsmReg(value=ri),AsmReg(value=rj)]:
                self.reg[ri] = self.data_mem[self.reg[rj]]
                return f'{ri} = 0x{self.reg[ri]:08X}'

            case ['STORE' | 'STR',AsmReg(value=ri),AsmReg(value=rj)]:
                self.data_mem[self.reg[rj]] = self.reg[ri]
                return f'0x{self.reg[rj]:08X} -> 0x{self.reg[ri]:08X}'

            case ['ADD'  ,AsmReg(value=ri),AsmReg(value=rj),AsmReg(value=rk)]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj + rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} + 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['ADD'  ,AsmReg(value=ri),AsmReg(value=rj),AsmImm(value=imm)]:
                rj, imm = self.reg[rj], imm
                self.reg[ri] = rj + imm
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} + 0x{imm:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            
            case ['ADD'  ,AsmReg(value=ri),AsmImm(value=imm)]:
                self.reg[ri] = self.reg[ri] + imm
                self.Z = self.reg[ri] == 0
                return f'{ri} += 0x{imm:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            
            case ['SUB'  ,AsmReg(value=ri),AsmReg(value=rj),AsmReg(value=rk)]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj - rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} - 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['SUB'  ,AsmReg(value=ri),AsmReg(value=rj),AsmImm(value=imm)]:
                rj, imm = self.reg[rj], imm
                self.reg[ri] = rj - imm
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} - 0x{imm:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'
            
            case ['SUB'  ,AsmReg(value=ri),AsmImm(value=imm)]:
                self.reg[ri] = self.reg[ri] - imm
                self.Z = self.reg[ri] == 0
                return f'{ri} -= 0x{imm:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['MUL'   ,AsmReg(value=ri),AsmReg(value=rj),AsmReg(value=rk)]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj * rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} * 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['NAND' ,AsmReg(value=ri),AsmReg(value=rj),AsmReg(value=rk)]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj & rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} & 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['OR'   ,AsmReg(value=ri),AsmReg(value=rj),AsmReg(value=rk)]:
                rj, rk = self.reg[rj], self.reg[rk]
                self.reg[ri] = rj | rk
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} | 0x{rk:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['INV'  ,AsmReg(value=ri),AsmReg(value=rj)]:
                rj = self.reg[rj]
                self.reg[ri] = ~rj
                self.Z = self.reg[ri] == 0
                return f'{ri} = ~{rj:08X} = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['INC'   ,AsmReg(value=ri),AsmReg(value=rj)]:
                rj = self.reg[rj]
                self.reg[ri] = rj + 1
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} + 1 = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['DEC'   ,AsmReg(value=ri),AsmReg(value=rj)]:
                rj = self.reg[rj]
                self.reg[ri] = rj - 1
                self.Z = self.reg[ri] == 0
                return f'{ri} = 0x{rj:08X} - 1 = 0x{self.reg[ri]:08X} | z = {self.Z}'

            case ['CMP'   ,AsmReg(value=ri),AsmReg(value=rj)]:
                if self.reg[ri] == self.reg[rj]:
                    self.Z = True
                return f'0x{self.reg[ri]:08X} ?= 0x{self.reg[rj]:08X} | z = {self.Z}'

            case ['CMP'   ,AsmReg(value=ri),AsmImm(value=imm)]:
                if self.reg[ri] == imm:
                    self.Z = True
                return f'0x{self.reg[ri]:08X} ?= 0x{imm:08X} | z = {self.Z}'

            case ['CP'    ,AsmReg(value=ri),AsmReg(value=rj)]:
                rj = self.reg[rj]
                self.reg[ri] = rj
                return f'{ri} = 0x{self.reg[ri]:08X}'

            case ['NOP']:
                pass

            case ['MOVC',AsmReg(value=ri),AsmImm(value=imm)]:
                self.reg[ri] = imm
                return f'{ri} = 0x{imm:08X}'
            
            case ['MOV',AsmReg(value=ri),AsmReg(value=rj)]:
                self.reg[ri] = self.reg[rj]
                return f'{ri} = 0x{self.reg[ri]:08X}'
            
            case ['MOV',AsmReg(value=ri),AsmImm(value=imm)]:
                self.reg[ri] = imm
                return f'{ri} = 0x{self.reg[ri]:08X}'

            case ['BZ',AsmReg(value=ri)]:
                if self.Z:
                    self.PC = self.reg[ri]-1
                return f'PC = 0x{self.PC+1:08X}'

            case ['BNZ',AsmReg(value=ri)]:
                if not self.Z:
                    self.PC = self.reg[ri]-1
                return f'PC = 0x{self.PC+1:08X}'
            
            case ['BEQPC',AsmImm(value=imm)]:
                if self.Z:
                    self.PC = self.PC+imm-1
                return f'PC = 0x{self.PC+1:08X}'

            case ['BNEQPC',AsmImm(value=imm)]:
                if not self.Z:
                    self.PC = self.PC+imm-1
                return f'PC = 0x{self.PC+1:08X}'

            case ['RT']:
                Exception('RT not implemented')

            case _:
                raise Exception(f'Invalid command: {", ".join(str(arg) for arg in args)}')


    def __call__( self , PC : int = 0, out : bool = False ):
        self.Z = 0
        self.N = 0
        self.PC = PC
        done = False
        if self.PC not in self.inst_mem:
            raise Exception(f'PC not pointing to an instruction!: {self.PC}')
        while not done:
            if self.PC in self.inst_mem:
                cmd = ''
                try:
                    cmd += f'{self.PC:08X}: {", ".join(str(arg) for arg in self.inst_mem[self.PC])}'
                    res = self.execute_instruc(*self.inst_mem[self.PC])
                except KeyError as e:
                    print('{e} Did you remember to load all registers?')
                    res = ''
                if out:
                    print(f'{cmd.ljust(40)} {res}')
                self.PC += 1
            else:
                done = True

__all__ = ['Asm']

if __name__ == '__main__':
    pass