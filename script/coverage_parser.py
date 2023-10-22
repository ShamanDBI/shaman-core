import sys, os
from collections import defaultdict

REC_TYPE_MODULE = 0
REC_TYPE_BASIC_BLOCK = 1


class ParseCoverage:

    def __init__(self, coverage_file) -> None:
        self.cov_file = open(coverage_file, 'rb')
        self.mod_base_addr = dict()
        self.mod_map = dict()
        self.exec_info = defaultdict(lambda: defaultdict(lambda : 0))

    def _read_u64(self):
        return int.from_bytes(self.cov_file.read(8), byteorder='little')
    
    def _read_u32(self):
        return int.from_bytes(self.cov_file.read(4), byteorder='little')
    
    def _read_u16(self):
        return int.from_bytes(self.cov_file.read(2), byteorder='little')
    
    def _read_u8(self):
        return int.from_bytes(self.cov_file.read(1), byteorder='little')
    
    def _read_str(self, str_len):
        return self.cov_file.read(str_len).decode('utf-8')        
    
    def set_mod_base_addr(self, mod_name, base_addr):
        self.mod_base_addr[mod_name] = base_addr

    def parse(self):
        should_cont = True
        while should_cont:
            rec_type = self._read_u16()

            if rec_type == REC_TYPE_MODULE:
                mod_len = self._read_u16()
                mod_name = self._read_str(mod_len)
                mod_id = self._read_u16()
                # self.mod_base_addr[mod_name] = 0
                self.mod_map[mod_id] = mod_name
                # print('Module : {} - {}'.format(mod_name, mod_id))
            
            elif rec_type == REC_TYPE_BASIC_BLOCK:
                pid = self._read_u32()
                mod_id = self._read_u8()
                exec_offset = self._read_u32() + self.mod_base_addr[mod_name]
                self.exec_info[pid][exec_offset] += 1
                # print('Exec {} {} {} {}'.format(pid, mod_id, hex(exec_offset), self.exec_info[pid][exec_offset]))
            # val = input('Enter : ')
            # if val == 'q':
            #     break
            should_cont = self.cov_file.tell() != os.fstat(self.cov_file.fileno()).st_size

    def report(self):
        for key_pid, val in self.exec_info.items():
            for key_addr, val in self.exec_info[key_pid].items():
                print('{} | {} - {}'.format(key_pid, hex(key_addr), self.exec_info[key_pid][key_addr]))

def main(coverage_file):
    pp = ParseCoverage(coverage_file)
    pp.set_mod_base_addr('test_prog', 0x100000)
    pp.parse()
    pp.report()


main(sys.argv[1])