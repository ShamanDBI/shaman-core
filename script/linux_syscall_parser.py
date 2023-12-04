import re
import sys

'''
This script extracts the system call table form the Linux Kernel Source.
We need to write our own parser because the we convert the sycall number
for different architecture to standard sycall number which is then handled
by the system call tracing engine.
'''

class Syscall:
    name = 'NO_SYSCALL'
    arm_num = -1
    arm64_num = -1
    x86_num = -1
    amd64_num = -1

    def __init__(self, _name) -> None:
        self.name = _name
    
    def __repr__(self) -> str:
        return '{} {} {} | {} {}'.format(self.name, self.x86_num, self.amd64_num, self.arm_num, self.arm64_num)


def parse_syscall_file(syscall_file_path, arch_name, arch_dict):

    syscall_fd = open(syscall_file_path)

    for syscall_line in syscall_fd:
        if syscall_line[0] == '#' or len(syscall_line) <= 1:
            continue
        grp_match = re.search('(\d+)\s+(\w+)\s+(\w+)', syscall_line)

        if grp_match:
            call_no, abi, call_name = grp_match.groups()
            # print(call_name, hasattr(arch_dict, call_name))
            if call_name not in arch_dict:
                arch_dict[call_name] = Syscall(call_name)
            setattr(arch_dict[call_name], arch_name + '_num', call_no)
            # print(getattr(arch_dict[call_name], arch_name + '_num'))
        else:
            print('Failed to parse :', syscall_line, len(syscall_line))
    
    syscall_fd.close()


def main():

    arch_file = {
        'x86': './syscall_x86.tbl', 
        'amd64': './syscall_amd64.tbl',
        'arm': './syscall_arm.tbl'
    }

    cross_arch_syscall = dict()

    for arch_name, syscall_file in arch_file.items():
        print('Parsing', arch_name, syscall_file)
        parse_syscall_file(syscall_file, arch_name, cross_arch_syscall)

    for syscall_obj in cross_arch_syscall.items():
        print(syscall_obj[1])

if __name__ == '__main__':
    main()
