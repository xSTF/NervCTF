from sys import exit, argv

EMPTY_VAL = "ERROR: value must not be empty.\n"
NOT_OPTION = "ERROR: value must be one of the options above.\n"
NEG_NUM = "ERROR: value must not be below 0.\n"
NOT_PATH = "ERROR: u must provide an absolute path.\n"
NOT_FLAG = "ERROR: ur missing either '{' or '}' in the flag.\n"
NOT_NUM = "ERROR: expected a number.\n"
NO_ELEMS = "ERROR: at least one element must be provided.\n"

# aux functions 

def get_input_till(prompt, is_valid, error_msg, lower=1):
    while True: 
        inp = input(prompt)
        if lower: 
            inp = inp.lower()

        valid, inp = is_valid(inp)
        if not valid: 
            print(error_msg)
        else: 
            break

    return inp

def not_empty(x): 
    return x != "", x

def is_in(x, arr, df=""): 
    if df != "" and x == "": 
        x = df
    return x in arr, x 

def is_ae(x, val, df=0): 
    if x == "" and df is not None: 
        x = df
    else:
        try: 
            x = int(x)
        except ValueError: 
            return False, x 

    return x >= val, x 

def is_path(path, is_abs=True): 
    if b'\0' in path.encode() or not path.strip().startswith('/'): 
        return False, path

    return True, path

def valid_flag(flag): 
    if flag == "" or '{' not in flag or '}' not in flag: 
        return False, flag 

    return True, flag

def print_header(title): 
    to_print = "=== "
    to_print += f"{title} " 
    to_print = to_print.ljust(50, '=')
    print(to_print)

def print_caption(caption): 
    print(caption.rjust(50, ' '))

def get_list(get_ints=0): 
    list = []
    newline = 0 
    while True: 
        line = input('- ')
        if line == "":
            if list == []: 
                print(NO_ELEMS)
                continue
            else: 
                break

        if get_ints: 
            try: 
                line = int(line) 
            except ValueError: 
                print(NOT_NUM)
                continue

        list.append(line)

    return list 


# main functions 
        
def build_file(exists, info, is_dynamic, is_instance):
    with open("challenge.yml", "w") as f: 
        indented_desc = "\n".join(f"  {l}" for l in info["desc"].splitlines()) 

        f.write(f'name: "{info['chall']}"\n')
        f.write(f'author: "{info['author']}"\n')
        f.write(f'category: {info['cat']}\n')
        f.write(f'description: |\n{indented_desc}\n')
        f.write(f'value: {info['max']}\n')
        f.write(f'type: {info['type']}\n')
        f.write(f'state: {info['state']}\n')

        if is_dynamic: 
            f.write("extra:\n")
            f.write(f"  initial: {info['max']}\n")
            f.write(f"  decay: {info['decay']}\n")
            f.write(f"  minimum: {info['min']}\n")
        if 'decay_func' in info: 
            f.write(f"  decay_function: {info['decay_func']}\n")

        if is_instance:
            f.write("instance:\n")
            f.write(f"  backend: {info['backend']}\n")
            if info['backend'] == "docker": 
                f.write("  image: .\n")
            elif info['backend'] == "compose": 
                f.write(f"  compose_file: {info['comp_path']}\n")
                f.write(f"  compose_service: {info['ports'][0][0]}\n")

            if len(info['ports']) == 1: 
                f.write(f"  internal_ports: {info['ports'][0][1]}\n")
            else: 
                f.write("  service_ports:\n") 
                for s, ps in info['ports']: 
                    to_add = f"{s}: {ps}"
                    f.write(f"    {to_add}\n")

            f.write(f"  connection: {info['con']}\n")
            f.write(f"  timeout_minutes: {info["timeout"]}\n")

            if info['flag_mode'] == "random": 
                f.write("  flag_mode: random\n")
                f.write(f'  flag_prefix: "{info['flags'][0][:-1]}"\n')
                f.write('  flag_suffix: "}"\n')
                f.write(f"  random_flag_length: {info['hash_len']}\n")
                f.write(f"  flag_delivery: {info['del_type']}\n")

                if info['del_type'] == 'file': 
                    f.write(f"  flag_file_path: {info['flag_path']}\n")
                    if info['backend'] == 'compose': 
                        f.write(f"  flag_service: {info['ports'][0][0]}\n")
                        
            if 'max_renew' in info: 
                f.write(f"  max_renewals: {info['max_renew']}\n")
            if 'cmd' in info: 
                f.write(f'  command: "{info['cmd']}"\n')

        if info['flag_mode'] == "static":
            f.write("flags:\n")
            for fl in info['flags']: 
                f.write(f"  - {fl}\n")
        
        f.write("tags:\n")
        for tg in info['tags']: 
            f.write(f"  - {tg}\n")

        if 'files' in info:   
            f.write("files:")
            for fi in info['files']: 
                f.write(f"   - {fi}")

        if 'hints' in info:   
            f.write("hints:")
            for h in info['hints']: 
                f.write(f'   - {{ content: "{h.content}", cost: {h.cost} }}')

        if 'req' in info:   
            f.write("requirements:")
            for r in info['req']: 
                f.write(f'   - "{r}"')

        if 'attempts' in info:   
            f.write(f"attempts: {info['attempts']}")

        f.write('version: "0.3"\n')
    

# required functions 

def get_ports(): 
    print_header("Port(s)") 
    print_caption("1 per line, empty line to finish")

    return get_list(get_ints=1)

def get_services(): 
    print_header("Compose Services")
    print_caption("services you want players to access")
    print_caption("1 per line, empty line to finish")

    return get_list()

def get_flag_info(): 
    mode = None 
    hash_len = None 
    del_type = None 
    path = None 

    # flag mode
    print_header("Flag Mode") 
    valid = ['static', 'random']
    default = 'random'
    print_caption(', '.join(valid))

    mode = get_input_till(
            f'[Enter] for {default} > ',
            lambda x: is_in(x, valid, df=default), 
            NOT_OPTION)

    if mode == "random": 
        print_header("Hash Length")
        print_caption(">= 0")
        default = 8
        hash_len = get_input_till(
                f'[Enter] for {default} > ',
                lambda x: is_ae(x, 0, df=8), 
                NEG_NUM)

        print_header("Delivery Mode") 
        valid = ['env', 'file']
        print_caption(', '.join(valid))
        del_type = get_input_till(
                f'> ',
                lambda x: is_in(x, valid), 
                NOT_OPTION)

        if del_type == "file":
            print_header("Flag Path") 
            path = get_input_till(
                    f'> ',
                    is_path, 
                    NOT_PATH, 
                    lower=0)

    return mode, hash_len, del_type, path

def get_compose_info(): 
    print_header("Compose File")
    file = input("> ")

    if file == "":
        print("\n\nERROR: Compose File must not be empty.")

    servs = get_services()

    config = {}
    print_header("Ports for Services")
    print_caption("1 per line, empty line to finish")
    for s in servs: 
        print(f"> {s}")

        ports = []
        while True: 
            line = input("- ")

            if line == "": 
                break

            try: 
                line = int(line) 
            except ValueError: 
                print(NOT_NUM)
                continue 
                
            ports.append(line)

        config[s] = ports

    return file, config

def get_instance_info(): 
    # flag mode 
    flag_mode, len, del_type, flag_path = get_flag_info() 

    # timeout
    print_header("Timeout")
    print_caption(">= 0")
    timeout = input('[Enter] for 45 > ')

    if timeout == "": 
        timeout = "45"

    timeout = int(timeout)
    if timeout < 0: 
        print("\n\nERROR: Timeout must be above 0.")

    # connection type 
    print_header("Connection") 
    print_caption("nc, http, ssh") 
    con = input('[Enter] for nc > ').lower()

    if con == "": 
        con = "nc"

    if con not in ["nc", "ssh", "http"]: 
        print("\n\nERROR: Connection must be one of the options above.") 

    # backend 
    print_header("Backend") 
    print_caption("docker, compose, lxc, vagrant") 
    backend = input('> ').lower()

    if backend not in ["docker", "compose", "lxc", "vagrant"]: 
        print("\n\nERROR: Backend must be one of the options above.") 

    if backend == "compose":
        comp_path, config = get_compose_info()

        ports = []
        for s, p in config.items(): 
            ports.append((s, p))

        return flag_mode, len, del_type, flag_path, timeout, backend, con, comp_path, ports
    else: 
        ports = [("app", get_ports())]
        return flag_mode, len, del_type, flag_path, timeout, backend, con, None, ports

def get_general_info():
    # challenge name 
    print_header("Challenge Name")   
    chall = get_input_till('> ', not_empty, EMPTY_VAL, lower=0)

    # author name 
    print_header("Author") 
    author = get_input_till('> ', not_empty, EMPTY_VAL, lower=0)

    # category  
    print_header("Category") 
    category = get_input_till('> ', not_empty, EMPTY_VAL, lower=0)

    # description  
    print_header("Description") 
    print_caption("2 empty lines to finish") 
    
    lines = []
    newline = 0 
    while True: 
        line = input()
        if line == "":
            if newline == 1: 
                break
            newline = 1
        else: 
            newline = 0
        lines.append(line)
            
    while lines and lines[-1] == "": 
        lines.pop()

    lines.append(f"\nCreated by {author}")
    description = "\n".join(lines)

    # type 
    print_header("Type") 
    valid = ['instance', 'standard', 'dynamic']
    default = 'instance'

    print_caption(", ".join(valid)) 

    type = get_input_till(
            f"[Enter] for {default} > ",
            lambda x: is_in(x, valid, df=default),
            NOT_OPTION)

    # state 
    print_header("State") 
    valid = ['visible', 'hidden']
    default = 'visible'

    print_caption(', '.join(valid)) 

    state = get_input_till(
            f"[Enter] for {default} > ",
            lambda x: is_in(x, valid, df=default),
            NOT_OPTION)

    return chall, author, category, description, type, state

def get_scoring(): 
    # chall max
    print_header("Max Score") 
    print_caption(f">= 0") 
    default = 500
    max = get_input_till(
            f"[Enter] for {default} > ",
            lambda x: is_ae(x, 0, df=default), 
            NEG_NUM)
    
    print_header("Dynamic Scoring")
    valid = ['y', 'n']
    default = 'y'
    print_caption("y/n")

    is_dynamic = get_input_till(
            "[Enter] for y > ", 
            lambda x: is_in(x, valid, df=default),
            NOT_OPTION)
    is_dynamic = True if is_dynamic == "y" else False

    if is_dynamic:
        # chall min
        print_header("Min Score")
        print_caption(">= 0")
        default = 50
        min = get_input_till(
                f"[Enter] for {default} > ",
                lambda x: is_ae(x, 0, df=default), 
                NEG_NUM)

        # chall decay
        print_header("Decay")
        print_caption(">= 0")
        default = 10
        decay = get_input_till(
                f"[Enter] for {default} > ",
                lambda x: is_ae(x, 0, df=default), 
                NEG_NUM)

        return max, is_dynamic, min, decay

    return max, is_dynamic, None, None

def get_flags(type): 
    # instance can only have one flag as they can be randomized 
    if type == "instance": 
        print_header("Flag")
        flag = get_input_till(
                f"> ", 
                lambda x: valid_flag(x), 
                NOT_FLAG,
                lower=0)

        return [flag] 

    print_header("Flag(s)")
    print_caption("1 per line, empty line to finish")

    return get_list()

def get_tags(): 
    print_header("Tag(s)")
    print_caption("1 per line, empty line to finish")

    return get_list()


# extra functions 

def get_max_renewals(): 
    print_header("Max Renewals")
    print_caption(">= 0")

    renew = get_input_till(
            "> ", 
            lambda x: is_ae(x, 0), 
            NEG_NUM)

    return renew

def get_command(): 
    print_header("Command")

    cmd = get_input_till(
            "> ", 
            lambda x: not_empty(x), 
            EMPTY_VAL, 
            lower=0)

    return cmd

def get_decay_func(): 
    print_header("Decay Function")
    valid = ['logarithmic', 'linear']
    default = 'logarithmic'
    print_caption(', '.join(valid))

    func = get_input_till(
            f"[Enter] for {default} > ", 
            lambda x: is_in(x, valid, df=default), 
            EMPTY_VAL)

    return func

def get_requirements(): 
    print_header("Requirement(s)")
    print_caption("1 per line, empty line to finish")

    return get_list()

def get_files(): 
    print_header("Handout")
    print_caption("1 file per line, empty line to finish")

    return get_list()

def get_hints(): 
    print("Hint(s):")

    hints = []
    while True: 
        print("Content:") 
        content = input()

        print("Cost:") 
        cost = int(input())

        if cost < 0: 
            print("\n\nERROR: Hint cost must be above 0.") 

        hints.append({ "content": content, "cost": cost })
        
        print("More hints? y/[n]")

        if input() != "y": 
            break

    return hints

def get_max_attempts(): 
    print_header("Attempts")
    default = 3 

    n_at = get_input_till(
            f"[Enter] for {default} > ", 
            lambda x: is_ae(x, 0),
            NEG_NUM)

    return n_at

if __name__ == '__main__': 
    if "--help" in argv: 
        print("""
FLAGS: 
-h - set hints 
-f - set handout files 
-r - set required challenges 
-a - set max attempts
--max-renew - set max renewals
-c - set command
--df - set decay function
        """)
        exit(0) 

    info = {}

    exists = True
    is_instance = False

    chall, author, category, description, type, state = get_general_info()
    info['chall'] = chall
    info['author'] = author
    info['cat'] = category
    info['desc'] = description
    info['type'] = type
    info['state'] = state

    max, is_dynamic, min, decay = get_scoring()
    info['max'] = max
    info['min'] = min
    info['decay'] = decay

    flags = get_flags(type)
    tags = get_tags()
    info['flags'] = flags
    info['tags'] = tags

    if type == "instance":
        is_instance = True
        flag_mode, hash_len, del_type, flag_path, timeout, backend, con, comp_path, ports = get_instance_info() 
        info['flag_mode'] = flag_mode
        info['hash_len'] = hash_len
        info['del_type'] = del_type
        info['flag_path'] = flag_path
        info['timeout'] = timeout
        info['backend'] = backend
        info['con'] = con
        info['comp_path'] = comp_path
        info['ports'] = ports

    if '-f' in argv: 
        info['files'] = get_files()
    if '-h' in argv: 
        info['hints'] = get_hints() 
    if '-r' in argv: 
        info['req'] = get_requirements() 
    if '-a' in argv: 
        info['attempts'] = get_max_attempts() 
    if '--max-renew' in argv: 
        max_renew = get_max_renewals()
        info['max_renew'] = max_renew 
    if '-c' in argv: 
        info['cmd'] = get_command()
    if '--df' in argv: 
        info['decay_func'] = get_decay_func()

    build_file(exists, info, is_dynamic, is_instance)

