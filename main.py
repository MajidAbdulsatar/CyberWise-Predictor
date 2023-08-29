import shlex
from scan_functions import scan
from map_functions import map_cve
from analyze_functions import analyze_and_predict
import time
def auto(args):
    if '-f' in args:
        NAMESPACE = args[args.index('-f') + 1] if '-f' in args else ""
        map_cve(NAMESPACE)
        time.sleep(2)
        analyze_and_predict(NAMESPACE)
        print("Start the automation from file level...")
    elif '-n' in args:
        NAMESPACE = args[args.index('-n') + 1] if '-n' in args else ""
        scan_call(NAMESPACE)
        time.sleep(2)
        map_cve(NAMESPACE)
        time.sleep(2)
        analyze_and_predict(NAMESPACE)
        print("Start the automation from name space level...")

def scan_call(args):
    name_index = args.index('-name') if '-name' in args else -1
    name = args[name_index + 1] if name_index != -1 else ""
    scan(namespace=name)

def map(args):
    NAMESPACE = args[args.index('-f') + 1]
    map_cve(NAMESPACE)

def analysis(args):
    file_name = args[args.index('-f') + 1] if '-f' in args else ""
    print(f"Analyzing file {file_name}...")
    analyze_and_predict(file_name)
def help():
    print("Instructions:")
    print("auto  [-f filename],[-n namespace]")
    print("scan -name [namespace]")
    print("map  [-f filename]")
    print("analysis -f [filename]")
    print("help")
    print("about")
    print("exit")

def about():
    print("Self-Adaptive Framework for Research Project!")  

def main():
    while True:
        try:
            command_line = input("> ")
            command_parts = shlex.split(command_line)

            if not command_parts:
                continue
            command = command_parts[0]
            if command == "scan":
                scan_call(command_parts[1:])
            elif command == "auto":
                auto(command_parts[1:])
            elif command == "map":
                map(command_parts[1:])
            elif command == "analysis":
                analysis(command_parts[1:])
            elif command == "help":
                help()
            elif command == "about":
                about()
            elif command == "exit":
                print("Exiting...")
                break
            else:
                print(f"Unknown command: {command}, use help to discover the options")

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
