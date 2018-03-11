#! /usr/bin/env python3
__author__ = 'Ayush Prakash Senapati <a.p.senapati008@gmail.com>'

# Standard libraries
import inspect
import os
import signal
import socket
import sys
import threading
from datetime import datetime
import time

# Third party libraries
try:
    import psutil
    import pickle
    from Crypto.Random import random
except ImportError as e:
    print(e)
    print('[psutil, pickle, pycrypt] packages must '
          'be installed before running the application')
    print('Exiting application..')
    sys.exit(0)

# Local modules
from APIs.logging import Log
from APIs.logging import Color
from APIs.security import *

# Declare Global variables
TERMINATE = False
CLI_HASH = {}
KEY = ''

# Constants
TOKEN_CHAR_LIST = "abcdefghij!@#$%"


class Server(object):
    def __init__(self):
        self.HOST_IP = '0.0.0.0'
        self.HOST_PORT = '8080'
        self.MAX_USR_ACCEPT = '100'

    @staticmethod
    def show_help():
        """Show available commands"""
        msg = '''
        AVAILABLE COMMANDS:
        \h          Print these information
        \d          Set default configuration
        \sd         Show default configuration
        \sc         Show current configuration
        \sau        Show active users
        \sac        Show active chat rooms
        \ssi        Show socket info
        \sf         Shutdown server forcefully
        \sg         Shutdown server gracefully [Recommended]
        \monitor    Enables monitor mode'''
        print(msg)

    def show_config(self, type_='default'):
        """Responsible for showing default or active server configurations"""
        if type_ in ('active', 'ACTIVE'):
            msg = '''
            Active configuration of the server :
            HOST IP = ''' + self.HOST_IP + '''
            HOST PORT = ''' + self.HOST_PORT + '''
            MAX USER ALLOWED = ''' + self.MAX_USR_ACCEPT 
            logging.log('Showing Active server configuration')
        else:
            msg = '''
            Default configuration of the server:
            HOST IP = 0.0.0.0
            HOST PORT = 8080
            MAX USER ALLOWED = 100'''
        print(msg)

    def set_usr_config(self, parameters):
        """Used to set custom server configuration"""
        if parameters:
            if sys.argv[1] in ('-h', '--help'):
                self.show_help()
            try:
                self.HOST_IP = sys.argv[1]
                self.HOST_PORT = sys.argv[2]
                self.MAX_USR_ACCEPT = sys.argv[3]
            except Exception as e:
                logging.log(e)
                print('USAGE:\nscript ip_address port_number max_usr_accept')
                sys.exit(0)
        else:
            self.HOST_IP = input('Enter host IP : ')
            self.HOST_PORT = input('Enter host PORT : ')
            self.MAX_USR_ACCEPT = input(
                    'Enter max number of users server would accept : ')

    def update_active_users(self):
        """Updates active users' name"""
        self.user_list = []
        for cli_obj in CLI_HASH.values():
            self.user_list.append(cli_obj.userName)

    @staticmethod
    def signal_handler(*args):
        """Handles SIGINT/Ctrl-C signal"""
        print(' has been pressed.\n')

    @staticmethod
    def get_connection_stats():
        """Shows server socket information"""
        msg = f"{'LOCAL_IP'}:{'LOCAL_PORT'}\t{'REMOTE_IP'}:" \
              f"{'REMOTE_PORT'}{'STATUS':>10}\t{'PID':>5}"
        print(msg)
        print('-' * len(msg))
        for conn in psutil.net_connections():
            if conn.laddr.port == 8080 and conn.status != "LISTEN":
                print("{}:{}\t\t{}:{}\t\t{}\t{}".format(
                    conn.laddr.ip, conn.laddr.port, conn.raddr.ip,
                    conn.raddr.port, conn.status, conn.pid))

    def srv_prompt(self):
        """Provides a prompt to manage the server"""
        global TERMINATE
        while True:
            opt = input(Color.PURPLE +
                        '\nenter command $ ' + Color.ENDC).lower()
            if opt == '\h':
                self.show_help()
            elif opt == '\monitor':
                print('Monitoring mode ENABLED!')
                logging.silent_flag = False
                signal.signal(signal.SIGINT, self.signal_handler)
                signal.pause()
                print('Monitoring mode DISABLED')
                logging.silent_flag = True
            elif opt == '\sd':
                self.show_config(type_='default')
            elif opt == '\sc':
                self.show_config(type_='active')
            elif opt == '\sau':
                self.update_active_users()
                logging.log(self.user_list)
                print(self.user_list)
            elif opt == '\ssi':
                self.get_connection_stats()
            elif opt == '\sf':
                print(
                    Color.WARNING + 'WARNING: All users will be disconnected'
                                    ' with out any notification!!' +
                    Color.ENDC)
                opt = input('Do you really want to close server?[Y/N] ')
                if opt == 'Y':
                    logging.log('Shutting down server...')
                    print('Shutting down server...')
                    TERMINATE = True
                    return
                else:
                    logging.log('Aborted.')
                    print('Aborted.')
                    pass
            elif opt == '\sg':
                pass
            elif opt == '':
                pass
            else:
                print('COMMAND NOT FOUND!!\n'
                      'Enter [\h] to view all available commands')

    def init_clients(self):
        """ Accepts connection requests from clients and stores
        two parameters- 'conn' which is a socket object for that user,
        and 'addr' which contains the IP address of the client
        that just connected to the server.
        """
        global CLI_HASH
        # Break the loop and stop accepting connections
        # from the clients, when terminate command is entered 
        # in the server prompt.
        while not TERMINATE:
            try:
                # logging.log(CLI_HASH)
                # Timeout for listening
                self.server.settimeout(1)  

                # Accept connections from the clients.
                conn, addr = self.server.accept()
            except socket.timeout:
                pass
            except Exception as e:
                raise e
            else:
                logging.log(f'A connection from '
                            f'[{addr[0]}.{addr[1]}] has been received.')
                # Instantiate individual Client thread object
                # to do client related stuffs.
                cli_obj = Client(conn, addr, self)
            
                # Maintain a hash table for client thread objects,
                # where keys will be connection object and values will
                # be client thread object.
                CLI_HASH[conn] = cli_obj

                # Initialise a new thread for instantiated client object
                threading._start_new_thread(cli_obj.run, ('',))
        try:
            print('\t\tServer has stopped listening on opened socket.')
            print('\t\tBroadcasting connection termination signal..', end=' ')
            msg = "Sorry! We are unable to serve at this moment."
            for cli_socket in CLI_HASH.keys():
                try:
                    cli_socket.send(
                        AES_.encrypt(CLI_HASH[cli_socket].KEY, msg))
                except Exception as e:
                    logging.log(e, msg_type="EXCEPTION")
                    cli_socket.close()
                    CLI_HASH.pop(cli_socket)
        except Exception as e:
            logging.log(e, msg_type="EXCEPTION")
        print(Color.CYAN, '\tDone', Color.ENDC)

    def init(self):
        """
        Initializes the server application as per user inputs.
        """
        logging.log('Initializing server')
        if len(sys.argv) == 1:
            self.show_config(type_='default')
            opt = input('Set these default config?[Y/n] ')
            if opt == '':
                opt = 'Y'
            if opt in ('Y', 'y', 'yes', 'Yes', 'YES'):
                print("Setting up default configurations...")
            else:
                self.set_usr_config(parameters=False)
        else:
            self.set_usr_config(parameters=True)

        # create socket
        """The first argument AF_INET is the address domain of the
        socket. This is used when we have an Internet Domain with
        any two hosts The second argument is the type of socket.
        SOCK_STREAM means that data or characters are read in
        a continuous flow."""
    
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
        try:
            # Try to create server socket
            self.server.bind((self.HOST_IP, int(self.HOST_PORT)))
            self.server.listen(int(self.MAX_USR_ACCEPT))
        except OSError as e:
            tmp_msg = f"[Function: {inspect.stack()[0].function}] {e}"
            print(tmp_msg)
            logging.log(msg=str(tmp_msg), msg_type='EXCEPTION')
            print(
                'Unable to bind HOST IP and PORT.\n'
                'Please check your configuration')
            sys.exit('EMERGENCY')
        print(f'\nServer is listening at {self.HOST_IP}:{self.HOST_PORT}')
        print(f'Server is configured to accept {self.MAX_USR_ACCEPT} clients')

        """
        Create two threads thread_srv and thread_cli, where thread_srv
        will be responsible for handling server input and thread_cli will be
        responsible for handling users.
        """

        # thread_srv = threading.Thread(target=self.srv_prompt, args=())
        thread_cli = threading.Thread(target=self.init_clients, args=())

        # Server prompt can't start by a thread as it uses
        # signal module to handle CTRL-C signals.
        # thread_srv.start() # Start a thread for server prompt
        thread_cli.start()  # Start a thread to listening clients requests
        self.srv_prompt()
        print('\tserver prompt has been exited')

        print('\tWaiting for client threads to exit...')
        thread_cli.join(5)
        if thread_cli.is_alive():
            logging.log(f'Time out reached. '
                        f'Terminating {threading.active_count()} forcefully')
        print(Color.CYAN, '\tDone', Color.ENDC)
        print('\tServer and Client threads are exited successfully')


class Client(object):
    def __init__(self, conn, addr, srv_obj):
        self.srv_obj = srv_obj
        self.conn = conn
        self.addr = addr
        self.userName = '-N/A-'
        self.PUBLIC_KEY = None
        self.KEY = ''

    def validate_user(self):
        pass

    def features(self, msg):
        # Feature-1: User can get online users list
        if msg == '@getonline':
            self._loop_break_flag = True
            self.conn.send(
                    AES_.encrypt(self.KEY, str(self.srv_obj.user_list)))

        # Feature-2: User can send msg to individual user
        if msg.split()[0][1:] in self.srv_obj.user_list:
            self._loop_break_flag = True
            for _conn in CLI_HASH:
                if CLI_HASH[_conn].userName == msg.split()[0][1:]:
                    try:
                        self.ind_sock = _conn
                        msg_send = "<" + self.userName + "@" + self.addr[0] +\
                                   "> [IND] " + ' '.join(msg.split()[1:])
                        self.broadcast(msg_send, ind_flag=True)
                    except Exception as e:
                        tmp_msg = f"[Function: {inspect.stack()[0].function}]"\
                                  f"[User: {self.userName}] {e}"
                        logging.log(tmp_msg, msg_type="EXCEPTION")
                        tmp_msg = f"[Caller: {inspect.stack()[1].function}]" \
                                  f"[User: {self.userName}] {e}"
                        logging.log(tmp_msg, msg_type="EXCEPTION")

    def get_shared_key(self) -> type(tuple):
        """
        Generates unique 10bit symmetric key for each client,
        calculates MD5 hash and encrypts the hash using RSA
        and returns the shared_key and Encrypted(shared_key)
        """
        # Generate unique symmetric 10bit key for each client
        passphrase = ''.join(random.sample(TOKEN_CHAR_LIST, 10))

        # Get 32bit MD5 hash of random string generated above
        shared_key = hasher(passphrase)

        # Encrypt shared key with user's public key
        EnSharedKey = RSA_.encrypt(self.PUBLIC_KEY, shared_key)
        if EnSharedKey:
            return (shared_key, EnSharedKey)
        else:
            logging.log(
                "Unable to encrypt shared key with RSA.", msg_type='ERROR')

    def run(self, *args):
        data = self.conn.recv(4000)

        # get serialized data from received data and
        # load it to user_name and public key variables.
        # tuple object can't be sent over a network,
        # it needs to be serialized before sending.
        if data:
            self.userName, self.PUBLIC_KEY = pickle.loads(data)

        # Get unique shared/symmetric key and encrypt
        # it with RSA public key received from the user.
        if self.PUBLIC_KEY:
            # If public key is received from the user,
            # generate symmetric key for that user.
            self.KEY, EnSharedKey = self.get_shared_key()
        else:
            # If public key has not been received,
            # terminate the unsecured connection.
            tmp_conn = "{}:{}".format(self.addr[0], self.addr[1])
            logging.log(
                    "Public key has not been received from [{}@{}]".format(
                        self.userName, tmp_conn))
            logging.log(
                f"[0.0.0.0:8080 --> {tmp_conn}] Socket has been terminated ")
            self.remove()

        if self.KEY == '':
            logging.log("Symmetric key generation failed")

        tmp_msg = f"symmetric key {self.KEY} has been sent to {self.userName}"
        logging.log(tmp_msg)
        
        # As EnSharedKey is a tuple, serialize
        # it before sending it to the user.
        try:
            assert isinstance(EnSharedKey, tuple)
        except AssertionError as e:
            logging.log(msg=e, msg_type='EXCEPTION')
        EnSharedKey = pickle.dumps(EnSharedKey)
        self.conn.send(EnSharedKey)

        self.validate_user()
        
        msg = self.userName + " has joined the chatroom."
        logging.log(msg)
        self.broadcast("\n" + msg)

        # sends a message to the client whose user object is conn
        msg_send = "Welcome [" + self.userName + "] to this chatroom!"
        self.conn.send(AES_.encrypt(self.KEY, msg_send))

        while True:
            try:
                self._loop_break_flag = False
                msg = self.conn.recv(20000)
                msg = AES_.decrypt(self.KEY, msg)

                if msg:
                    if msg.split()[0][0] == '@':
                        self.srv_obj.update_active_users()
                        self.features(msg)

                    if not self._loop_break_flag:
                        # print the msg sent by user
                        log_msg = "<" + self.userName + "@" +\
                                  self.addr[0] + "> " + msg
                        logging.log(msg_type='CHAT', msg=log_msg)

                        # Call broadcast method to
                        # relay message to connected users
                        msg_send = "<" + self.userName + "@" +\
                                   self.addr[0] + "> " + msg
                        self.broadcast(msg_send)
                else:
                    # msg may have no content if the connection
                    # is broken, in that case remove the connection
                    self.remove()
                    pass
            except Exception as e:
                tmp_msg = f"[Function: {inspect.stack()[0].function}]" \
                          f"[User: {self.userName}] {e}"
                logging.log(tmp_msg, msg_type="EXCEPTION")
                try:
                    tmp_msg = f"[Caller: {inspect.stack()[1].function}]" \
                              f"[User: {self.userName}] {e}"
                    logging.log(tmp_msg, msg_type="EXCEPTION")
                except:
                    logging.log(
                        "No caller found for above exception",
                        msg_type="EXCEPTION")
                # self.remove()

    def broadcast(self, msg, ind_flag=False):
        """
        This method allows to both broadcasting
        messages to all connected users and to send message
        to a particular user if ind_flag is set.
        """
        if ind_flag:
            self.ind_sock.send(
                    AES_.encrypt(CLI_HASH[self.ind_sock].KEY, msg))
            return
        for cli_socket in CLI_HASH.keys():
            if cli_socket != self.conn:
                try:
                    tmp = "msg sent to " + CLI_HASH[cli_socket].userName +\
                          " encrypted with his unique KEY [" +\
                          CLI_HASH[cli_socket].KEY + "] "
                    logging.log(tmp)
                    cli_socket.send(
                            AES_.encrypt(CLI_HASH[cli_socket].KEY, msg))
                except Exception as e:
                    tmp_msg = f"[Function: {inspect.stack()[0].function}]" \
                              f"[User: {self.userName}] {e}"
                    logging.log(tmp_msg, msg_type="EXCEPTION")
                    tmp_msg = f"[Caller: {inspect.stack()[1].function}]" \
                              f"[User: {self.userName}] {e}"
                    logging.log(tmp_msg, msg_type="EXCEPTION")
                    cli_socket.close()
                    # If the link is broken, remove the client
                    self.remove()

    def remove(self):
        """
        This method checks if the connection registered
        to the thread is present in ClientHash table. If
        it is present then close the socket and if userName
        is assigned to the clientThread object, broadcast
        the user went offline, un-register the connection
        information from the ClientHash table and exit
        the thread.
        """
        if self.conn in CLI_HASH.keys():
            self.conn.close()
            if self.userName != "-N/A-":
                msg = str(CLI_HASH[self.conn].userName) + " went offline!"
                logging.log(msg)
                msg = "\n" + msg 
                self.broadcast(msg)
            CLI_HASH.pop(self.conn)
            self.srv_obj.update_active_users()
            logging.log(f"Active users list: {self.srv_obj.user_list}")
            sys.exit()


if __name__ == "__main__":
    # Call main function if the program is running as active program.
    try:
        """
        Check if the server application is running on Linux/Mac.
        If it's a Linux machine, no need of root privilege to
        fetch network connection stats from the kernel.
        If it's a Macintosh, application must start by root
        user to get connection information.
        """
        logging = Log(f_name='server_chatroom_' +
                             datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        logging.logging_flag = True
        logging.silent_flag = True
        logging.validate_file()
        # Checks if the OS is Linux
        if os.uname().sysname != 'Linux':
            # Checks if application is running by root user
            if os.getuid() != 0:
                print(
                    Color.WARNING + "WARNING: Program must be running "
                                    "with root user to monitor sockets." + 
                    Color.ENDC)
                logging.log(
                        "Application was not started with root privilege",
                        msg_type="WARNING")
                sys.exit(0)
        server = Server()
        server.init()
    except SystemExit as e:
        if e.code != 'EMERGENCY': 
            raise  # Normal exit, let unittest catch it
        else:
            print(sys.exc_info())
            print('Something went wrong!!\nPlease contact developers.')
            sys.exit(1)
    except:
        print(Exception)
        print(
            'Something went wrong!!\n'
            'Please contact developers\nTerminating the process forcefully..')
        time.sleep(1)
        sys.exit(1)
    finally:
        msg = 'logging has been stopped.'
        logging.log(msg)
        print(msg)
        print(Color.CYAN, 'Done', Color.ENDC)

