#! /usr/bin/env python3
__author__ = 'Ayush Prakash Senapati <a.p.senapati008@gmail.com>'

import os
import sys
import socket

import getpass
import select
import signal
import threading
import time
from datetime import datetime

# Local modules
from APIs.logging import Log
from APIs.security import *

# Declare Global variables
TERMINATE = False
CLI_HASH = {}
KEY = ''

class Server():
    def __init__(self):
        self.HOST_IP = '0.0.0.0'
        self.HOST_PORT = '8080'
        self.MAX_USR_ACCPT = '100'

    def show_help(self):
        msg = '''
        AVAILABLE COMMANDS:
        \h          Print these information
        \d          Set default configuration
        \sd         Show default configuration
        \sc         Show current configuration
        \sau        Show active users
        \sac        Show active chat rooms
        \sf         Shutdown server forcefully
        \sg         Shutdown server gracefully [Recommended]
        \monitor    Enables monitor mode'''
        print(msg)

    def show_config(self, type_='default'):
        if type_ in ('active', 'ACTIVE'):
            msg = '''
            Active configuration of the server :
            HOST IP = ''' + self.HOST_IP + '''
            HOST PORT = ''' + self.HOST_PORT + '''
            MAX USER ALLOWED = ''' + self.MAX_USR_ACCPT 
            logging.log('Showing Active server configuration')
            print(msg)
        else:
            msg = '''
            Default configuration of the server:
            HOST IP = 0.0.0.0
            HOST PORT = 8080
            MAX USER ALLOWED = 100'''
            print(msg)

    def set_usr_config(self, parameters):
        if parameters:
            if sys.argv[1] in ('-h', '--help'):
                self.show_help()
            try:
                self.HOST_IP = sys.argv[1]
                self.HOST_PORT = sys.argv[2]
                self.MAX_USR_ACCPT = sys.argv[3]
            except:
                print('USAGE:\nscript ip_address port_number max_usr_accpt')
                sys.exit(0)
        else:
            self.HOST_IP = input('Enter host IP : ')
            self.HOST_PORT = input('Enter host PORT : ')
            self.MAX_USR_ACCPT = input('Enter max number of users server would accept : ')

    def update_active_users(self):
        self.user_list = []
        for cli_obj in CLI_HASH.values():
            self.user_list.append(cli_obj.userName)

    def signal_handler(self, signal, frame):
        print(' has been pressed.\n')

    def srv_prompt(self):
        global TERMINATE
        while True:
            OPT = input('\nenter command $ ')
            if OPT == '\h':
                self.show_help()
            elif OPT == '\monitor':
                print('Monitoring mode ENABLED!')
                logging.silent_flag = False
                signal.signal(signal.SIGINT, self.signal_handler)
                signal.pause()
                print('Monitoring mode DISABLED')
                logging.silent_flag = True
            elif OPT == '\sd':
                self.show_config(type_='default')
            elif OPT == '\sc':
                self.show_config(type_='active')
            elif OPT == '\sau':
                self.update_active_users()
                logging.log(self.user_list)
                print(self.user_list)
            elif OPT == '\sf':
                print('WARNING: All users will be disconnected with out any notification!!')
                OPT = input('Do you really want to close server?[Y/N] ')
                if OPT == 'Y':
                    logging.log('Shuting down server...')
                    print('Shuting down server...')
                    TERMINATE = True
                    sys.exit(0)
                else:
                    logging.log('Aborted.')
                    print('Aborted.')
            elif OPT == '\sg':
                pass
            elif OPT == '':
                pass
            else:
                print('COMMAND NOT FOUND!!')

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
                logging.log('No exception occured')
                # Instantiate individual Client thread object
                # to do client related stuffs.
                cli_obj = Client(conn, addr, self)
            
                # Maintain a hash table for client thread objects,
                # where keys will be connection object and values will
                # be client thread object.
                CLI_HASH[conn] = cli_obj

                threading._start_new_thread(cli_obj.run, ('',))
        try:
            print('Server has stopped listening on opened socket.')
            print('Broadcasting connection termination signal..')
            msg = "Sorry! We are unable to serve at this moment."
            for cli_socket in CLI_HASH.keys():
                try:
                    cli_socket.send(msg.encode())
                except:
                    cli_socket.close()
                    CLI_HASH.pop(cli_socket)
        except:
            pass

    def init(self):
        """
        Initializes the server application as per user inputs.
        """
        logging.log('Initializing server')
        if len(sys.argv) == 1:
            self.show_config(type_='default')
            OPT = input('Set these default config?[Y/n] ')
            if OPT == '':
                OPT = 'Y'
            if OPT in ('Y', 'y', 'yes', 'Yes', 'YES'):
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
            self.server.listen(int(self.MAX_USR_ACCPT))
        except:
            print('Unable to bind HOST IP and PORT.\nPlease check your configuration')            
            sys.exit('EMERGENCY')
        print('\nServer is listening at {}:{}'.format(self.HOST_IP, self.HOST_PORT))
        print('Server is configured to accept %s clients.' %(str(self.MAX_USR_ACCPT)))

        """ Create two threads thread_srv and thread_cli, where thread_srv
        will be resposible for handling server input and thread_cli will be
        responsible for handling users. """

        #thread_srv = threading.Thread(target=self.srv_prompt, args=())
        thread_cli = threading.Thread(target=self.init_clients, args=())

        #thread_srv.start() # Start a thread for server prompt
        thread_cli.start() # Start a thread to listening clients reqests
        self.srv_prompt()
        
        for thread in (thread_srv, thread_cli):
            thread.join()
        print('Server and Client threads are exited.')


class Client():
    def __init__(self, conn, addr, srv_obj):
        self.srv_obj = srv_obj
        self.conn = conn
        self.addr = addr
        self.userName = '-N/A-'

    def validate_user(self):
        pass

    def features(self, msg):
        # Feature-1: User can get online users list
        if msg == '@getonline':
            self._loop_break_flag = True
            #self.conn.send(str(self.srv_obj.user_list).encode())
            self.conn.send(encrypt(KEY, str(self.srv_obj.user_list)))

        # Feature-2: User can send msg to individual user
        if msg.split()[0][1:] in self.srv_obj.user_list:
            self._loop_break_flag = True
            for _conn in CLI_HASH:
                if CLI_HASH[_conn].userName == msg.split()[0][1:]:
                    try:
                        self.IND_SOCK = _conn
                        msg_send = "<" + self.userName + "@" + self.addr[0] + "> " +\
                                '[IND] ' + ' '.join(msg.split()[1:])
                        self.broadcast(msg_send, IND_FLAG=True)
                    except Exception as e:
                        logging.log(msg_type='EXCEPTION', msg=e)

    def run(self, *args):
        #self.userName = self.conn.recv(100).decode()
        self.userName = decrypt(KEY, self.conn.recv(100))
        #_userPasswd = self.conn.recv(100).decode()

        self.validate_user()
        
        msg = self.userName + " has joined the chatroom."
        logging.log(msg)
        self.broadcast("\n" + msg)
        
        # sends a message to the client whose user object is conn
        msg_send = "Welcome [" + self.userName + "] to this chatroom!"
        #self.conn.send(msg_send.encode())
        self.conn.send(encrypt(KEY, msg_send))

        while True:
            try:
                self._loop_break_flag = False
                msg = decrypt(KEY, self.conn.recv(2048))

                if msg:
                    if msg.split()[0][0] == '@':
                        self.srv_obj.update_active_users()
                        self.features(msg)

                    if not self._loop_break_flag:
                        # print the msg sent by user
                        log_msg = "<" + self.userName + "@" + self.addr[0] + "> " + msg
                        logging.log(msg_type='CHAT', msg=log_msg)

                        # Call broadcast method to relay message to connected users
                        msg_send = "<" + self.userName + "@" + self.addr[0] + "> " + msg
                        self.broadcast(msg_send)
                else:
                    # msg may have no content if the connection
                    # is broken, in that case remove the connection
                    self.remove()
            except Exception as e:
                logging.log('exception occured for user ' + self.userName)
                logging.log(msg_type='EXCEPTION', msg=e)
                self.remove()

    def broadcast(self, msg, IND_FLAG=False):
        if IND_FLAG:
            #self.IND_SOCK.send(encrypt(KEY, msg).encode())
            self.IND_SOCK.send(encrypt(KEY, msg))
            return
        for cli_socket in CLI_HASH.keys():
            if cli_socket != self.conn:
                try:
                    #cli_socket.send(msg.encode())
                    cli_socket.send(encrypt(KEY, msg))
                except:
                    cli_socket.close()
                    # If the link is broken, remove the client
                    self.remove()

    def remove(self):
        if self.conn in CLI_HASH.keys():
            msg = str(CLI_HASH[self.conn].userName) + " went offline!"
            logging.log(msg)
            msg = "\n" + msg 
            self.broadcast(msg)
            CLI_HASH.pop(self.conn)
            sys.exit()

if __name__ == "__main__":
    try:
        #global KEY
        # Call main function if the program is running as active program.
        logging = Log(f_name='server_chatroom_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        logging.logging_flag = True
        logging.silent_flag = True
        logging.validate_file()
        KEY = hasher(getpass.getpass("Key to encrypt the chatrooom:").encode())
        server = Server()
        server.init()
    except SystemExit as e:
        if e.code != 'EMERGENCY':
            # Normal exit, let unittest catch it
            raise
        else:
            print(sys.exc_info())
            print('Something went wrong!!\nPlease contact developers.')
            os._exit(1)
    except:
        print('Something went wrong!!\nPlease contact developers\nTerminating the process forcefully..')
        time.sleep(1)
        os._exit(1)
