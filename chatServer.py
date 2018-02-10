#! /usr/bin/env python3
__author__ = 'Ayush Prakash Senapati <a.p.senapati008@gmail.com>'

import os
import sys
import socket
import select
import threading
import time
from datetime import datetime

# Local modules
from APIs.logging import Log

# Set program Terminate flag
TERMINATE = False
CLI_HASH = {}

class Server():
    def __init__(self):
        self.cli_hash = {}
        self.HOST_IP = '0.0.0.0'
        self.HOST_PORT = '8080'
        self.MAX_USR_ACCPT = '100'
        logging.log('Initializing server')
        self.init()

    def show_help(self):
        msg = '''
        AVAILABLE COMMANDS:
        \h      Print these information
        \d      Set default configuration
        \sd     Show default configuration
        \sc     Show current configuration
        \sau    Show active users
        \sac    Show active chat rooms
        \sf     Shutdown server forcefully
        \sg     Shutdown server gracefully [Recommended]'''
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

    def srv_prompt(self):
        global TERMINATE
        while True:
            OPT = input('\nenter command $ ')
            if OPT == '\h':
                self.show_help()
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
                #cli_thread_obj.run()

                threading._start_new_thread(cli_obj.run, ('',))
        # Wait for all client threads to exit their process
        try:
            # TODO Broadcast connection termination request
            # when the server is going to shutdown.
            # Upon receiving connection termination request, all
            # connected client applications must wait for 5 seconds
            # for the users to close their applications, before
            # terminating connections automatically.
            print('Server has stopped listening on opened socket.')
            print('Broadcasting connection termination signal..')
        except:
            pass

    def init(self):
        """
        Initializes the server application as per user inputs.
        """
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

        thread_srv = threading.Thread(target=self.srv_prompt, args=())
        thread_cli = threading.Thread(target=self.init_clients, args=())

        thread_srv.start() # Start a thread for server prompt
        thread_cli.start() # Start a thread to listening clients reqests
        
        for thread in (thread_srv, thread_cli):
            thread.join()
        print('Server and Client threads are exited.')


class Client(Server):
    def __init__(self, conn, addr, srv_obj):
        self.srv_obj = srv_obj
        self.conn = conn
        self.addr = addr
        self.userName = '-N/A-'

    def run(self, *args):
        self.userName = self.conn.recv(100).decode()
        #_userPasswd = self.conn.recv(100).decode()
        
        # TODO: Log client has been connected
        self.broadcast("\n" + self.userName + " has joined the chatroom.")
        
        # sends a message to the client whose user object is conn
        msg_send = "Welcome [" + self.userName + "] to this chatroom!"
        self.conn.send(msg_send.encode())
        logging.log('welcome msg sent to user ' + self.userName)

        while True:
            try:
                _loop_break_flag = False
                msg = self.conn.recv(2048).decode()
                if msg == '@getonline':
                    _loop_break_flag = True
                    self.srv_obj.update_active_users()
                    self.conn.send(str(self.srv_obj.user_list).encode())
                if not _loop_break_flag:
                    if msg:
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
                raise e
                logging.log('exception occured for user ' + self.userName)
                self.remove()

    def broadcast(self, msg):
        for cli_socket in CLI_HASH.keys():
            if cli_socket != self.conn:
                try:
                    cli_socket.send(msg.encode())
                except:
                    cli_socket.close()
                    # If the link is broken, remove the client
                    self.remove()

    def remove(self):
        if self.conn in CLI_HASH.keys():
            msg = "\n" + str(CLI_HASH[self.conn].userName) + " went offline!"
            self.broadcast(msg)
            CLI_HASH.pop(self.conn)

if __name__ == "__main__":
    try:
        # Call main function if the program is running as active program.
        logging = Log(f_name='server_chatroom_' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        logging.logging_flag = True
        logging.validate_file()
        server = Server()
    except SystemExit as e:
        if e.code != 'EMERGENCY':
            # Normal exit, let unittest catch it
            raise
        else:
            #print(sys.exc_info())
            print('Something went wrong!!\nPlease contact developers.')
            os._exit(1)
    #except:
    #    print('Something went wrong!!\nPlease contact developers\nTerminating the process forcefully..')
    #    time.sleep(1)
    #    os._exit(1)
