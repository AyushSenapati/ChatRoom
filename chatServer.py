#! /usr/bin/env python3

import os
import sys
import socket
import select
import threading
import time

class Server():
    def __init__(self):
        self.TERMINATE = False
        self.cli_hash = {}
        self.HOST_IP = '0.0.0.0'
        self.HOST_PORT = '8080'
        self.MAX_USR_ACCPT = '100'
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

    def srv_prompt(self):
        while True:
            OPT = input('\nenter command $ ')
            if OPT == '\h':
                self.show_help()
            elif OPT == '\sd':
                self.show_config(type_='default')
            elif OPT == '\sc':
                self.show_config(type_='active')
            elif OPT == '\sf':
                print('WARNING: All users will be disconnected with out any notification!!')
                OPT = input('Do you really want to close server?[Y/N] ')
                if OPT == 'Y':
                    print('Shuting down server...')
                    self.TERMINATE = True
                    time.sleep(0.5)
                    print('Done.')
                    sys.exit()
                else:
                    print('Aborted.')
            elif OPT == '\sg':
                pass
            else:
                print('COMMAND NOT FOUND!!')

    def init_clients(self):
        """ Accepts connection requests from clients and stores
        two parameters- 'conn' which is a socket object for that user,
        and 'addr' which contains the IP address of the client
        that just connected to the server.
        """
        while True:
            # Break the loop and stop accepting connections
            # from the clients, when terminate command is entered 
            # in the server prompt.
            if self.TERMINATE:
                break

            # Accept connections from the clients.
            conn, addr = self.server.accept()
    
            # Instantiate individual Client thread object
            # to do client related stuffs.
            cli_thread_obj = Client(conn, addr)
            
            # Maintain a hash table for client thread objects,
            # where keys will be connection object and values will
            # be client thread object.
            self.cli_hash[conn] = cli_thread_obj

            #threading._start_new_thread(client.clientthread)
        # Wait for all client threads to exit their process
        try:
            # TODO Broadcast connection termination request
            # when the server is going to shutdown.
            # Upon receiving connection termination request, all
            # connected client applications must wait for 5 seconds
            # for the users to close their applications, before
            # terminating connections automatically.
            print('Wating for all clients to terminate their connections...')
            for cli_thread in self.cli_hash.values():
                cli_thread.join()
        except:
            print('No client is connected to the server.')

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
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.conn = conn
        self.addr = addr

    def clientthread(self):
        _userName = self.conn.recv(100).decode()
        #_userPasswd = self.conn.recv(100).decode()
        
        # TODO: Log client has been connected and and add
        #       broadcast method to broadcast this info.

    def broadcast(self):
        pass

    def remove(self):
        pass

if __name__ == "__main__":
    try:
        # Call main function if the program is running as active program.
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
