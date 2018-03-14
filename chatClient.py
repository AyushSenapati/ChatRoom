#! /usr/bin/env python3

# import os
import sys
import socket

import inspect
import pickle
import threading
import time
from datetime import datetime
from tkinter import *
import tkinter.scrolledtext as st
import tkinter.simpledialog as simpledialog
from tkinter import messagebox

# Local modules
from APIs.logging import Log
from APIs.security import *

GUI_OBJ = None
KEY = None


class GUI(object):
    def __init__(self, master, network_obj):
        global GUI_OBJ
        self.master = master
        self.network = network_obj
        self.flag = True
        self.connection_status = False
        GUI_OBJ = self
        self.init_canvas()
        self.init_frame()
        self.init_textbox()
        self.init_buttons()
        self.init_menubar()

    def init_canvas(self):
        """Initialise canvas"""
        self.canvas = Canvas(self.master, width=730, height=650)
        self.canvas.pack(fill="both", expand=True)

    def init_menubar(self):
        def exit_():
            response_ = messagebox.askyesno('WARNING', 'Are you sure?')
            if response_:
                self.master.destroy()

        self.menubar = Menu(self.master)
        self.master.config(menu=self.menubar)
        self.file_menu = Menu(self.menubar)
        self.edit_menu = Menu(self.menubar)
        self.help_menu = Menu(self.menubar)
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.menubar.add_cascade(label="Edit", menu=self.edit_menu)
        self.menubar.add_cascade(label="Help", menu=self.help_menu)
        # self.file_menu.add_command(label="Find People", command=self.findPeople)
        # self.file_menu.add_separator()
        self.file_menu.add_command(label='Quit', command=exit_)
        self.edit_menu.add_command(label='Preferences',
                                   command=self.menubar_preferences)
        self.help_menu.add_command(label='About ChatRoom',
                                   command=self.menubar_about)

    def menubar_preferences(self):
        pass

    def menubar_about(self):
        messagebox.showinfo(
            'About', 'Chat Room v1.0.0\nAuthor: ' + \
                     'AyushSenapati <a.p.senapati008@gmail.com>\n\n' + \
                     'Report bugs at -\ngithub.com/AyushSenapati/')

    def init_frame(self):
        """Initialise 2 frames, one at the left for entry widget
        and one at the right for rest frames. Place 3 frames
        ['for displaying messages', 'for user input', 'for button']
        over right side frame.
        """
        # Frame for placing Entry widget to get username input
        self.frame_left = Frame(self.canvas, height=400, width=200)
        # Create a frame at the right side to contain 3 more frames
        self.frame_right = Frame(self.canvas, width=500)
        # Create and place 3 frames over Right one.
        self.frame_right_chat_show = Frame(self.frame_right, borderwidth=2,
                                           relief=GROOVE)
        self.frame_right_chat_input = Frame(self.frame_right, width=460,
                                            height=30, borderwidth=2,
                                            relief=GROOVE)
        self.frame_right_chat_input_buttons = Frame(self.frame_right, width=40,
                                                    height=30, borderwidth=2,
                                                    relief=GROOVE)

        self.frame_left.pack(fill=Y, side='left')
        self.frame_right.pack(fill=Y, side='left')
        self.frame_right_chat_show.pack(fill=X, side='top')
        self.frame_right_chat_input.pack(side='left')
        self.frame_right_chat_input_buttons.pack(side='left')

    def init_entrybox(self):
        """Create an entry widget over left side frame to
        to get username input. No other available text fields
        should be used while application is waiting for username
        input. So diable two other text fields.
        """
        # Disable text fields
        self.txt_disp.configure(state='disabled')
        self.txt_input.configure(state='disabled')
        # Create and pack Entry widget
        self.entry_username = Entry(self.frame_left)
        self.username = StringVar()
        self.username.set("Enter user name")
        self.entry_username["textvariable"] = self.username
        self.entry_username.bind('<Key-Return>', self.get_username)
        self.entry_username.bind('<Button-1>', self.clear_username_field)
        self.entry_username.pack()

    def prompt_username(self):
        username = simpledialog.askstring("User Information",
                                          "Enter user name")
        print(username)
        if username:
            self.network.send_msg(username)
            self.txt_input.focus()
        else:
            self.update("No username provided")
            self.network.disconnect()
            self.connection_status = False
            self.update("Disconnected from the server")
            #self.update("Exiting application")
        # self.master.destroy()

    def init_textbox(self):
        """Initialise two text boxes, one for displaying
        messages and another for getting user input.
        Text boxes must be initialised first before initialising
        entry widgets as textbox widgets are disabled in init_entrybox
        """
        self.txt_disp = st.ScrolledText(self.frame_right_chat_show, height=30,
                                        width=87, bg='forest green')
        self.txt_input = Text(self.frame_right_chat_input, height=3,
                              bg='lime green')
        self.txt_input.bind('<Key-Return>', self.get_entry)
        self.txt_disp.pack(side='left')
        self.txt_input.pack()

    def init_buttons(self):
        """Initialise 'Send' and 'Clear' button widgets"""
        self.btn_send = Button(self.frame_right_chat_input_buttons,
                               text='Send', borderwidth=0,
                               command=self.get_entry)
        self.btn_clear = Button(self.frame_right_chat_input_buttons,
                                text='Clear', borderwidth=0,
                                command=self.clear_txt_input_field)
        self.btn_send.pack()
        self.btn_clear.pack()

    def clear_username_field(self, *args):
        # self.entry_username.delete(0, END)
        self.txt_input.focus()

    def clear_txt_input_field(self, *args):
        self.txt_input.delete('1.0', END)

    def get_username(self, event):
        """Fetch username from the entry widget and
        send to the server. Disable the entry widget and
        get the text_input widget back to normal state
        """
        username = self.username.get()
        self.entry_username.delete(0, END)
        self.entry_username.configure(state='disabled')
        self.txt_input.configure(state='normal')
        self.network.send_msg(username)

    def update(self, msg):
        """This method updates messages on display window"""
        msg = '\n' + msg
        self.txt_disp.configure(state='normal')
        self.txt_disp.insert(END, msg)
        self.txt_disp.see(END)
        self.txt_disp.configure(state='disabled')

    def get_entry(self, *arg):
        """ Gets input from the input field and uses
        network object to send message to the server.
        Finally clears input field to enter msg.
        """
        # print(self.thread_name + ">> " + str(self.txt_input.get('1.0',END)))
        msg_snd = self.txt_input.get('1.0', END)
        msg_snd = msg_snd.strip('\n')
        if msg_snd and self.connection_status:
            self.network.send_msg(msg_snd)
            msg_snd = '<YOU> ' + msg_snd
            self.update(msg_snd)
            self.txt_input.delete('1.0', END)
            self.clear_txt_input_field()

    def get_msg(self, *arg):
        """ This method is being used by separate thread
        to keep on receiving messages from the server and
        update chat window.
        """
        while True:
            msg_rcv = self.network.get_msg
            if msg_rcv:
                msg_rcv = msg_rcv.strip('\n')
                print('-' * 60)
                print(msg_rcv)
                self.update(msg_rcv)


class Network(object):
    """Class to handle all networking stuffs for the client application"""

    def __init__(self, srv_ip='', srv_port='8080'):
        """ Constructor to initialise network
        connectivity between the client and server.
        """
        self.srv_ip = srv_ip
        self.srv_port = int(srv_port)
        self.cli_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.KEY_FLAG = False
        self.priv_key = None
        self.pub_key = None

    def connect(self) -> (bool, type or None):
        """Responsible for establishing network connection on demand"""
        GUI.connection_status = False
        try:
            self.cli_socket.connect((self.srv_ip, self.srv_port))
            GUI.connection_status = True
            return True, None
        except ConnectionAbortedError as e:
            return False, e
        except ConnectionResetError as e:
            return False, e
        except ConnectionRefusedError as e:
            return False, e
        except ConnectionError as e:
            return False, e

    def disconnect(self):
        self.cli_socket.close()
        GUI.connection_status = False

    def genRSA(self, *args):
        """Generate Private and Public key for particular session"""
        logging.log("Generating private and public key")
        self.priv_key, self.pub_key = RSA_.genRSA()
        logging.log("Keys generation completed.")
        logging.log(self.pub_key.exportKey())

    def initEncryption(self, userName):
        """Initialise secure connection"""
        global KEY

        # Prepare data for serialization as tuple
        # can't be transmitted over network.
        msg_send = (userName, self.pub_key)
        msg_send = pickle.dumps(msg_send)
        self.cli_socket.send(msg_send)
        logging.log(
            "User name along with public key has been sent to the server.")

        # Wait for the server to send symmetric key
        EnSharedKey = self.cli_socket.recv(1024)
        EnSharedKey = pickle.loads(EnSharedKey)
        print(EnSharedKey)
        KEY = RSA_.decrypt(self.priv_key, EnSharedKey)
        print(KEY)
        if KEY:
            logging.log("Unique key has been received")
            self.KEY_FLAG = True
            logging.log("Secure connection has been established.")

    @property
    def get_msg(self):
        if KEY is not None:
            msg_rcv = AES_.decrypt(KEY.encode(), self.cli_socket.recv(20000))
            return msg_rcv

    def send_msg(self, msg_snd):
        if KEY is None:
            # Send (userName, RSA_PublicKey) to the server
            # to get encrypted symmetric key for further encryption.
            GUI.update(GUI_OBJ, "Establishing secure connection...")
            self.initEncryption(msg_snd)
            GUI.update(GUI_OBJ, "Connection has been encrypted")
            return
        try:
            print(msg_snd)
            result = self.cli_socket.send(AES_.encrypt(KEY.encode(), msg_snd))
            print("Bytes sent: ", result)
        except BrokenPipeError as e:
            tmp_msg = f"[Function: {inspect.stack()[0].function}] {e}"
            logging.log(msg=tmp_msg, msg_type='EXCEPTION')
            GUI.update(GUI_OBJ, "Not connected to the server")
        except Exception as e:
            logging.log(msg=e, msg_type='EXCEPTION')
            GUI.update(GUI_OBJ, "Not connected to the server")


# Outside class functions
def connection_thread(*args):
    srv_ip = args[1]
    gui = args[0]
    retry_count = 0
    gui_flag = True  # GUI has been initialized
    network_flag = False  # Connection has not been established
    print(f'Connecting {srv_ip}')

    # Check if connection has not been established
    while not network_flag:
        network = Network(srv_ip, '8080')
        status, return_msg = network.connect()
        if status:  # If connection established successfully
            if gui_flag:
                gui.network = network
            logging.log('Connected to the server')
            gui.update('Connected to the server')
            gui.connection_status = True
            # gui.entry_username.configure(state='normal')
            network_flag = True
        else:
            msg = "[Retry {}] {}".format(retry_count + 1, return_msg)
            logging.log(msg)
            retry_count += 1
            if retry_count == 1 and gui_flag:
                # gui = GUI(root, None)
                # gui.entry_username.configure(state='disabled')
                gui.update("Failed to connect the server.\n"
                           "Started retrying.")
                gui.update("Retry connecting...")
                time.sleep(5)
            elif 4 > retry_count:
                time.sleep(5)
            elif retry_count == 5 and gui_flag:
                gui.update("Retry limit exceeded.\n"
                           "Unable to connect the server.\n")
                return
    logging.log(
        'New thread has been initialized to fetch data from the server')
    rsa_thread = threading.Thread(target=network.genRSA, args=())
    rsa_thread.start()
    rsa_thread.join()
    gui.master.after(2000, gui.prompt_username)

    # Start a new thread to fetch
    # messages from the server continuously
    threading._start_new_thread(gui.get_msg, ())


def main():
    srv_ip = '127.0.0.1'
    if len(sys.argv) == 2:
        srv_ip = sys.argv[1]
    root = Tk()  # initialize root window
    root.title('C H A T R O O M')
    root.wm_maxsize(width=830, height=515)
    root.resizable(False, False)

    # initialize GUI with establishing the network
    gui = GUI(root, None)

    threading._start_new_thread(connection_thread, (gui, srv_ip))

    root.mainloop()

    logging.log('exiting main thread.')
    logging.stop()


if __name__ == "__main__":
    logging = Log(f_name='client_chatroom_' +
                         datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    opt = input('Enable logging? (y/N): ')
    if opt in ('y', 'Y', 'yes', 'Yes', 'YES'):
        # it will both save log_msg to a file and print to sys.stdout
        logging.logging_flag = True
        logging.validate_file()
    main()
