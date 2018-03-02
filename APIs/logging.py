#! /usr/bin/env python3

import os
import time

class Log(object):
    def __init__(self, f_location='/tmp/', f_name=''):
        ''' Use this class to print logs on the sys.out and
        permanently save to a file. can be used for both client
        and server side programming. instantiate object with
        file location and name. Default extension of log file
        is [.log], can be changed as per needed.
        '''
        self.f_location = f_location
        self.f_name = f_name
        self.f_extn = '.log'
        self.logging_flag = False
        self.silent_flag = False
        self.abspath = self.f_location + self.f_name + self.f_extn
        self.f_obj = None

    def validate_file(self):
        ''' This method sets absolute path of the given file
        and checks file's availability on the system. This creates
        a file object which will be later used to write msg
        to a file.
        '''
        if self.logging_flag:
            if os.path.exists('self.abspath'):
                raise ValueError('{} File exists'.format(self.abspath))
            else:
                try:
                    self.f_obj = open(self.abspath, 'w+')
                    print('Logging has been enabled!!!')
                    print('Log file: ' + self.abspath)
                except Exception as e:
                    raise e
                                
    def log(self, msg='\t-N/A-', msg_type='INFO'):
        ''' log_type must be mentioned to show the serverity
        of the logging message. severity can be one of the
        followings: ['INFO', 'WARNING', 'ALERT', 'CRITICAL', 'CHAT']
        '''
        self.msg_type = msg_type.upper()
        logging_msg = time.ctime() + ' [' + self.msg_type + '] ' + str(msg)
        if not self.silent_flag:
            print(logging_msg)
        if self.logging_flag and self.f_obj:
            self.f_obj.write(logging_msg + '\n')

    def stop(self, msg='logging has been stopped'):
        if self.logging_flag:
            print(msg)
            self.f_obj.write(msg)
            try:
                self.f_obj.close()
            except Exception as e:
                raise e
