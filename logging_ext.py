#!/usr/bin/python3.6

import logging
from logging.handlers import RotatingFileHandler

log_dir = '/var/scripts/logs/'

def get_log_level(level_str):
    """ converts a string of a level to the integer value """
    level = logging.WARNING
    # declare associations
    str_levels = [
                                ['debug',    logging.DEBUG],
                                ['info',    logging.INFO],
                                ['warning',  logging.WARNING],
                                ['error',    logging.ERROR],
                                ['critical', logging.CRITICAL]
                              ]
    # make string level to lowercase
    level_str = level_str.lower()
    # find association
    for str_level in str_levels:
        if str_level[0].startswith(level_str):
            level = str_level[1]
    return level

def set_logger(name, log_stdout=True, stdout_level='e', log_file=True, file_name=None, file_level='w', backup_count=2, max_size=102400):
    # create logger
    logger = logging.getLogger(name)
    # set debug level
    logger.setLevel(logging.DEBUG)
    # create logger formatting
    formatter = logging.Formatter('%(asctime)s:%(pathname)s:%(funcName)s:%(lineno)d:%(levelname)s:%(message)s')
    #formatter = logging.Formatter('%(asctime)s:%(name)s:%(pathname)s:%(funcName)s:%(lineno)d:%(levelname)s:%(message)s')
    # configure logging to stdout
    if log_stdout:
        stream_handler = logging.StreamHandler()
        # set logger formatting
        stream_handler.setFormatter(formatter)
        # set stdout logging level
        log_level = get_log_level(stdout_level)
        stream_handler.setLevel(log_level)
        # add handler
        logger.addHandler(stream_handler)
    # configure logging to file
    if log_file and file_name is not None:
        # create filename
        logfile_name = log_dir+file_name
        # create rotating logs
        file_handler = RotatingFileHandler(logfile_name, maxBytes=max_size, backupCount=backup_count)
        # set logger formatting
        file_handler.setFormatter(formatter)
        # set file logging level
        log_level = get_log_level(file_level)
        file_handler.setLevel(log_level)
        # add handler
        logger.addHandler(file_handler)
    return logger

class Logger:
    global log_dir
    # create logger formatting
    #formatter = logging.Formatter('%(asctime)s:%(pathname)s:%(funcName)s:%(lineno)d:%(levelname)s:%(message)s')
    formatter = logging.Formatter('%(asctime)s:%(name)s:%(pathname)s:%(funcName)s:%(lineno)d:%(levelname)s:%(message)s')
    # create logger
    def __init__(name, verbose=False):
        self = logging.getLogger(name)
        # set debug level
        logger.setLevel(logging.DEBUG)
    # configure logging to stdout
    def log(self, level='w'):
        stream_handler = logging.StreamHandler()
        # set logger formatting
        stream_handler.setFormatter(formatter)
        # set stdout logging level
        log_level = get_log_level(level)
        stream_handler.setLevel(log_level)
        # add handler
        self.addHandler(stream_handler)
    # configure logging to file
    def log_file(self, file_name, level='e', file_dir=log_dir, backup_count=2, max_size=51200):
        # create filename
        logfile_name = file_dir+file_name
        # create rotating logs
        file_handler = RotatingFileHandler(logfile_name, maxBytes=max_size, backupCount=backup_count)
        # set logger formatting
        file_handler.setFormatter(formatter)
        # set file logging level
        log_level = get_log_level(level)
        file_handler.setLevel(log_level)
        # add handler
        self.addHandler(file_handler)
    # stop logs
    def kill(self):
        for handler in self.handlers[:]:
            self.removeHandler(handler)

