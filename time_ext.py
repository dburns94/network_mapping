#!/usr/bin/python3.6

import sys
import time
from datetime import datetime, timedelta

def delete_last_line():
    sys.stdout.write('\x1b[1A')
    sys.stdout.write('\x1b[2K')

def get_time():
    return time.time()

###################################################
###################### Sys ########################
###################################################
class Unbuffered(object):
    """ disables buffering for stdout """
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

def no_buffer():
    """ disables buffering for stdout """
    sys.stdout = Unbuffered(sys.stdout)

###################################################
###################### Time #######################
###################################################
def sleep(seconds):
    time.sleep(seconds)

def hms(timeLapsed):
    """ returns elapsed time as 'X hours Y minutes Z seconds' """
    timeLapsed = float(timeLapsed)
    # determine hours, minutes, seconds
    hour = 0
    while timeLapsed >= 3600:
        timeLapsed -= 3600
        hour += 1
    minute = 0
    while timeLapsed >= 60:
        timeLapsed -= 60
        minute += 1
    # format time
    formattedTime = ""
    if hour > 0:
        formattedTime += "%s hour" % hour
        if hour > 1:
            formattedTime += "s"
        formattedTime += " "
    if minute > 0:
        formattedTime += "%s minute" % minute
        if minute > 1:
            formattedTime += "s"
        formattedTime += " "
    # round to the nearest tenth place
    timeLapsed = round(timeLapsed, 1)
    # if the number has zero tenths place (i.e. 'N.0XYZ')
    if int((timeLapsed % 1) * 100) == 0:
        # make it an integer
        timeLapsed = int(timeLapsed)
    if timeLapsed > 0 or (hour == 0 and minute == 0):
        formattedTime += "%s second" % timeLapsed
        if (timeLapsed-1) != 0:
            formattedTime += "s"
    # if the last character is a space
    if formattedTime[-1] == " ":
        # remove the space
        return formattedTime[:-1]
    # return modified time
    return formattedTime

def tod_name(hour):
    """ returns PM if time is after noon, AM otherwise """
    if hour >= 12:
        return 'PM'
    return 'AM'

def tod_hour(hour):
    if hour > 12:
        return hour-12
    return hour

class Time:
    def __init__(self):
        self._datetime = datetime.today()
        self._time = time.time()
    def __repr___(self):
        return "Time()"
    def __str__(self):
        return "Time()"
    def elapsed(self, format=True):
        """ returns the time elapsed since class creation """
        time_elapsed = time.time() - self._time
        # if user wants this formatted as string (e.g. X hours Y minutes Z seconds)
        if format:
            time_elapsed = hms(time_elapsed)
        return time_elapsed
    @property
    def work_hours(self):
        """ returns True is the current time is within work hours """
        if 0 < self.datetime.day < 6 and 7 < self.datetime.hour < 17:
            return True
        return False
    @property
    def month(self):
        return self._datetime.month
    @property
    def day(self):
        return self._datetime.day
    @property
    def year(self):
        return self._datetime.year
    @property
    def hour(self):
        return self._datetime.hour
    @property
    def tod_hour(self):
        return tod_hour(self.hour)
    @property
    def minute(self):
        return self._datetime.minute
    @property
    def second(self):
        return self._datetime.second
    @property
    def tod(self):
        """ returns PM if time is after noon, AM otherwise """
        return tod_name(self.hour)
    def date(self, char='-', fill=True, stamp=False):
        """ returns today's date """
        # get the month, date, and year
        month = str(self.month)
        day = str(self.day)
        year = str(self.year)
        # if the user wants zeros padded
        if fill or stamp:
            month = month.zfill(2)
            day = day.zfill(2)
            # if this is a time stamp intended for a file
            if stamp:
                # put the year first for sorting
                return f"{year}{char}{month}{char}{day}"
        return f"{month}{char}{day}{char}{year}"
    def time(self, char=':', tod=True, fill=True, stamp=False):
        """ returns the current local time """
        # get the hour, minute and second
        if tod:
            hour = str(self.tod_hour)
        else:
            hour = str(self.hour)
        minute = str(self.minute).zfill(2)
        second = str(self.second).zfill(2)
        # if the user wants zeros padded
        if fill or stamp:
            hour = hour.zfill(2)
            # if this is is a time stamp intended for a file
            if stamp:
                return f"{hour}{minute}{second}"
        time_string = f"{hour}{char}{minute}{char}{second}"
        # if user wants TOD printed
        if tod:
            time_string += f" {self.tod}"
        return time_string
    def datetime(self, char=' ', date_char='-', time_char=':', tod=True, fill=True, stamp=False):
        """ returns the current local date and time """
        if stamp:
            return f"{self.date(char=date_char, stamp=stamp)}_{self.time(char=time_char, stamp=stamp)}"
        else:
            return f"{self.date(char=date_char, fill=fill)}{char}{self.time(char=time_char, tod=tod, fill=fill)}"
    def timedate(self, char=' ', date_char='-', time_char=':', tod=True, fill=True, stamp=False):
        """ returns the current local date and time """
        if stamp:
            return f"{self.time(char=time_char, stamp=stamp)}_{self.date(char=date_char, stamp=stamp)}"
        else:
            return f"{self.time(char=time_char, tod=tod, fill=fill)}{char}{self.date(char=date_char, fill=fill)}"
    def past_date(self, char='-', fill=True, days=0):
        """ returns a past date offset from the current local date """
        # create past timestruct
        date = self._datetime - timedelta(days=days)
        # get the month, date, and year
        month = str(date.month)
        day = str(date.day)
        year = str(date.year)
        # if the user wants zeros padded
        if fill or stamp:
            month = month.zfill(2)
            day = day.zfill(2)
        return f"{month}{char}{day}{char}{year}"
    def past_time(self, char=':', tod=True, fill=True, hours=0, minutes=0, seconds=0):
        """ returns a past time offset from the current local time """
        # create past timestruct
        date = self._datetime - timedelta(hours=hours, minutes=minutes, seconds=seconds)
        # get the hour, minute and second
        if tod:
            hour = str(tod_hour(date.hour))
        else:
            hour = str(date.hour)
        minute = str(date.minute).zfill(2)
        second = str(date.second).zfill(2)
        # if the user wants zeros padded
        if fill:
            hour = hour.zfill(2)
        time_string = f"{hour}{char}{minute}{char}{second}"
        # if user wants TOD printed
        if tod:
            time_string += f" {tod_name(date.hour)}"
        return time_string
        #return f"{hour}{char}{minute}{char}{second}"
    def past_datetime(self, char=' ', date_char='-', time_char=':', tod=True, fill=True, days=0, hours=0, minutes=0, seconds=0):
        """ returns a past date and time offset from the current local date and time """
        return f"{self.past_date(char=date_char, fill=fill, days=days)}{char}{self.past_time(char=time_char, tod=tod, fill=fill, hours=hours, minutes=minutes, seconds=seconds)}"

