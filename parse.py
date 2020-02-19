#!/usr/bin/python3.6

import sys
import re

def string_to_array(string, char='\n'):
    """ returns a string as an array of lines """
    result = []
    # split the string on char (default '\n')
    lines = string.split(char)
    # remove the empty lines
    for line in lines:
        if len(line) > 0:
            result.append(line)
    return result

def min_spaces(string):
    """ ensures string has no leading zeros and is only seperated by a single space character """
    last_char_is_not_space = False
    new_string = ''
    # remove all leading and trailing spaces
    string = string.strip()
    # ensure each string is seperated by a single space chararacter
    for i in string:
        # if this character is not a space, add it to the final string
        if i != ' ':
            new_string += i
            last_char_is_not_space = True
        # if this character is a space...
        else:
            # if the last character was not a space, add it to the final string
            if last_char_is_not_space:
                new_string += i
                last_char_is_not_space = False
    return new_string

def remove_end_spaces(string):
    """ removes all spaces from the end of a string or string array """
    if type(string) is str:
        string = string.replace('\r', '')
        while string[-1] == ' ':
            string = string[:-1]
        return string
    else:
        new_strings = []
        for line in string:
            line = line.replace('\r', '')
            if len(line) > 0:
                while line[-1] == ' ':
                    line = line[:-1]
            new_strings.append(line)
        return new_strings

def remove_border_newlines(string):
    # remove beginning new-lines
    while len(string) > 0 and string[0] == '\n':
        string = string[1:]
    # remove trailing new-lines
    while len(string) > 0 and string[-1] == '\n':
            string = string[:-1]
    return string

def make_table(table, cols='all', indent=0, spacing=2, wrap=False):
    """ creates a table from an array """
    rows = []
    # turn all columns into a string
    for i in range(len(table)):
        for j in range(len(table[i])):
            if type(table[i][j]) != str:
                table[i][j] = str(table[i][j])
    # always assume header is the first line
    headers = table[0]
    # determine columns to print
    try:
        if cols.lower() == 'all':
            cols = []
            for i in range(len(headers)):
                cols.append(i)
    except AttributeError:
        pass
    # initialize column lengths array
    length = []
    # if user wants the header wrapped
    if wrap:
        num_header_lines = []
        for i in range(len(cols)):
            length.append(0)
            num_header_lines.append(1)
        # find max length of each column
        for i in range(len(length)):
            for row in table[1:]:
                if len(row[cols[i]]) > length[i]:
                    length[i] = len(row[cols[i]])
        # calculate lines of headers
        max_lines = 0
        for i in range(len(cols)):
            # if this column requires multiple lines
            if len(headers[cols[i]]) > length[i]:
                words = headers[cols[i]].split(' ')
                # if any word length is greater than the column size
                for j in range(len(words)):
                    if len(words[j]) > length[i]:
                        # increase this column length to that size
                        length[i] = len(words[j])
                # find the number of lines required for the length
                current_length = len(words[0])
                for j in range(1, len(words)):
                    # if this line has room for another word
                    if current_length + 1 + len(words[j]) <= length[i]:
                        # add the length and check the next word
                        current_length += 1 + len(words[j])
                    # if this line does not have room for another word
                    else:
                        # start a new line
                        current_length = len(words[j])
                        num_header_lines[i] += 1
                # store the max number of lines for later use
                if num_header_lines[i] > max_lines:
                    max_lines = num_header_lines[i]
        # add header rows
        for i in range(max_lines):
            string = ''
            for j in range(indent):
                string += ' '
            j = max_lines - i
            for k in range(len(cols)):
                # if this column header has a line to print
                if num_header_lines[k] >= j:
                    header = ''
                    words = headers[cols[k]].split(' ')
                    # calculate the lines
                    current_line = 0
                    current_length = len(words[0])
                    this_piece = words[0]
                    for l in range(1, len(words)):
                        # if this line has room for another word
                        if current_length + 1 + len(words[l]) <= length[k]:
                            this_piece += ' ' + words[l]
                            current_length += 1 + len(words[l]) <= length[k]
                        # if this line does not have room for another word
                        else:
                            # if this is the line to print
                            if num_header_lines[k] - current_line == j:
                                # stop making new lines
                                break
                            # start a new line
                            this_piece = words[l]
                            current_line += 1
                    # add the line to the string
                    string += this_piece
                    for l in range(length[k] - len(this_piece) + spacing):
                        string += ' '
                # if this column header does not have a line to print
                else:
                    # fill the gap with spaces
                    for l in range(length[k] + spacing):
                        string += ' '
            rows.append(string[:-spacing])
    # if user does not want the header wrapped
    else:
        for i in range(len(cols)):
            length.append(len(headers[cols[i]]))
        # find max length of each column
        for i in range(len(length)):
            for row in table[1:]:
                if len(row[cols[i]]) > length[i]:
                    length[i] = len(row[cols[i]])
        # add header row
        string = ''
        for i in range(indent):
            string += ' '
        for i in range(len(cols)):
            string += headers[cols[i]]
            for j in range(length[i] - len(headers[cols[i]]) + spacing):
                string += ' '
        rows.append(string[:-spacing])
    # add header underline
    string = ''
    for i in range(indent):
        string += ' '
    for i in range(len(cols)):
        for j in range(length[i]):
            string += '-'
        for j in range(spacing):
            string += ' '
    rows.append(string[:-spacing])
    # add data rows
    for i in range(1, len(table[1:])+1):
        string = ''
        for j in range(indent):
            string += ' '
        for j in range(len(cols)):
            string += table[i][cols[j]]
            for k in range(length[j] - len(table[i][cols[j]]) + spacing):
                string += ' '
        rows.append(string[:-spacing])
        i += 1
    return rows

def print_table(table, cols='all', indent=0, spacing=2, wrap=False):
    # make table with user input
    table = make_table(table, cols=cols, indent=indent, spacing=spacing, wrap=wrap)
    # print each row
    for row in table:
        print(row)
    return None

def parse_table(lines, delimiter=' ', seperator='-', threshold=55):
## this function will seperate columns formatted with spaces (delimiter)
    # find max length of a line
    maxLength = 0
    for line in lines:
        if len(line) > maxLength:
            maxLength = len(line)
    # only keep lines that are at least 55% (threshold) of max length
    tableLines = []
    for line in lines:
        if float(len(line))/maxLength*100 > threshold:
            # also only keep lines that are not dividers
            if float(len(line.replace(seperator,'')))/maxLength*100 > 20:
                tableLines.append(line)
    lines = tableLines
    # always assume the header is the first line
    header = lines[0]
    # find the positions of all delimiters in the header
    delims = []
    inaWord = True
    section = []
    for i in range(len(header)):
        # if a header if found, append the section to the delimiters array,
        ## and begin the next section
        if header[i] != delimiter and not(inaWord):
            inaWord = True
            delims.append(section)
            section = []
        # if another delimiter is found before a word,
        ## append the index the the section of delimiters
        elif header[i] == delimiter:
            inaWord = False
            section.append(i)
    # initialize the counts array
    counts = []
    for i in delims:
        section = []
        for j in i:
            section.append(0)
        counts.append(section)
    # count the occurrances of the delimiters in the same position in every line
    for line in lines[1:]:
        for i in range(len(delims)):
            for j in range(len(delims[i])):
                try:
                    if line[delims[i][j]] == delimiter:
                        counts[i][j] += 1
                except IndexError:
                    counts[i][j] += 1
    # for each section, find the position with the most delimiter matches
    posx = [0]
    maxCounts = [len(lines[1:])]
    for i in range(len(counts)):
        maxPosx = -1
        maxCount = 0
        for j in range(len(counts[i])):
            if counts[i][j] >= maxCount:
                maxCount = counts[i][j]
                maxPosx = delims[i][j]
        # only keep the position if it occurs more than 90%
        try:
            if int(float(maxCount)/(len(lines[1:])-1)*100) > 90:
                posx.append(maxPosx+1)
                maxCounts.append(maxCount)
        except:
            if int(float(maxCount)/(len(lines[1:]))*100) > 90:
                posx.append(maxPosx+1)
                maxCounts.append(maxCount)
    # append the max length to the end of the posx array
    ## this allows the next loop to grab the last column
    posx.append(maxLength)
    maxCounts.append(len(lines[1:]))
    # create table from the calculated indices
    table = []
    for line in lines:
        row = []
        for i in range(len(posx)-1):
            row.append(line[posx[i]:posx[i+1]].strip())
        table.append(row)
    # find empty columns
    remove_cols = []
    for i in range(len(table[0])):
        count = 0
        for j in range(len(table)):
            if len(table[j][i]) == 0:
                count += 1
        if count == len(table):
            remove_cols.append(i)
    # remove empty columns
    final_table = []
    for i in range(len(table)):
        final_row = []
        for j in range(len(table[i])):
            if j not in remove_cols:
                final_row.append(table[i][j])
        if len(final_row) > 0:
            final_table.append(final_row)
    # create json of each header's indices
    headers = {}
    headerCount = 0
    for i in final_table[0]:
        headers[i] = headerCount
        headerCount += 1
    return headers, final_table

def include(pattern, response):
    """ returns the lines of the response that include the pattern specified """
    if response is None:
        response = self.response
    results = ""
    pattern = r".*"+pattern+r".*\n"
    matches = re.finditer(pattern, response, re.M)
    # for each match
    for match in matches:
        results += match.group(0)
    return results

def exclude(pattern, response):
    """ returns the lines of the response that do not include the pattern specified """
    result = []
    pattern = re.compile(pattern, re.M)
    lines = response.split('\n')
    for line in lines:
        match = pattern.search(line)
        if match is None:
            result.append(line)
    return '\n'.join(result)

def section(pattern, response):
    """ returns the sections of the response that include the pattern specified """
    results = ""
                        # match initial line         # match any following lines with more starting spaces
    pattern = r"(?P<spaces>[ ]*).*"+pattern+r".*\n((?P=spaces)[ ]+.*\n)*"
    matches = re.finditer(pattern, response, re.M)
    # for each match
    for match in matches:
        results += match.group(0)
    return results

def esection(pattern, response):
    """ returns the response without the sections of pattern specified """
    pattern = r"(?P<spaces>[ ]*).*"+pattern+r".*\n((?P=spaces)[ ]+.*\n)*"
    return re.sub(pattern, '', response, flags=re.M)

def begin(pattern, response):
    """ returns the response begginning at the line that contains the pattern specified """
    results = ""
    pattern = r".*"+pattern+r".*\n(.*\n)*"
    match = re.search(pattern, response, re.M)
    if match is not None:
        results = match.group(0)
    return results

def until(pattern, response):
    """ returns the response ending before the line that contains the pattern specified """
    results = ""
    pattern = r"(?P<response>(.*\n)*).*"+pattern+r".*\n"
    match = re.search(pattern, response, re.M)
    if match is not None:
        results = match.group('response')
    else:
        results = response
    return results

def parse_lines(parse_string, response):
    """ returns a response parsed using 'include', 'section', 'begin', or 'until' """
    # get all operations
    operations = []
    # declare valid operations
    valid_operations = ['include', 'exclude', 'section', 'esection', 'begin', 'until']
    # get valid pieces of the command
    pieces = parse_string.split(' | ')
    # for each operation
    for piece in pieces:
        # get the first word of the operation and the pattern
        match = re.search(r"(?P<word>\S+)[ ]+(?P<pattern>.*)", piece)
        # if a first word and pattern was found
        if match is not None:
            # collect the first word and pattern
            first_word = match.group('word')
            pattern = match.group('pattern')
            # if there was a pattern specified
            if len(pattern) > 0:
                # for each valid operation
                for valid_operation in valid_operations:
                    # if this is a valid operation
                    if valid_operation.startswith(first_word):
                        # append it to the operations list
                        operations.append([valid_operation, pattern])
                        break
    # for each operation
    for operation, pattern in operations:
        # parse the response
        if operation == 'begin':
            response = begin(pattern, response)
        elif operation == 'until':
            response = until(pattern, response)
        elif operation == 'include':
            response = include(pattern, response)
        elif operation == 'exclude':
            response = exclude(pattern, response)
        elif operation == 'section':
            response = section(pattern, response)
        elif operation == 'esection':
            response = esection(pattern, response)
    # return the response
    return response

