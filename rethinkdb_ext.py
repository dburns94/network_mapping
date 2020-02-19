#!/usr/bin/python3.6

import re
import rethinkdb as rdb
import networking as n
import time_ext as t_ext

r = rdb.RethinkDB()
default_server = '10.32.210.136'

def connect(server=default_server, ro=False):
    """ returns a connection to rethinkdb server """
    if ro:
        return r.connect(host=server, port=28015, user='readonly', password='r3@d0n!y').repl()
    else:
        return r.connect(host=server, port=28015, password='myth0s').repl()

def get_dbs(server=default_server):
    """ returns all databases from the server """
    # open connection to server
    conn = connect(server=server)
    databases = r.db_list().run()
    # close connection to the server
    conn.close()
    return databases

def get_tables(database, server=default_server):
    """ returns all tables in a database """
    # open connection to server
    conn = connect(server=server)
    tables = r.db(database).table_list().run()
    # close connection to the server
    conn.close()
    return tables

def get_unique_id(server=default_server):
    """ returns a unique ID to be used for a data entry """
    # open connection to server
    conn = connect(server=server)
    unique_id = r.uuid().run()
    # close connection to the server
    conn.close()
    return unique_id

def add_unique_ids(dataset, server=default_server):
    # ensure dataset is an array
    if type(dataset) is not list:
        dataset = [dataset]
    # open connection to server
    conn = connect(server=server)
    # for each array item
    for i in range(len(dataset)):
        # if data has no ID
        if dataset[i].get('id') is None:
            # add a unique ID
            dataset[i]['id'] = r.uuid().run()
    # close connection to the server
    conn.close()
    return dataset

def get_data(database, table, refine=None, pattern=None, server=default_server):
    """ returns a set of data from the server, database, and table """
    # open connection to server
    conn = connect(server=server)
    if refine is not None:
        # get the filtered data
        dataset = list(r.db(database).table(table).filter(refine).run())
    elif pattern is not None:
        # initialize data filter
        data_filter = {}
        # initialize pattern, if necessary
        if pattern is None:
            pattern = ''
        # declare filter methods
        invert = re.compile(r"NOT\((?P<pattern>.+)\)", re.I)
        contains = re.compile(r"CONTAIN(S)?\((?P<pattern>.+)\)", re.I)
        starts_with = re.compile(r"START(S)?\((?P<pattern>.+)\)", re.I)
        ends_with = re.compile(r"END(S)?\((?P<pattern>.+)\)", re.I)
        # seperate fields
        fields = pattern.split('&')
        # for each field
        for field in fields:
            # initialize values
            invert_match = False
            regex = None
            # seperate key and value
            key, value = field.split('=')
            # if any value is acceptable
            if value == 'any':
                # remove the key from the filter
                new_filter = {}
                for filter_key, filter_value in data_filter.items():
                    if filter_key != key:
                        new_filter[key] = filter_value
                data_filter = new_filter
                continue
            # if user wants to use NOT
            match = invert.fullmatch(value)
            if match is not None:
                invert_match = True
                value = match.group('pattern')
            # if user wants to use CONTAINS
            match = contains.fullmatch(value)
            if match is not None:
                regex = match.group('pattern')
            else:
                # if user wants to use STARTS
                match = starts_with.fullmatch(value)
                if match is not None:
                    regex = r"(?m)^"+match.group('pattern')
                else:
                    # if user wants to use ENDS
                    match = ends_with.fullmatch(value)
                    if match is not None:
                        regex = r"(?m)"+match.group('pattern')+r"$"
                    else:
                        regex = r"(?m)^"+value+r"$"
            # store the values determined
            data_filter[key] = { 'invert': invert_match, 'pattern': re.compile(regex, re.I) }
        # get all data
        dataset = []
        all_data = list(r.db(database).table(table).run())
        # for each data entry
        for data in all_data:
            keep = True
            # for each filter determined
            for key, value in data_filter.items():
                # if data does not contain the key
                if data.get(key) is None:
                    # don't keep this data
                    keep = False
                    break
                data_value = str(data.get(key))
                # determine if the pattern matches
                match = value['pattern'].search(data_value)
                # if pattern is NOT but match was found
                if value['invert'] and match is not None:
                    # don't keep this data
                    keep = False
                    break
                # if match was not found
                elif not value['invert'] and match is None:
                    # don't keep this data
                    keep = False
                    break
            # if keeping this data
            if keep:
                # add it to the final list
                dataset.append(data)
    else:
        # get all data
        dataset = list(r.db(database).table(table).run())
    # close connection to the server
    conn.close()
    return dataset

def delete_data(database, table, dataset, server=default_server):
    """ deletes data from the server, database, and table """
    # ensure dataset is an array
    if type(dataset) is not list:
        dataset = [dataset]
    # open connection to server
    conn = connect(server=server)
    # for each array item
    for data in dataset:
        # if the item is a string
        if type(data) is str:
            data_id = data
        else:
            data_id = data['id']
        # delete the data
        r.db(database).table(table).get(data_id).delete().run()
    # close connection to the server
    conn.close()

def insert_data(database, table, dataset, server=default_server):
    # ensure dataset is an array
    if type(dataset) is not list:
        dataset = [dataset]
    # open connection to server
    conn = connect(server=server)
    # for each array item
    for data in dataset:
        # insert data into table
        r.db(database).table(table).insert(data).run()
    # close connection to the server
    conn.close()

def update_data(database, table, dataset, server=default_server):
    # ensure dataset is an array
    if type(dataset) is not list:
        dataset = [dataset]
    # open connection to server
    conn = connect(server=server)
    # for each array item
    for data in dataset:
        # update data in table
        r.db(database).table(table).get(data['id']).update(data).run()
    # close connection to the server
    conn.close()

#######################################################################################

def compare_data(old_dataset, new_dataset, match_key, days=1):
    # create Time class
    time = t_ext.Time()
    # create array of valid dates for data
    valid_dates = []
    for i in range(days+1):
        valid_dates.append(time.past_date(days=i))
    # determine data to delete
    old_valid_dataset = []
    delete_results = []
    for data in old_dataset:
        # if this data has a valid date
        if data.get('date') in valid_dates:
            # add it to the list of old data to keep
            old_valid_dataset.append(data)
        # if it does not have a valid date
        else:
            # add it to the list of data to delete
            delete_results.append(data)
    # get new data and data to update
    new_results = []
    update_results = []
    for data in new_dataset:
        missing = True
        update = False
        identified = data.get(match_key)
        for old_data in old_valid_dataset:
            # if the data matches
            if identified == old_data.get(match_key):
                missing = False
                # for each field in the new data
                for key, value in data.items():
                    # if the value doesn't match
                    if (match_key == 'id' or key != 'id') and old_data.get(key) != value:
                        # update the data
                        update = True
                        # get the id from the previous data
                        if old_data.get('id') is not None:
                            data['id'] = old_data['id']
                        elif data.get('id') is None:
                            data['id'] = get_unique_id()
                        update_results.append(data)
                        break
        # if missing and not updating
        if missing and not update:
            # this is new data
            new_results.append(data)
    # get missing data
    missing_results = []
    for old_data in old_valid_dataset:
        missing = True
        identified = old_data.get(match_key)
        for data in new_dataset:
            # if the data matches
            if identified == data.get(match_key):
                missing = False
        # if data is missing
        if missing:
            missing_results.append(old_data)
    return new_results, update_results, missing_results, delete_results

def get_device_by_id(device_id):
    data = get_data('collected_data', 'devices', refine={'id': device_id})
    if len(data) > 0:
        return data[0]
    return None

def get_interface_by_id(interface_id):
    data = get_data('collected_data', 'interfaces', refine={'id': interface_id})
    if len(data) > 0:
        return data[0]
    return None

def get_devices(pattern=None, server=default_server, database='collected_data', table='devices'):
    if pattern is None:
        pattern = 'status=active'
    else:
        pattern = 'status=active&'+pattern
    # return devices
    return get_data(database, table, pattern=pattern)

def get_network(ip):
    database = 'collected_data'
    table = 'ips'
    # if 'ip' is not an IP class
    if not isinstance(ip, n.IP):
        # create the IP class
        ip = n.IP(ip)
    # if the IP is not valid
    if not ip.valid:
        return None
    # get today's date
    date = t_ext.Time().date()
    # check database for IP address
    dataset = get_data(database, table, refine={'ip': ip.addr, 'date': date})
    # if any data was found
    if len(dataset) > 0:
        # return the info
        return get_network_data(dataset[0])
    # for each network that contains the IP/Network
    for network in ip.networks():
        # get devices that contain that subnet
        dataset = get_data(database, table, refine={'network': network, 'date': date})
        # if any data was found
        if len(dataset) > 0:
            # return the info
            return get_network_data(dataset[0])
    return None

def get_network_data(network):
    device = get_device_by_id(network['device_id'])
    interface = get_interface_by_id(network['intf_id'])
    # store data from the device
    return {'network': network, 'device': device, 'interface': interface}

###########################################################################
### START OF OLD FUNCTIONS - NEEDS REMOVED
###########################################################################

def getDevices(status="active", types="all", groups="all", server=default_server, database="tools", table="devices"):
    devices = []
    # create the filters
    deviceFilter = {}
    # if user specified a status
    if len(status) > 0:
        # if user did not want all status
        if status.lower() != "all" and status.lower() != "any":
            # capitalize 'active'
            if status.lower() == "active":
                status = "Active"
            # store the status
            deviceFilter['status'] = status
    # if types is a string
    if type(types) == str:
        # if user did not want all types
        if types.lower() != "all" and types.lower() != "any":
            # if user wants all CMTS
            if types.lower() == "cmts":
                types = ["E6000", "C100G", "CBR8", "9504N", "9516", "7360"]
            # if user wants all routers
            elif types.lower() == "routers":
                types = ["9500", "4500", "3850", "ASR9K", "CRS-X"]
            else:
                # store the type
                deviceFilter['model'] = types
    # if groups is a string
    if type(groups) == str:
        # if user did not want all groups
        if groups.lower() != "all" and groups.lower() != "any":
            # store the group
            deviceFilter['group'] = groups
    # if multiple types and groups were specified
    if type(types) == list and type(groups) == list:
        # for each group
        for group in groups:
            deviceFilter['group'] = group
            # for each type
            for deviceType in types:
                deviceFilter['model'] = deviceType
                # get the list of devices
                devices += get_data(database, table, refine=deviceFilter, server=server)
    # if multiple types and one group was specified
    elif type(types) == list:
        # for each type
        for deviceType in types:
            deviceFilter['model'] = deviceType
            # get the list of devices
            devices += get_data(database, table, refine=deviceFilter, server=server)
    # if one type and multiple groups were specified
    elif type(groups) == list:
        # for each group
        for group in groups:
            deviceFilter['group'] = group
            # get the list of devices
            devices += get_data(database, table, refine=deviceFilter, server=server)
    # if one type and one group was specified
    else:
        # get list of devices
        devices += get_data(database, table, refine=deviceFilter, server=server)
    # only keep unique devices
    id_list = []
    unique_devices = []
    for device in devices:
        data_id = device['id']
        if data_id not in id_list:
            id_list.append(data_id)
            unique_devices.append(device)
    return unique_devices

def get_ECs(group='all'):
    # declare HE information
    ec_list = [
        {'name': 'HE01 (BC01)', 'version': 'EC9', 'address': '10.253.1.1',     'group': 'VSS'},
        {'name': 'HE02 (BC02)', 'version': 'EC7', 'address': '10.253.2.1',     'group': 'VSS'},
        {'name': 'HE05 (BC05)', 'version': 'EC9', 'address': '10.253.5.1',     'group': 'VSS'},
        {'name': 'HE07 (BC07)', 'version': 'EC9', 'address': '10.253.7.1',     'group': 'VSS'},
        {'name': 'HE08 (BC08)', 'version': 'EC9', 'address': '10.253.8.1',     'group': 'VSS'},
        {'name': 'HE09 (CC05)', 'version': 'EC7', 'address': '172.16.44.7',    'group': 'VSS'},
        {'name': 'HE10 (BC10)', 'version': 'EC9', 'address': '10.253.10.1',    'group': 'VSS'},
        {'name': 'HE11 (CC03)', 'version': 'EC7', 'address': '172.27.11.71',   'group': 'VSS'},
        {'name': 'HE13 (BC13)', 'version': 'EC9', 'address': '10.253.13.1',    'group': 'VSS'},
        {'name': 'HE15 (BC15)', 'version': 'EC9', 'address': '10.253.15.1',    'group': 'VSS'},
        {'name': 'HE17 (CC06)', 'version': 'EC9', 'address': '172.16.45.244',  'group': 'VSS'},
        {'name': 'HE19 (CC04)', 'version': 'EC7', 'address': '172.16.45.7',    'group': 'VSS'},
        {'name': 'HE24 (CC01)', 'version': 'EC7', 'address': '172.16.128.6',   'group': 'VSS'},
        {'name': 'HE28 (CC02)', 'version': 'EC7', 'address': '172.27.3.198',   'group': 'VSS'},
        {'name': 'HE29 (CC08)', 'version': 'EC7', 'address': '172.16.46.7',    'group': 'INT'},
        {'name': 'HE32 (TC32)', 'version': 'EC9', 'address': '65.185.203.164', 'group': 'INT'},
        {'name': 'HE33 (TC33)', 'version': 'EC7', 'address': '65.185.203.180', 'group': 'INT'}
    ]
    if group.lower() == 'all':
        return ec_list
    # get list of only the group
    final_list = []
    for ec in ec_list:
        if ec['group'] == group:
            final_list.append(ec)
    return final_list

################################################################################################################################################
###### SG Status Functions
################################################################################################################################################
def convertDay(day):
    # split pieces of the day
    day_pieces = day.split(".")
    # get appropriate date
    this_date = t_ext.getPastDate(int(day_pieces[0]))
    # if this is the morning or noon check
    if len(day_pieces) > 1:
        # if this is the morning check
        if day_pieces[1] == "25":
            checkTime = "morning"
        # if this is the noon check
        elif day_pieces[1] == "5":
            checkTime = "noon"
        else:
            return 0
    # if this is the final check
    else:
        checkTime = "final"
    return {"date": this_date, "check": checkTime}

def getPreviousTimes(day):
    # split pieces of the day
    day_pieces = day.split(".")
    # if this is the morning or noon check
    if len(day_pieces) > 1:
        # if this is the morning check
        if day_pieces[1] == "25":
            # there is no previous checks today
            previous_times = []
        # if this is the noon check
        elif day_pieces[1] == "5":
            # today's only previous check is morning
            previous_times = [day_pieces[0] + ".25"]
        else:
            return 0
    # if this is the final check
    else:
        # today's previous checks are noon and morning
        previous_times = [day_pieces[0] + ".5", day_pieces[0] + ".25"]
    return previous_times

def getDaysAgo(day, num_days):
    # initialize array
    previousChecks = getPreviousTimes(day)
    # calculate previous day number
    day_before = int(day.split(".")[0]) + 1
    for i in range(num_days-1):
        next_day = str(day_before + i)
        # add previous day check
        previousChecks.append(next_day)
        previousChecks += getPreviousTimes(next_day)
    if num_days != 0:
        previousChecks.append(str(int(day.split(".")[0])+num_days))
    return previousChecks


