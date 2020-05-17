"""
This script fetches a list of malicious domains from both Q and CTI.
Since CTI is fed from honeypot incidents, we need Q for reveal data which resides in the "task" collection.
"""

__author__ = 'Ophir Harpaz'


import argparse
import datetime as dt
import json
import logging
import pymongo
from models.iocs_models import Dns
from models.utils import connect_to_cti_db
from sshtunnel import SSHTunnelForwarder, BaseSSHTunnelForwarderError


Q_CONFIG_FILE = 'Q_config.json'
CTI_CONFIG_FILE = 'config.json'
LOG_FILE = 'quad9_domains.log'
MONGO_PORT = 27017
TASK_COLLECTION = 'task'


class QServer:
    def __init__(self, public_addr, private_addr, username, password, db_name):
        self.public_addr = public_addr
        self.private_addr = private_addr
        self.username = username
        self.password = password
        self.db_name = db_name
    
    def __repr__(self):
        return 'Q Server ({}, {})'.format(self.public_addr, self.private_addr)


def get_args():
    parser = argparse.ArgumentParser(
        description='Fetch malicious domains from CTI and Q for a specified period of time')
    today = dt.datetime.today()
    week_ago = today - dt.timedelta(days=7)
    parser.add_argument('-qc', '--q-config', help='path to Q configuration file', default=Q_CONFIG_FILE)
    parser.add_argument('-cc', '--cti-config', help='path to CTI configuration file', default=CTI_CONFIG_FILE)
    parser.add_argument('st', help='start time', default=week_ago)
    parser.add_argument('et', help='end time', default=today)
    return parser.parse_args()


def get_q_servers_from_config(config_file):
    with open(config_file) as f:
        config = json.load(f)
    return [
        QServer(e['public'], e['private'], config['user'], config['password'], config['db_name'])
        for e in config['servers']
    ]


def get_collection(q, collection_name):
    connection = pymongo.MongoClient()  # localhost:27017
    db = connection[q.db_name]
    collection = db[collection_name]
    return collection


def fetch_domains_per_period_from_q(q, start_time, end_time):
    # SSH Tunnel
    try:
        server = SSHTunnelForwarder(
            q.public_addr,
            ssh_username=q.username,
            ssh_password=q.password,
            remote_bind_address=(q.private_addr, MONGO_PORT),
            local_bind_address=("localhost", MONGO_PORT)
        )
        server.start()
        logger.info('SSH-tunneled to {}'.format(q))
    except BaseSSHTunnelForwarderError:
        logger.warning('Could not SSH-tunnel to {}'.format(q))
        return set()
    
    # Fetch data
    task_collection = get_collection(q, TASK_COLLECTION)
    # Malicious domain between the specified time range.
    # Note this query satisfies one of the collection's indexes
    cur = task_collection.find({'$and': [
        {'task_kwargs.domain_name': {"$exists": True}},
        {'result.verdict': 'malicious'},
        {"time_start": {"$gt": start_time}},
        {"time_start": {"$lt": end_time}},
    ]}, {'task_kwargs.domain_name': True})
    
    t = dt.datetime.now()
    domains = set(x['task_kwargs']['domain_name'] for x in cur)
    logger.info('Fetching domains from cursor took {} seconds'.format(dt.datetime.now() - t))
    
    # Terminate tunnel
    server.stop()
    
    logger.info('Fetched {} domains'.format(len(domains)))
    return domains


def get_cti_domains_per_period(start_time, end_time):
    return list(Dns
                .select(Dns.dns_record).distinct()
                .where(Dns.first_seen < end_time, Dns.first_seen >= start_time))


def fetch_all_malicious_domains_per_period(start_time, end_time, config_file):
    domains = set()
    q_servers = get_q_servers_from_config(config_file)
    logger.info('Q Servers: {}'.format(q_servers))
    # for q_server in q_servers:
    #     new_domains = fetch_domains_per_period_from_q(q_server, start_time, end_time)
    #     domains.update(new_domains)
    
    new_domains = get_cti_domains_per_period(start_time, end_time)
    domains.update(new_domains)
    return domains


if __name__ == '__main__':
    # Logging
    logger = logging.getLogger()
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
    
    # Arguments
    args = get_args()
    q_conf = args.q_config
    cti_conf = args.cti_config
    st = dt.datetime.strptime(args.st, '%d/%m/%Y')
    et = dt.datetime.strptime(args.et, '%d/%m/%Y')
    logger.info('Fetching domains for period {} to {}'.format(st, et))
    
    # Work!
    connect_to_cti_db(cti_conf)
    logger.info('connected to CTI')
    all_domains = fetch_all_malicious_domains_per_period(st, et, q_conf)
    output_file = 'quad9_domains_{}_{}.txt'.format(args.st, args.et).replace('/', '')
    with open(output_file, 'w') as f:
        f.write('\n'.join(all_domains))
