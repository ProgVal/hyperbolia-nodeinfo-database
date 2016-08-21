#!/usr/bin/env python3
import os
import re
import json
import time
import resource
import requests
import multiprocessing
import multiprocessing.dummy

DB_FILE = './nodeinfo_database.json'

#GRAPH_JSON_URL = 'http://map.hype.ovh/static/graph.json'
GRAPH_JSON_URL = 'https://www.fc00.org/static/graph.json'

REQUEST_TIMEOUT = 10 # in seconds
MAX_HEAP_SIZE = 10*1024*1024 # in bytes

_trailing_comma_re = re.compile(',+(?P<delim>\s*[\\}\\]])')
_missing_colon_re = re.compile('"\s+(?P<char>[a-zA-Z0-9"])')
def fix_json(s):
    """Fix a erros in JSON string caused by humans writing the nodeinfo.json
    without following the JSON spec."""
    s = _trailing_comma_re.sub(lambda m: m.group('delim'), s)
    s = _missing_colon_re.sub(lambda m: '":' + m.group('char'), s)
    return s

def get_nodes(url):
    """Return a list of nodes from a public database."""
    graph = requests.get(url).json()
    return graph['nodes']


def _request_worker(url, queue):
    """A worker process that requests an (untrusted) URL while limiting its
    heap size to prevent memory bombs from malicious servers."""
    rsrc = resource.RLIMIT_DATA
    resource.setrlimit(rsrc, (MAX_HEAP_SIZE, MAX_HEAP_SIZE))
    try:
        response = requests.get(url)
    except requests.exceptions.ConnectionError:
        return
    except ValueError as e:
        print('Error for {}: {}'.format(url, e.args[0]))
        return
    except requests.exceptions.Timeout:
        return
    queue.put(response)

def request(url):
    """Makes a request to an untrusted URL, with protection against
    memory bombs and requests that do not timeout."""
    queue = multiprocessing.Queue()
    try:
        proc = multiprocessing.Process(target=_request_worker, args=(url, queue))
        proc.start()
        proc.join(REQUEST_TIMEOUT)
        if proc.is_alive():
            proc.terminate()
            return None
        elif queue.empty():
            return None
        else:
            return queue.get()
    finally:
        queue.close()

def get_nodeinfo(ip_address):
    """Return the decoded content of nodeinfo.json if any, None otherwise."""
    url = 'http://[{}]/nodeinfo.json'.format(ip_address)
    response = request(url)
    if response is None or not response.ok:
        return None
    content_type = response.headers['Content-Type'].split(';')[0]
    if content_type in {'text/html', 'application/xhtml+xml', 'application/xml'}:
        # Don't even try to parse these
        return None
    content = response.text
    content = fix_json(response.text)
    try:
        return json.loads(content)
    except ValueError:
        print('Warning: could not decode JSON from {}'.format(url))
        return None

def get_nodeinfo_worker(node):
    node_id = node['id']
    nodeinfo = get_nodeinfo(node_id)
    if nodeinfo is None:
        print('{} has no nodeinfo.'.format(node_id))
        return (node_id, None)
    else:
        print('{} has a nodeinfo.'.format(node_id))
        return (node_id, nodeinfo)

def write_db(filename, db):
    """Write the nodeinfo database to a file."""
    if os.path.isfile(filename):
        os.unlink(filename)
    with open(filename, 'a') as fd:
        json.dump(db, fd, indent=4, sort_keys=True)

def main():
    if os.path.isfile(DB_FILE):
        with open(DB_FILE, 'rt') as fd:
            db = json.load(fd)
    else:
        db = {}

    nodes = get_nodes(GRAPH_JSON_URL)
    with multiprocessing.dummy.Pool(100) as pool:
        results = pool.map(get_nodeinfo_worker, nodes)

    for (node, nodeinfo) in results:
        db[node] = {
                'last_crawl': time.time(),
                'nodeinfo': nodeinfo,
                }
    write_db(DB_FILE, db)

if __name__ == '__main__':
    #print(get_nodeinfo_worker({'id': 'fcd6:9c33:dd06:3320:8dbe:ab19:c87:f6e3'}))
    main()
