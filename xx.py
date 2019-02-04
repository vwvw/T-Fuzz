import re
from collections import Counter

with open('haha2') as file2:
    bytes_addresses = []
    func = [[]]
    matched = False
    r = re.compile(r'^(?P<addr>0x[0-9a-fA-F]+): (?P<func_name>.+?)( (\| (?P<inst>[^A-Z]*?) )?(\| (?P<operation>.+) )?\| (?P<value>0x[0-9a-fA-F]+))? \| (((?P<dest>.+?) <-( (?P<src>.+?))?)|(?P<taint>.+?)?)\n$')
    for i, l in enumerate(file2.readlines()):
        if i %90  == 0:
            import ipdb; ipdb.set_trace()
            print i
            print len(bytes_addresses)
        res = r.match(l)
        if res:
            func_name = res.group('func_name').split(' ')[0]            
            if not matched:
                matched = True
                bytes_addresses.append({'obj': set([res.group('src')]), 'label': set([res.group('dest')])})
                func[0].append(func_name)
            else:
                if res.group('dest') and res.group('src'):
                    d = res.group('dest')
                    sourced = False
                    for s in reversed(sorted(res.group('src').replace('(', '').replace(')', '').split(' '))):
                        found = False
                        for i, byte in enumerate(bytes_addresses):
                            if s in byte['obj'] or s in byte['label']:
                                if d.endswith('_unknownobj'):
                                    bytes_addresses[i]['obj'].add(d)
                                    func[i].append(func_name)
                                else:
                                    #print s[-11:]
                                    func[i].append(func_name)
                                    bytes_addresses[i]['label'].add(d)
                                found = True
                        if not found and not sourced:
                            if not s.endswith('_unknownobj'):
                                continue
                            best_diff = None
                            idx = None
                            for i, byte in enumerate(bytes_addresses):
                                for addr in byte['obj']:
                                    diff = int(s[:-11], 16) -  int(addr[:-11], 16)
                                    if not best_diff:
                                        best_diff = diff
                                        idx = i
                                    else:
                                        if abs(diff) < abs(best_diff):
                                            best_diff = diff
                                            idx = i
                            if 0 <= idx + best_diff < len(bytes_addresses):
                                func[idx+best_diff].append(func_name)
                                bytes_addresses[idx+best_diff]['obj'].add(s)
                                bytes_addresses[idx+best_diff]['label'].add(d)
                            else:
                                diff = idx + best_diff
                                if diff > 0:
                                    while diff >= len(bytes_addresses):
                                        stro = bytes_addresses[-1]['obj'].pop()
                                        bytes_addresses[-1]['obj'].add(stro)
                                        bytes_addresses.append({'obj':set(['{:02x}_unknownobj'.format(int(stro[:-11],16) + 1)]), 'label':set()})
                                        func.append([])
                                    if s not in bytes_addresses[-1]['obj']:
                                        bytes_addresses[-1]['obj'].add(s)
                                    bytes_addresses[-1]['label'].add(d)
                                    func[-1].append(func_name)
                                else:
                                    assert diff < 0
                                    while diff < 0:
                                        diff += 1
                                        func.insert(0, [])
                                        bytes_addresses.insert(0, {'obj':set('{:02x}_unknownobj'.format(int(bytes_addresses[0]['obj'][0][:-11],16) - 1)), 'label':set()})
                                    if s not in bytes_addresses[0]['obj']:
                                        bytes_addresses[0]['obj'].add(s)
                                    bytes_addresses[0]['label'].add(d)
                                    func[0].append(func_name)
                        sourced = sourced or found



            #if res.    group('dest'):
            #    if d.endswith('_unknownobj'):
            #        visited.add(d[:-11])
            #    else:
            #        visited.add(d)
            #    if res.group('src') is not None:
            #        src = res.group('src').split(' ')
            #        for s in src:
            #            s2 = s#.replace('(', '').replace(')', '')
            #
            #            if s.endswith('_unknownobj'):
            #                s2 = s[:-11]
            #            if s2 not in visited and d is not None:
            #                addr = int(s2, 16)
            #                for i, b in enumerate(bytes_addresses):
            #                    for j, a in enumerate(b):
            #                        if abs(a - addr) < 200:



            #                nn.append(s)
            #    else:
            #        print 'no src'
            #        print l
            #elif res.group('operation') == 'IfGoto':
            #    pass
            #else:
            #    print "No dest"
            #    print l
            #
        else:
            print l
            pass
   # print visited
    for i,k in enumerate(bytes_addresses):
        if len(func[i]) > 0:
            print Counter(func[i])
    print len(bytes_addresses)
