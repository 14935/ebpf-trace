import re


def detected_sql_injection(request: str) -> bool:
    match = None
    req = request[0 if request.find("';") == -1 else 2:].lower()
    cmd = [i for i in req.split(' ') if len(i) != 0][0]
    if cmd == 'select':
        match = re.match(r'\s?select\sd?i?s?t?i?n?c?t?\s?[\w*,.]+\sfrom\s\w+', req)
    elif cmd == 'update':
        match = re.match(r'\s?update\s\w+\sset\s[\w+?=,\s]+', req)
    elif cmd == 'insert':
        match = re.match(r"\s?insert\sinto\s\w+\s\(?[\w+,\s]+\)?\svalues\s\([\w'+,\s]+\)", req)
    elif cmd == 'drop':
        match = re.match(r'\s?drop\s\w+$', req)
        if match is None:
            match = re.match(r'\s?drop\sview \w+$', req)
    elif cmd == 'show':
        match = re.match(r'\s?show\s\w+$', req)
    elif cmd == 'use':
        match = re.match(r'\s?use\s\w+$', req)
    elif cmd == 'source':
        match = re.match(r'\s?source\s\w+.sql$', req)
    elif cmd == 'describe':
        match = re.match(r'\s?describe\s\w+$', req)
    elif cmd == 'create':
        match = re.match(r'\s?create\stable\s\w+ \(', req)
        if match is None:
            match = re.match(r'\s?create\sview\s\w+\sas', req)
    elif cmd == 'delete':
        match = re.match(r'\s?delete\sfrom\s\w+', req)

    if match is None:
        return False

    return True


if __name__ == '__main__':
    s = input()
    print(detected_sql_injection(s))
