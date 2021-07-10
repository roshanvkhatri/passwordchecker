import hashlib
import requests
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error Fetching : {res.status_code}')
    return res


def get_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    password_sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five, tail = password_sha1[:5], password_sha1[5:]
    response = request_api_data(first_five)
    return get_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'your password "{password}" was found {count} times')
        else:
            print(f"your '{password}' was not found, you're good to go")
    return 'Done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
