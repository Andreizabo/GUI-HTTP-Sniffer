# importing the requests library
import time
import tqdm
import requests


def get_req():
    url = "http://192.168.100.25:80"

    # defining the parameters to be sent
    params = {'message': 'Hello world!'}

    # sending get request
    requests.get(url=url, params=params)


def post_req():
    url = "http://192.168.100.25:80"

    # defining the parameters to be sent
    params = {'message': 'Hello world!'}

    # sending post request
    requests.post(url=url, params=params)


if __name__ == '__main__':
    while True:
        try:
            get_req()
        except:
            pass
        print('\nsent get\n')
        try:
            post_req()
        except:
            pass
        print('\nsent post\n')
        for _ in tqdm.tqdm(range(10)):
            time.sleep(0.5)
