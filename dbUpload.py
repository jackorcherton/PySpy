from requests import post

def send():
    """Uploads Database to Ubuntu Server"""
    print("____________________________________________________\n\nDatabase Upload\n")
    print("Uploading file")
    file = open('info.sqlite3', 'rb')
    try:
        r = post("https://error404coventry.hopto.org/", files={'file': file})
        print(r.text)
    except ConnectionError:
        print("Cannot connect - check server is on / has active internet connection")
    file.close()

if __name__ == '__main__':  send()#If the program isn't being imported - it will automatically run