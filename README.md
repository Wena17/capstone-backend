# Running locally

Don't forget to start the postgres db server as Flask shuts it down when you press Ctrl-C:

```
pg_ctl start
flask run --cert=adhoc
```

Https is required to enable the geo location API in the browser, which is required during registration to learn the location of the device.

# Login stuff

https://hackersandslackers.com/flask-login-user-authentication/
https://flask-login.readthedocs.io/en/latest/
