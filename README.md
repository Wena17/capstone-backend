# Running locally

Don't forget to start the postgres db server as Flask shuts it down when you press Ctrl-C:

```
pg_ctl start
flask run --cert=adhoc
```

Https is required to enable the geo location API in the browser, which is required during registration to learn the location of the device.


|                   |   Outage is ongoing   |    No Outage ongoing
|-------------------|-----------------------|-------------------------
| voltage is zero   |    do nothing         |    new outage
| voltage is not zero |  outage ended       |   do nothing
