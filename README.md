
# chefexplore

Script to sync Chef nodes information to Device42 (http://device42.com)


# Requirements

You will need to install `pychef` Python's packege: [https://github.com/coderanger/pychef](https://github.com/coderanger/pychef).


# Configure

Take the file `settings.yaml.example` and rename it to `settings.yaml`. Then change the settings to correct ones.

Note that for Chef Server >= 12 you should set up 'organization' parameter.

You should obtain client name and its key file to be able to connect to Chef server.

See [NodeFilter.md](./NodeFilter.md) for node filtering options.


# Run

```
    python chefexplore.py [-c /path/to/settings.yaml]
```


# Bugs / Feature Requests

Please attach node info from chef/ohai while sending bugs/feature requests. It can help to understand your specifics.
