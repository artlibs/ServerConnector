# ServerConnector
sc - Just a SSH server connector command



### Init

-   need golang 1.23.0

### install

```shell
$ sudo make install
sc installed to /usr/local/bin/sc with config /etc/sc/config.ini. Enjoy :)
```

### uninstall

```shell
$ sudo make uninstall
sc removed from your system :)
```

### sample

```shell
$ sc
Usage:
  sc    [command]     Connect with normal user
  sc -a [command]     Connect with admin user

Commands:

 dev        31.*.*.162      Aliyun devp server
 prod       114.*.61.*      Aliyun prod server

$
```

