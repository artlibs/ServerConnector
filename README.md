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
  sc [command]           Connect with normal user
  sc [command] x         Connect with admin user
  sc --encrypt-config    Encrypt passwords in config file

Available commands:

 dev        32.*.*.161      Aliyun devp server
 pro        115.*.60.*      Aliyun prod server

$
```

