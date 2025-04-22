# ServerConnector
sc - Just a SSH server connector command



### Init

-   need golang 1.23.0

### install

```shell
$ make install
Installing sc...
Creating default gitconfig...
Done. Edit /etc/sc/config.yml to configure.
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
  sc [environ] e         Switch to [environ] git & ssh config
  sc --encrypt-config    Encrypt passwords in config.yml file

Available commands:

 dev        32.*.*.161      Aliyun devp server
 pro        115.*.60.*      Aliyun prod server

Available environments:

  Current: f
  * pro          My production env
    dev          My developement env

$
```

