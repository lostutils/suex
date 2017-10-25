## fine-grained package management

```
deny odedlaz as root cmd /usr/bin/dnf args (autoremove|update|upgrade).+
permit keepenv nopass odedlaz as root cmd /usr/bin/dnf args (autoremove|update|upgrade)$
```

The first rule denies `odedlaz` of running `dnf` as `root` with any arguments that start with `autoremove`, `update` & `upgrade` and have other arguments as well.

The second rule allows `odedlaz` to run `dnf` as `root` only with `autoremove`, `update`, `upgrade` and no other arguments.

These protect `odedlaz` from  from accidentally running `dnf autoremove -y` or `dnf upgrade -y`, even if He's a privileged user (a member of the `wheel` group).

On the other hand, it allows `odedlaz` to run these commands without a password (`nopass`) if they are executed without any trailing arguments.

## rm -rf protection

```
deny odedlaz as root cmd /bin/rm args .*\s+/$
```

The above rule protects `odedlaz` from accidentally running `rm -rf /` and the like.

## one rule, multiple executables

```
permit keepenv nopass odedlaz as root cmd /home/odedlaz/Development/suex/tools/* args .*
```

The above rule allows `odedlaz` to run any executable found at `~/Development/suex/tools` with any arguments, as `root` without requiring a password.
