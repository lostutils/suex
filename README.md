<h1 align="center">
  <a href="https://github.com/odedlaz/doas"><img src="https://oded.blog/images/2017/10/doas_xkcd.png" alt="doas" width="256" height="256"/></a><br>
  <a href="https://github.com/odedlaz/doas">doas</a>
</h1>

<h4 align="center">A complete re-implementation of OpenBSD's doas that's extremely more robust</h4>

*doas* is a utility that is aimed to replace *sudo* for most ordinary use cases.
Ted Unagst's, an OpenBSD developer, explained why He originally wrote it in his blog post: [doas - dedicated openbsd application subexecutor](https://www.tedunangst.com/flak/post/doas).

The gist is that `sudo` is hard to configure and does a lot more then the standard user needs.  

`doas` was created in order to replace `sudo` for regular folks like me and you.

## Why Another Port?

The original utility only targeted *OpenBSD*, and lacked features that I felt were missing from it and `sudo` as well.  
Furthermore, all ports I looked at weren't production read & poorly written.

## Changes compared to the original

### Security checks

The original `doas` doesn't check the owners & permissions of the binary and configuration file.
`sudo` checks those, but only warns the user.

This version ensures the binary and configuration file are owned by `root:root`.  
It also ensures the binary has [setuid](https://en.wikipedia.org/wiki/Setuid), and that the configuration file has only read permissions.

Furthermore, only full paths of commands are allowed in the configuration file.  
The idea is that privileged users (i.e: members of the *wheel* group) need to explicitly set the rule instead of depending on the running user's path.

### Edit mode

```bash
doas -E
```

`doas` allows any privileged user (i.e: members of the *wheel* group) to edit the configuration file safely.
Furthermore, if the configuration file is corrupted, privileged users can still access it and edit it.

The edit option is similar to `visudo`, it creates a copy of the configuration and updates the real configuration only when the copy is valid.

Non-privileged users are not allowed to edit the configuration.

### Verbose mode

```
doas -V
```

`doas` allows to show logging information to privileged users. That information shows which rules are being loaded & how they are processed.  

Non-privileged users are not allowed to turn on verbose mode.

###  Dump mode

```
doas -D
```

`doas` allows the user to dump the permissions it loaded to screen.  
group permissions and command globs are expanded into individual rules as well.

privileged users see the permissions of all users instead of only their own.

## Project Goals

* ***Secure***. User's must not be able to abuse the utility, and it should protect the user from making stupid mistakes.

* **Easy**. The utility should be easy to audit, to maintain, to extend and to contribute to.

* ***Friendly***. Rule creation should be straight forward. Rule should be easy to understand and easy to debug.

* ***Powerful***. Rules should be short, concise and allow find-grained control.

* ***Feature Parity***. This project should have *complete* feature parity with the original utility.

To achieve these goals, the following design decisions were made:

1. The whole project was implemented in modern C++.
2. Explicit is better then implicit (for instance, rule commands must be absolute paths)
3. Prefer using the standard library when possible - for the sake of security and maintainability.
5. Commands are globs, which allows to use the same rule for many executables.
1. Arguments are PCRE-compliant regular expressions, which allows to create fine-grained rules.

## Getting started

You can find pre-compiled `.deb` and `.rpm` packages in the [releases page](https://github.com/odedlaz/doas/releases).

**[!]** [Ubuntu PPA](https://help.ubuntu.com/community/PPA) & [Fedora Copr](https://docs.pagure.org/copr.copr/)  are coming soon.

### Building from source

#### Fedora

```bash
$ git clone https://github.com/odedlaz/doas.git
$ sudo dnf install -y cmake pam-devel elfutils-devel
$ mkdir -p doas/build && cd doas/build && cmake .. && cd ..
```

#### Ubuntu

```bash
$ git clone https://github.com/odedlaz/doas.git
$ sudo apt install -y cmake libpam-dev libdw-dev  
$ mkdir -p doas/build && cd doas/build && cmake .. && cd ..
```

**[!]** If you're familiar with [direnv](https://oded.blog/2016/12/29/direnv/) and use  [fish shell](https://fishshell.com/) you'll enjoy a pre-baked environment.

## Authors

The main author is [Oded Lazar](https://oded.blog/whoami/)

## Contributions

I gladly accept contributions via GitHub pull requests. 

If you are interested in contributing but not sure where to start, feel free to contact me.

Once I feel this method is not effective anymore, I'll probably create a slack channel or IRC channel.


## Examples

Ted Unagst's wrote a great blog post called [doas mastery](https://www.tedunangst.com/flak/post/doas-mastery). Because the project has *complete feature parity* with the OpenBSD version, the mentioned post should be a good starting point.

Never the less, there are some powerful enhancments in this release that deserve special attention.


### fine-grained package management

```
deny odedlaz as root cmd /usr/bin/dnf args (autoremove|update|upgrade).+
permit keepenv nopass odedlaz as root cmd /usr/bin/dnf args (autoremove|update|upgrade)$
```

The first rule denies `odedlaz` of running `dnf` as `root` with any arguments that start with `autoremove`, `update` & `upgrade` and have other arguments as well.

The second rule allows `odedlaz` to run `dnf` as `root` only with `autoremove`, `update`, `upgrade` and no other arguments.

These protect `odedlaz` from  from accidentally running `dnf autoremove -y` or `dnf upgrade -y`, even if He's a privileged user (a member of the `wheel` group).

On the other hand, it allows `odedlaz` to run these commands without a password (`nopass`) if they are executed without any trailing arguments.

### rm -rf protection

```
deny odedlaz as root cmd /bin/rm args .*\s+/$
```

The above rule protects `odedlaz` from accidentally running `rm -rf /` and the like.

### one rule, multiple executables

```
permit keepenv nopass odedlaz as root cmd /home/odedlaz/Development/doas/tools/* args .*
```

The above rule allows `odedlaz` to run any executable found at `/home/odedlaz/Development/doas/tools` with any arguments, as `root` without requiring a password.
