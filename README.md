<h1 align="center">
  <a href="https://github.com/odedlaz/suex"><img src="https://oded.blog/images/2017/10/suex_xkcd.png" alt="suex" width="256" height="256"/></a><br>
  <a href="https://github.com/odedlaz/suex"><b>S</b>witch <b>U</b>ser <b>Ex</b>ecute</a>
</h1>

<h4 align="center">A complete re-implementation of OpenBSD's doas that's extremely more robust</h4>

*doas* is a utility created by Ted Unagst (an OpenBSD developer) that aimed to replace *sudo* for most ordinary use cases. He explained why he wrote *doas* in a blog post: [doas - dedicated openbsd application subexecutor](https://www.tedunangst.com/flak/post/doas).

The gist is that `sudo` is hard to configure and does a lot more then the standard user needs.  

`doas` was created in order to replace `sudo` for regular folks like me and you.

## Why Another Port?

However, `doas` only targets *OpenBSD*, and lacked features that I felt were missing from it and `sudo` as well.  
Furthermore, all ports I looked at weren't production ready & poorly written.

Instead of creating my own port, I decided to re-write `doas` and create a new version that fixes the issues I care about.

## Project Goals

* ***Secure***. Users must not be able to abuse the utility, and it should protect users from making stupid mistakes.

* ***Easy***. The utility should be easy to audit, to maintain, to extend, and to contribute to.

* ***Friendly***. Rule creation should be straightforward. Rules should be easy to understand and easy to debug.

* ***Powerful***. Rules should be short, concise, and allow fine-grained control.

* ***Feature Parity***. This project should have *complete* feature parity with the original utility.

To achieve these goals, the following design decisions were made:

1. The whole project was implemented in modern C++
2. Explicit is better then implicit (for instance, rule commands must be absolute paths)
3. Prefer using the standard library when possible - for the sake of security and maintainability.
5. Commands are globs, which allows the same rule to be used for many executables.
1. Arguments are PCRE-compliant regular expressions, which allows the creation of fine-grained rules.

## Getting started

pre-compiled `.deb` and `.rpm` packages are [uploaded on each release](https://github.com/odedlaz/suex/releases).

## Fedora

The project is currently available in a [Copr](https://copr.fedorainfracloud.org/coprs/odedlaz/suex):
```bash
$ sudo dnf copr enable odedlaz/suex
$ sudo dnf install -y suex
```

You can also build it from source:
```bash
$ git clone https://github.com/odedlaz/suex.git
$ sudo dnf install -y cmake pam-devel elfutils-devel rubygem-ronn gcc-c++
$ mkdir -p suex/build && cd suex/build && cmake .. && cd ..
```

## Ubuntu

The project has a pre-compiled `deb` available at the [release page](https://github.com/odedlaz/suex/releases).

You can also build it from source:
```bash
$ git clone https://github.com/odedlaz/suex.git
$ sudo apt install -y cmake libpam-dev libdw-dev ruby-ronn g++ rpm
$ mkdir -p suex/build && cd suex/build && cmake .. && cd ..
```

**[!]** A [PPA](https://help.ubuntu.com/community/PPA) is coming soon.

## Arch

**[!]** coming soon...

## Project Status

The project *is in beta* and will be until it reaches the `1.0` milestone.  
I don't expect any major features to be added until then.

In order to reach 1.0 the project must:

1. get a good-enough unit & system test coverage.
2. pass a professional security audit.
3. have a continuous test & integration pipeline.
4. be available on major *client* distributions, i.e: Ubuntu, Fedora, Arch
5. have both an faq & examples page that have enough quality content in them

## Authors

The main author is [Oded Lazar](https://oded.blog/whoami/)

## Contributions

I gladly accept contributions via GitHub pull requests.

If you are interested in contributing but not sure where to start, feel free [to contact me](https://twitter.com/odedlaz).

Once I feel this method is not effective anymore, I'll probably open a slack / irc channel.
