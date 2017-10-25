# Changes compared to `doas`

## Security checks

### Owenership & Permissions

`doas` doesn't check the owners & permissions of the binary and configuration file.
`sudo` checks those, but only warns the user.

This version ensures the binary and configuration file are owned by `root:root`.  
It also ensures the binary has [setuid](https://en.wikipedia.org/wiki/Setuid), and that the configuration file has only read permissions.

Furthermore, only full paths of commands are allowed in the configuration file.  
The idea is that privileged users (i.e: members of the *wheel* group) need to explicitly set the rule instead of depending on the running user's path.

### Rule Creation

`doas` allows users to ommit the `as` and `cmd` keywords.  
if `as` is not specified, `root` is used.
if `cmd` is not specified, the command works on all binaries.
if `args` is empty, the command doesn't match for processes with arguments.

`suex` works a bit differently:
- `as` and `cmd` are mandatory. You have to specify them.
- `args` is not mandatory. if omitted, only the cmd matches.
  if you want to match *any* args, use `args .*` instead.

## Modes

The following sections detail new command line toggles that aren't available in `doas`.

### Edit mode

```bash
suex -E
```

`suex` allows any privileged user (i.e: members of the *wheel* group) to edit the configuration file safely.
Furthermore, if the configuration file is corrupted, privileged users can still access it and edit it.

The edit option is similar to `visudo`, it creates a copy of the configuration and updates the real configuration only when the copy is valid.

Non-privileged users are not allowed to edit the configuration.

### Verbose mode

```bash
suex -V
```

`suex` allows to show logging information to privileged users. That information shows which rules are being loaded & how they are processed.  

Non-privileged users are not allowed to turn on verbose mode.

###  List mode

```bash
suex -l
```

`suex` allows the user to dump the permissions it loaded to screen.  
group permissions and command globs are expanded into individual rules as well.

privileged users see the permissions of all users instead of only their own.
## Examples

Ted Unagst's wrote a great blog post called [doas mastery](https://www.tedunangst.com/flak/post/doas-mastery). Because `suex` has *complete feature parity* with `doas`, the mentioned post should be a good starting point.

Never the less, there are some powerful enhancments in this release that deserve special attention.
