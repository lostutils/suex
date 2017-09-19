DOAS(1) -- execute commands as another user
=============================================

## SYNOPSIS

`doas` \[`-Lns`] \[`-a` *style*] \[`-C` *config*] \[`-u` *user*] *command* \[*args*]

## DESCRIPTION

The **doas** utility executes the given command as another user.
The command argument is mandatory unless `-C`, `-L`, or `-s` is specified.

The options are as follows:

  * `-a` *style*:
    Use the specified PAM configuration file when validating the user. These can be found in **pam.d(5)**.

  * `-C` *config*:
    Parse and check the configuration file *config*, then exit. If *command* is
    supplied, `doas` will also perform command matching. In the latter case either
    ‘permit’, ‘permit nopass’ or ‘deny’ will be printed on standard output,
    depending on command matching results. No command is executed.

  * `-L`:
    Clear any persisted authorizations from previous invocations, then immediately exit. No command is executed.

  * `-n`:
    Non interactive mode, fail if **doas** would prompt for password.

  * `-u` *user*:
    Execute the command as user. The default is root.

  * `-E`:
    Edit */etc/doas.conf*, fail if user is not a member of the *wheel* group.

  * `-D`:
    Print loaded permissions. Will print all permissions, unless user is not
    a member of the *wheel* group. In that case, will only print the user's permissions.

  * `-s`:
    Execute the shell from *SHELL* or */etc/passwd*.

  * `-V`:
    Turn on verbose output, fail if user is not a member of the *wheel* group.

  * `-v`:
    Show version and exit.

## EXIT STATUS

The `doas` utility exits 0 on success, and > 0 if an error occurs.  
It may fail for one of the following reasons:

   * The config file /etc/doas.conf could not be parsed.
   * The user attempted to run a command which is not permitted.
   * The password was incorrect.
   * The specified command was not found or is not executable.

## SEE ALSO

su(1), doas.conf(5), pam(5), pam.d(5)

## AUTHORS

Oded Lazar <<odedlaz@gmail.com>>
