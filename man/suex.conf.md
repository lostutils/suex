SUEX.CONF(5) -- suex configuration file
=======================================

## DESCRIPTION

The **suex(1)** utility executes commands as other users according to the rules
in the **suex.conf** configuration file.

rules have the following format:

   **permit**|**deny** [*options*] *identity* [**as** *target*] [**cmd** *command* [**args** ...]]

They consist of the following parts:

  * **permit**|**deny**:
   The action to be taken if this rule matches.

   * *options*:

       + `nopass`:
          The user is not required to enter a password.

       + `persist`:
          After the user successfully authenticates, do not ask for a password
          again for some time.

       + `keepenv`:
          The user's environment is maintained. The default is to reset the
          environment, except for the variables DISPLAY, HOME, LOGNAME, MAIL,
          PATH, TERM, USER and USERNAME.

       + `setenv {` [*variable*...] [*variable*=*value*. ..] `}`:
          In addition to the variables mentioned above, keep the space-separated
          specified variables. Variables may also be removed with a leading ‘-’
          or set using the latter syntax. If the first character of value is a 
          ‘$’ then the value to be set is taken from the existing environment 
          variable of the same name.

  * *identity*:
   The username to match. Groups may be specified by prepending a colon (‘:’).
   Numeric IDs are also accepted. The action to be taken if this rule matches.

  * `as` *target*:
   The target user the running user is allowed to run the command as. The
   default is all users.

  * `cmd` *command*:
   The command the user is allowed or denied to run. Relative paths are forbidden
   for security reasons. Commands are **glob(3)**, therefore multiple executables
   can be used.
   
  * `args` [*argument* ...]:
   Arguments to command. The command arguments provided by the user need to match
   those specified. The keyword **args** defaults to no arguments. Arguments
   are PCRE-compliant regular expressions.

The last matching rule determines the action taken. If no rule matches, 
the action is denied.

Comments can be put anywhere in the file using a hash mark (‘#’), and extend to 
the end of the current line.

The following quoting rules apply:

 - The text between a pair of double quotes (‘"’) is taken as is.

 - The backslash character (‘\’) escapes the next character, including new line 
   characters, outside comments; as a result, comments may not be extended over 
   multiple lines.

 - If quotes or backslashes are used in a word, it is not considered a keyword.

## FILES

  * `/etc/suex.conf`:
   SuEx configuration file.

## EAMPLES

...

## SEE ALSO

su(1), suex.conf(5), pam(5), pam.d(5), glob(3)

## AUTHORS

Oded Lazar <<odedlaz@gmail.com>>
