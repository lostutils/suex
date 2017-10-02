#include <conf.h>
#include <utils.h>
#include <logger.h>
#include <options.h>
#include <version.h>
#include <path.h>


int doas(Permissions &permissions, Options &opts) {
    // check in the configuration if the destination user can run the command with the requested permissions
    std::string cmdtxt{cmdargv_txt(opts.CommandArguments())};

    if (!bypass_perms(opts.Me(), opts.AsUser(), opts.AsGroup()) &&
        !hasperm(permissions, opts.AsUser(), opts.AsGroup(), opts.CommandArguments())) {
        std::stringstream ss;
        ss << "You can't execute '" << cmdtxt <<
           "' as '" << opts.AsUser().name() << ":" << opts.AsGroup().name()
           << "': " << std::strerror(EPERM);
        throw std::runtime_error(ss.str());
    }

    // update the HOME env according to the dest_user dir
    setenv("HOME", opts.AsUser().dir().c_str(), 1);

    // set permissions to requested id and gid
    setperm(opts.AsUser(), opts.AsGroup());

    // execute with uid and gid. path lookup is done internally, so execvp is not needed.
    execvp(opts.CommandArguments()[0], &opts.CommandArguments()[0]);

    // will not get here unless execvp failed
    throw std::runtime_error(cmdtxt + " : " + std::strerror(errno));
}


int main(int argc, char *argv[]) {
    try {
        // check that enough args were passed
        if (argc < 2) {
            std::cout << "Usage: " << argv[0]
                      << " user-spec command [args]" << std::endl << std::endl <<
                      "version: " << VERSION << ", license: MIT" << std::endl;
            return 0;
        }

        // check that enough args were passed
        // check that the running binary has the right permissions
        // i.e: suid is set and owned by root:root
        validate_binary(getpath(*argv, true));

        // load the arguments into a vector, then add a null at the end,
        // to have an indication when the vector ends
        Options opts{argc, argv};
        // load the configuration from the default path
        Permissions permissions{opts.ConfigurationPath()};

        return doas(permissions, opts);

    } catch (std::exception &e) {
        logger::error << e.what() << std::endl;
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
