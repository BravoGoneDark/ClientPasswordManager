#include "cli/cli_interface.hpp"

int main(int argc, char* argv[]) {
    pwdmgr::cli::CliInterface cli;
    return cli.run(argc, argv);
}
