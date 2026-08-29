// zygiskd main entry point and subcommand dispatch.
//
// Usage:
//   zygiskd daemon         — start the long-lived daemon
//   zygiskd service-stage  — hook the service stage
//   zygiskd exit           — drain the daemon (called by
//                             emulated-soft-reboot.sh)
//   zygiskd status         — print status (used by WebUI)
//   zygiskd version        — print version (used by WebUI)
//   zygiskd enable         — enable Zygisk (toggles config flag)
//   zygiskd disable        — disable Zygisk (toggles config flag)
//   zygiskd list           — list modules (used by WebUI)
//   zygiskd toggle <id>    — toggle module enable/disable
//   zygiskd bugreport      — generate bugreport (delegates to
//                             action.sh; the WebUI uses
//                             action.sh directly for this)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "daemon.h"
#include "log.h"
#include "modules.h"

// Version string — also embedded in module.prop.
static const char ZYGISKD_VERSION[] = "1.5.0 (843-5217106-release)";

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s <command> [args]\n"
        "\n"
        "Commands:\n"
        "  daemon           Start the long-lived daemon (post-fs-data stage)\n"
        "  service-stage    Hook the service stage (after Zygote is up)\n"
        "  exit             Tell the running daemon to exit\n"
        "  status           Print status summary\n"
        "  version          Print version\n"
        "  enable            Enable Zygisk (set on next boot)\n"
        "  disable           Disable Zygisk (set on next boot)\n"
        "  list              List modules\n"
        "  toggle <id>       Toggle a module's enable/disable state\n",
        argv0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "daemon") == 0) {
        return daemon_main();
    }
    if (strcmp(cmd, "service-stage") == 0) {
        return service_stage_main();
    }
    if (strcmp(cmd, "exit") == 0) {
        return exit_daemon();
    }
    if (strcmp(cmd, "status") == 0) {
        return status_main(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "version") == 0) {
        printf("%s\n", ZYGISKD_VERSION);
        return 0;
    }
    if (strcmp(cmd, "enable") == 0) {
        return config_set_zygisk_enabled(true) == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "disable") == 0) {
        return config_set_zygisk_enabled(false) == 0 ? 0 : 1;
    }
    if (strcmp(cmd, "list") == 0) {
        size_t n;
        struct ModuleInfo *mods = modules_list(&n);
        for (size_t i = 0; i < n; i++) {
            printf("%s\t%s\t%s\t%s%s\n",
                   mods[i].id, mods[i].name, mods[i].version,
                   mods[i].enabled ? "enabled" : "disabled",
                   mods[i].has_companion ? "\tzygisk" : "");
        }
        free(mods);
        return 0;
    }
    if (strcmp(cmd, "toggle") == 0) {
        if (argc < 3) {
            fprintf(stderr, "toggle: missing module id\n");
            return 1;
        }
        // Determine current state and flip.
        size_t n;
        struct ModuleInfo *mods = modules_list(&n);
        bool found = false;
        bool new_state = false;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(mods[i].id, argv[2]) == 0) {
                found = true;
                new_state = !mods[i].enabled;
                break;
            }
        }
        free(mods);
        if (!found) {
            fprintf(stderr, "toggle: no such module: %s\n", argv[2]);
            return 1;
        }
        return modules_toggle(argv[2], new_state) == 0 ? 0 : 1;
    }

    usage(argv[0]);
    return 1;
}
