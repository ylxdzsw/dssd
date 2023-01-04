DSSD: Dead Simple Secret Daemon
===============================

DSSD (partially) implements [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/) to
provide a backend for [libsecret](https://wiki.gnome.org/Projects/Libsecret). DSSD is implemented with ~300 lines of
code and compiles to a ~1M binary. The secrets are stored in an unencrypted JSON file in `~/.local/state/dssd`.
