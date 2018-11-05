# libfakeext4

Just a dumb thing to fake the type of a filesystem

# Intro

Dropbox will no longer allow running the Linux client on any filesystem other
than Ext4 ([forum thread][support], [Reddit thread][reddit]).  Ext4 is garbage.
So, just pretend we're running `dropbox` on an Ext4 filesystem.

# Usage

## Compile library

Compile this using `cmake`, e.g. in a temp directory (starting from this repo):

```sh
dir="$(pwd)"
cd "$(mktemp -d -t build-fakeext4.XXXXXXXX)"
cmake "$dir"
make
```

## Install it

(optional, but definitely easiest):

```sh
make install
## default prefix = /usr/local
## library file = ${prefix}/lib/libfakeext4.so
```

## Ensure `dropboxd` uses it

Ensure it's in `dropboxd`'s `LD_PRELOAD` environment variable. E.g., via a
`systemd` user unit drop-in file:

```sh
config_dir=$HOME/.config/systemd/user/dropbox.service.d
mkdir -p "$config_dir"
cat > "$config_dir/environment.conf" <<'CONFIG'
[Service]
Environment=LD_PRELOAD=/usr/local/lib/libfakeext4.so
CONFIG
```

# Features and TODOs

- [x] Successfully intercepts `libc` calls
- [x] Intercepts raw syscalls on x86_64 Linux
- [x] Prevents `dropboxd` from popping up a warning about impending failure
- [ ] Keeps working after the "drop-dead" date
- [ ] Check into overriding [`statvfs` `f_fsid` field][statvfs]

# License

Copyright © 2018 Benjamin R. Haskell

Distributed under the MIT License (included in file: [LICENSE](LICENSE)).

[support]: https://www.dropboxforum.com/t5/Syncing-and-uploads/Dropbox-client-warns-me-that-it-ll-stop-syncing-in-Nov-why/td-p/290058
[reddit]: https://www.reddit.com/r/linux/comments/966xt0/linux_dropbox_client_will_stop_syncing_on_any/
[statvfs]: https://www.reddit.com/r/linux/comments/966xt0/linux_dropbox_client_will_stop_syncing_on_any/e3yx2gs/
