#!/usr/bin/env bash
set -euo pipefail

pause_seconds=5
vim_seconds=2
workdir="${TMPDIR:-/tmp}/vim-forcer-demo"
nano_bin="${NANO_BIN:-$(command -v nano || true)}"
real_vim="$(command -v vim || true)"
vim_wrapper_dir="$workdir/vim-wrapper"
joke_index=0
jokes=(
    "nano detected. Standards enforcement has entered the chat."
    "Your editor has been upgraded without asking, just like nature intended."
    "If you wanted training wheels, they are in another terminal."
    "This incident has been forwarded to the Vim council."
    "Please remain calm while modal editing improves your character."
    "nano tried its best. Vim will take it from here."
    "Tiny editor energy detected. Redirecting to something with modes."
)

cleanup() {
    rm -rf "$workdir"
}
trap cleanup EXIT

rm -rf "$workdir"
mkdir -p "$workdir"

say() {
    printf '\n\033[1;36m==> %s\033[0m\n' "$*"
}

note() {
    printf '    %s\n' "$*"
}

wait_a_moment() {
    sleep "$pause_seconds"
}

display_command() {
    local first=1
    local arg

    for arg in "$@"; do
        arg="${arg//$workdir/\$TMP}"
        if [[ "$first" -eq 1 ]]; then
            printf '%s' "$arg"
            first=0
        else
            printf ' %s' "$arg"
        fi
    done
    printf '\n'
}

run_case() {
    local title="$1"
    shift
    local status_file="$workdir/case-$(date +%s%N).status"

    say "$title"
    note "Command: $(display_command "$@")"
    wait_a_moment

    set +e
    STATUS_FILE="$status_file" bash --noprofile --norc -i -c '
        set +m
        trap "" CHLD
        "$@" > /dev/tty 2> /dev/tty
        status=$?
        if [ "$status" -gt 128 ]; then
            status=0
        fi
        printf "%s\n" "$status" > "$STATUS_FILE"
        exit 0
    ' vim-forcer-demo-case "$@"
    local status=$?
    set -e

    if [[ -s "$status_file" ]]; then
        status="$(cat "$status_file")"
    fi
    if [[ "$status" != "0" ]]; then
        note "Exit status: $status"
    fi
    printf '\033[2K\r'
    wait_a_moment
}

make_file() {
    local name="$1"
    local path="$workdir/$name"
    printf '%s\n' "${jokes[$((joke_index % ${#jokes[@]}))]}" > "$path"
    joke_index=$((joke_index + 1))
    printf '%s\n' "$path"
}

download_file() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$output" "$url"
    else
        return 1
    fi
}

distro_id() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n' "${ID:-unknown}"
    else
        printf 'unknown\n'
    fi
}

distro_like() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s %s\n' "${ID:-unknown}" "${ID_LIKE:-}"
    else
        printf 'unknown\n'
    fi
}

ubuntu_codename() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n' "${VERSION_CODENAME:-noble}"
    else
        printf 'noble\n'
    fi
}

download_arch_nano() {
    local output="$1"
    local url="https://archlinux.org/packages/core/x86_64/nano/download/"
    local package="$workdir/arch-nano.pkg.tar.zst"
    local extract_dir="$workdir/arch-nano-package"

    mkdir -p "$extract_dir"
    download_file "$url" "$package" || return 1
    tar --zstd -xf "$package" -C "$extract_dir" usr/bin/nano || return 1
    mv "$extract_dir/usr/bin/nano" "$output" || return 1
    printf 'Arch Linux package: %s\n' "$url"
}

download_ubuntu_nano() {
    local output="$1"
    local codename
    codename="$(ubuntu_codename)"
    local url="https://packages.ubuntu.com/${codename}/amd64/nano/download"
    local page="$workdir/ubuntu-nano-download.html"
    local package="$workdir/ubuntu-nano.deb"
    local extract_dir="$workdir/ubuntu-nano-package"
    local filename

    mkdir -p "$extract_dir"
    download_file "$url" "$page" || return 1

    filename="$(sed -n 's/.*\(nano_[^` <]*_amd64\.deb\).*/\1/p' "$page" | head -n 1)"
    if [[ -z "$filename" ]]; then
        return 1
    fi

    if ! download_file "https://security.ubuntu.com/ubuntu/pool/main/n/nano/$filename" "$package"; then
        if ! download_file "https://archive.ubuntu.com/ubuntu/pool/main/n/nano/$filename" "$package"; then
            download_file "https://mirrors.kernel.org/ubuntu/pool/main/n/nano/$filename" "$package"
        fi
    fi

    if command -v dpkg-deb >/dev/null 2>&1; then
        dpkg-deb -x "$package" "$extract_dir" || return 1
    else
        command -v ar >/dev/null 2>&1 || return 1
        ar p "$package" data.tar.xz | tar -xJ -C "$extract_dir" ./usr/bin/nano || return 1
    fi

    mv "$extract_dir/usr/bin/nano" "$output" || return 1
    printf 'Ubuntu package page: %s\n' "$url"
}

download_distro_nano() {
    local output="$1"
    local distro
    distro="$(distro_like)"

    case "$distro" in
        *arch*)
            download_arch_nano "$output"
            ;;
        *ubuntu*)
            download_ubuntu_nano "$output"
            ;;
        *)
            return 1
            ;;
    esac
}

if [[ -z "$nano_bin" ]]; then
    say "nano was not found"
    note "Install nano or set NANO_BIN=/path/to/nano before running this demo."
    exit 1
fi

if [[ -z "$real_vim" ]]; then
    say "vim was not found"
    note "Install vim before running this demo."
    exit 1
fi

mkdir -p "$vim_wrapper_dir"
cat > "$vim_wrapper_dir/vimrc" <<VIMRC
set nomore
set shortmess+=F
autocmd VimEnter * call timer_start($((vim_seconds * 1000)), {timer -> execute('qa!')})
VIMRC
cat > "$vim_wrapper_dir/vim" <<WRAPPER
#!/usr/bin/env bash
exec "$real_vim" -Nu "$vim_wrapper_dir/vimrc" "\$@"
WRAPPER
chmod +x "$vim_wrapper_dir/vim"

say "vim-forcer circumvention demo"
note "Temporary workspace: $workdir"
note "Using nano binary: $nano_bin"
note "Auto-closing Vim after ${vim_seconds}s"
note "Run vim-forcer in another terminal first, for example:"
note "sudo env PATH=\"$vim_wrapper_dir:\$PATH\" target/release/vim-forcer"
wait_a_moment

plain_file="$(make_file plain-name.txt)"
run_case \
    "Baseline: direct nano launch" \
    "$nano_bin" "$plain_file"

symlink_bin="$workdir/pico-but-not-really"
ln -s "$nano_bin" "$symlink_bin"
symlink_file="$(make_file renamed-symlink.txt)"
run_case \
    "Symlink with a harmless-looking name" \
    "$symlink_bin" "$symlink_file"

copy_bin="$workdir/not-the-editor-you-are-looking-for"
cp "$nano_bin" "$copy_bin"
chmod +x "$copy_bin"
copy_file="$(make_file renamed-copy.txt)"
run_case \
    "Renamed copy of the nano executable" \
    "$copy_bin" "$copy_file"

hardlink_bin="$workdir/tiny-notepad"
if ln "$nano_bin" "$hardlink_bin" 2>/dev/null; then
    hardlink_file="$(make_file hardlink.txt)"
    run_case \
        "Hard link with a different basename" \
        "$hardlink_bin" "$hardlink_file"
else
    say "Hard link with a different basename"
    note "Skipped: hard links usually cannot cross filesystems and may be blocked by permissions."
fi

path_dir="$workdir/path-shadow"
mkdir -p "$path_dir"
cp "$nano_bin" "$path_dir/helpful-editor"
chmod +x "$path_dir/helpful-editor"
path_file="$(make_file path-shadow.txt)"
run_case \
    "PATH shadowing" \
    env PATH="$path_dir:$PATH" helpful-editor "$path_file"

downloaded_bin="$workdir/downloaded-nano"
say "Downloaded distro package"
note "Detected distro: $(distro_id)"
note "Downloading and extracting into the temp workspace."
if package_source="$(download_distro_nano "$downloaded_bin")"; then
    note "$package_source"
    chmod +x "$downloaded_bin"
    downloaded_file="$(make_file downloaded.txt)"
    run_case \
        "Downloaded distro nano package, renamed executable" \
        "$downloaded_bin" "$downloaded_file"
else
    note "Skipped: distro unsupported, downloader unavailable, or package extraction failed."
fi

shell_wrapper="$workdir/friendly-wrapper"
cat > "$shell_wrapper" <<'WRAPPER'
#!/usr/bin/env bash
exec "${NANO_BIN:-nano}" "$@"
WRAPPER
chmod +x "$shell_wrapper"
wrapper_file="$(make_file wrapper.txt)"
run_case \
    "Shell wrapper around nano" \
    env NANO_BIN="$nano_bin" "$shell_wrapper" "$wrapper_file"

say "Done"
