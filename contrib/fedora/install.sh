#!/usr/bin/env bash
# Install pinpam on Fedora: PAM module, setgid pinutil, policy, and an
# authselect profile that adds pinpam to system-auth behind a feature flag.
#
# Usage (from the repo root, after `cargo build --release --all-features`):
#   sudo contrib/fedora/install.sh            # install + enable
#   sudo contrib/fedora/install.sh uninstall  # disable + remove
set -euo pipefail

PROFILE=pinpam
PAM_DIR=/usr/lib64/security
PINUTIL=/usr/local/bin/pinutil
POLICY_DIR=/etc/pinpam
TPM_GROUP=tss
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release"

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

uninstall() {
    if authselect current 2>/dev/null | grep -q "custom/$PROFILE"; then
        authselect disable-feature with-pinpam
        echo "pinpam disabled in authselect (profile custom/$PROFILE still selected;"
        echo "switch back with e.g. 'authselect select local <features>' if desired)"
    fi
    rm -f "$PAM_DIR/libpinpam.so" "$PAM_DIR/libpinpam_master_key.so" "$PINUTIL"
    rm -f /etc/systemd/system/polkit-agent-helper@.service.d/10-pinpam.conf
    systemctl daemon-reload
    semodule -l | grep -qx pinpam && semodule -r pinpam
    echo "removed pinpam binaries; $POLICY_DIR left in place. PINs stay in the TPM"
    echo "(delete them first with 'pinutil delete' if you want them gone)."
}

if [[ ${1:-} == uninstall ]]; then
    uninstall
    exit 0
fi

for f in libpinpam.so pinutil; do
    [[ -f $TARGET/$f ]] || { echo "missing $TARGET/$f; run cargo build --release --all-features" >&2; exit 1; }
done

getent group "$TPM_GROUP" >/dev/null || { echo "group $TPM_GROUP missing (install tpm2-tss)" >&2; exit 1; }

# Fedora's tpm2-tss udev rules already make /dev/tpmrm0 root:tss 0660.
# Warn if any human user is in that group: they could delete other users' PINs.
members=$(getent group "$TPM_GROUP" | cut -d: -f4)
for u in ${members//,/ }; do
    uid=$(id -u "$u" 2>/dev/null || echo 0)
    if (( uid >= 1000 )); then
        echo "WARNING: user '$u' is in group $TPM_GROUP and can tamper with other users' PINs" >&2
    fi
done

install -Dm755 "$TARGET/libpinpam.so" "$PAM_DIR/libpinpam.so"
[[ -f $TARGET/libpinpam_master_key.so ]] && install -Dm755 "$TARGET/libpinpam_master_key.so" "$PAM_DIR/libpinpam_master_key.so"
install -Dm755 "$TARGET/pinutil" "$PINUTIL"
chown "root:$TPM_GROUP" "$PINUTIL"
chmod 2755 "$PINUTIL"

# Written only when absent, so local edits survive re-runs.
if [[ ! -f $POLICY_DIR/policy ]]; then
    install -d -m755 "$POLICY_DIR"
    cat > "$POLICY_DIR/policy" <<EOF
pin_min_length=4
pin_max_length=6
pin_lockout_max_attempts=5
pinutil_path=$PINUTIL
EOF
fi
chown root:root "$POLICY_DIR" "$POLICY_DIR/policy"
chmod 644 "$POLICY_DIR/policy"

restorecon -RF "$PAM_DIR/libpinpam"*.so "$PINUTIL" "$POLICY_DIR" 2>/dev/null || true

# Let display managers (xdm_t) reach the TPM through pinutil.
if selinuxenabled 2>/dev/null; then
    tmp=$(mktemp -d)
    checkmodule -M -m -o "$tmp/pinpam.mod" "$REPO_ROOT/contrib/fedora/pinpam.te"
    semodule_package -o "$tmp/pinpam.pp" -m "$tmp/pinpam.mod"
    semodule -i "$tmp/pinpam.pp"
    rm -rf "$tmp"
fi

# Only matters if polkit-agent-helper.socket is enabled: the socket-activated
# helper runs with PrivateDevices and cannot reach the TPM otherwise.
install -d /etc/systemd/system/polkit-agent-helper@.service.d
cat > /etc/systemd/system/polkit-agent-helper@.service.d/10-pinpam.conf <<EOF
[Service]
PrivateDevices=no
DeviceAllow=/dev/tpmrm0 rw
EOF
systemctl daemon-reload

# authselect owns /etc/pam.d/system-auth, so add pinpam through a custom
# profile derived from the currently selected one.
read -r -a current < <(authselect current --raw)
base=${current[0]}
features=("${current[@]:1}")
if [[ $base != "custom/$PROFILE" ]]; then
    rm -rf "/etc/authselect/custom/$PROFILE"
    authselect create-profile "$PROFILE" -b "$base" --symlink-meta --symlink-nsswitch --symlink-dconf
    for f in system-auth; do
        sed -i -E '0,/^auth +sufficient +pam_(fprintd|u2f|unix)\.so/s//auth        sufficient                                   libpinpam.so                                           {include if "with-pinpam"}\n&/' \
            "/etc/authselect/custom/$PROFILE/$f"
    done
    grep -q libpinpam "/etc/authselect/custom/$PROFILE/system-auth" || { echo "failed to patch system-auth template" >&2; exit 1; }
fi
authselect select "custom/$PROFILE" "${features[@]}" with-pinpam --force --backup=pre-pinpam

echo
echo "Installed. Next steps (as your normal user):"
echo "  pinutil setup          # create your PIN"
echo "  sudo -k; sudo true     # should prompt for PIN first"
echo "If something fails, check: journalctl -t pinpam -b ; sudo ausearch -m avc -ts recent"
echo "Disable without uninstalling: sudo authselect disable-feature with-pinpam"
