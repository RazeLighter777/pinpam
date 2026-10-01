#!/usr/bin/env bash
# Install pinpam on Fedora KDE: everything install.sh does, plus PIN support
# for the Plasma lock screen (kde) and the login screen (plasmalogin or sddm).
#
# Usage (from the repo root, after `cargo build --release --all-features`):
#   sudo contrib/fedora/install-kde.sh               # install + enable
#   sudo contrib/fedora/install-kde.sh --master-key  # also stamp the wallet
#                                                    # token at the login screen
#   sudo contrib/fedora/install-kde.sh uninstall     # revert KDE edits + remove
set -euo pipefail

PAM_ETC=${PAM_ETC:-/etc/pam.d}
PAM_VENDOR=${PAM_VENDOR:-/usr/lib/pam.d}
PAM_LIB=${PAM_LIB:-/usr/lib64/security}
DECIDE=pinpam-decide
DECIDE_MARK="# pinpam: written by contrib/fedora/install-kde.sh"
MARK="# pinpam: install-kde.sh replaced:"
OLD_MARK="# pinpam: added by install-kde.sh"
COPY_MARK="# pinpam: copied from $PAM_VENDOR by contrib/fedora/install-kde.sh"
SUBSTACK_LINE="auth        substack      $DECIDE"
MASTER_KEY_LINE="auth        optional      libpinpam_master_key.so"
# Services whose auth goes through password-auth, which pinpam deliberately
# avoids because sshd uses it too.
SERVICES=(kde plasmalogin sddm)
# Login services, where the session's keyring modules capture PAM_AUTHTOK.
LOGIN_SERVICES=(plasmalogin sddm)

# The greeters have a single input field and answer only the first secret
# prompt, so the PIN or password must be collected once. pam_unix prompts and
# stores the input as PAM_AUTHTOK even when the password check fails; pinpam
# then tests that same input as a PIN without prompting again.
write_decide() {
    local file=$PAM_ETC/$DECIDE
    if [[ -f $file ]] && ! head -1 "$file" | grep -qxF "$DECIDE_MARK"; then
        echo "$file exists and was not written by this script; leaving it alone"
        return 0
    fi
    cat > "$file" <<EOF
$DECIDE_MARK
# PIN-or-password decision for the single-field KDE greeters. Sufficient
# short-circuits stay inside this substack, so the calling service still runs
# its keyring modules afterwards.
auth  required    pam_env.so
auth  required    pam_faildelay.so delay=2000000
auth  sufficient  pam_unix.so nullok
auth  sufficient  libpinpam.so use_first_pass
auth  requisite   pam_deny.so
EOF
    chmod 644 "$file"
    echo "$file: written"
}

# Drop the pre-substack layout (a sufficient pinpam line ahead of
# password-auth) left by earlier versions of this script or by the old manual
# README steps.
migrate_old() {
    local file=$1
    grep -qxF "$OLD_MARK" "$file" || grep -qE '^auth +sufficient +libpinpam\.so *$' "$file" || return 0
    sed -i -e "/^$(sed 's/[\/.*]/\\&/g' <<< "$OLD_MARK")\$/d" -e '/^auth \+sufficient \+libpinpam\.so *$/d' "$file"
    echo "$file: removed old-style pinpam line"
}

# Replace the password-auth auth line of a PAM service with the pinpam-decide
# substack, copying the vendor file into /etc/pam.d first if needed. The
# replaced line is kept in a marker comment so uninstall can restore it.
patch_service() {
    local svc=$1 master_key=$2 file=$PAM_ETC/$1 extra=""
    if [[ ! -f $file ]]; then
        [[ -f $PAM_VENDOR/$svc ]] || return 0
        { echo "$COPY_MARK"; cat "$PAM_VENDOR/$svc"; } > "$file"
        chmod 644 "$file"
    fi
    migrate_old "$file"
    if grep -qE "^[^#]*(libpinpam\.so|$DECIDE)" "$file"; then
        echo "$file: pinpam already present"
        return 0
    fi
    if ! grep -qE '^auth +(substack|include) +password-auth' "$file"; then
        echo "WARNING: $file has no 'auth substack password-auth' line; add pinpam manually" >&2
        return 0
    fi
    [[ $master_key == 1 ]] && extra="\n$MASTER_KEY_LINE"
    sed -i -E "0,/^auth +(substack|include) +password-auth.*/s//$MARK &\n$SUBSTACK_LINE$extra/" "$file"
    echo "$file: auth now goes through $DECIDE${extra:+ (with master-key)}"
}

unpatch_service() {
    local file=$PAM_ETC/$1
    [[ -f $file ]] || return 0
    if head -1 "$file" | grep -qxF "$COPY_MARK"; then
        rm -f "$file"
        echo "$file: removed (vendor file in $PAM_VENDOR applies again)"
        return 0
    fi
    migrate_old "$file"
    grep -qF "$MARK" "$file" || return 0
    awk -v mark="$MARK " -v sub_line="$SUBSTACK_LINE" -v mk="$MASTER_KEY_LINE" '
        index($0, mark) == 1 { print substr($0, length(mark) + 1); skip = 1; next }
        skip && ($0 == sub_line || $0 == mk) { next }
        { skip = 0; print }
    ' "$file" > "$file.tmp" && cat "$file.tmp" > "$file" && rm -f "$file.tmp"
    echo "$file: restored password-auth"
}

main() {
    [[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
    local here master_key=0 svc
    here="$(dirname "$0")"

    case ${1:-} in
        uninstall)
            for svc in "${SERVICES[@]}"; do unpatch_service "$svc"; done
            if [[ -f $PAM_ETC/$DECIDE ]] && head -1 "$PAM_ETC/$DECIDE" | grep -qxF "$DECIDE_MARK"; then
                rm -f "$PAM_ETC/$DECIDE"
                echo "$PAM_ETC/$DECIDE: removed"
            fi
            "$here/install.sh" uninstall
            exit 0
            ;;
        --master-key) master_key=1 ;;
        "") ;;
        *) echo "usage: $0 [--master-key | uninstall]" >&2; exit 1 ;;
    esac

    "$here/install.sh"
    echo
    if [[ $master_key == 1 && ! -f $PAM_LIB/libpinpam_master_key.so ]]; then
        echo "WARNING: $PAM_LIB/libpinpam_master_key.so not installed; skipping master-key" >&2
        master_key=0
    fi
    write_decide
    for svc in "${SERVICES[@]}"; do
        if [[ " ${LOGIN_SERVICES[*]} " == *" $svc "* ]]; then
            patch_service "$svc" "$master_key"
        else
            patch_service "$svc" 0
        fi
    done
    restorecon "$PAM_ETC"/{$DECIDE,kde,plasmalogin,sddm} 2>/dev/null || true

    echo
    echo "KDE lock screen and login screen now accept your PIN or your password"
    echo "in the same field."
    if [[ $master_key == 1 ]]; then
        echo "Master-key is on: re-key KWallet to the token from"
        echo "'pinutil master-key get-user-token ${SUDO_USER:-<user>}' (see README.md) or it"
        echo "will stop unlocking at login."
    else
        echo "After a PIN login KWallet will ask for its password; see the"
        echo "Master-key section of README.md, then re-run with --master-key."
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
