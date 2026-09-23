#!/usr/bin/env bash
set -euo pipefail

# Package an existing native build. Run on the target distribution so that
# dpkg-shlibdeps selects that distribution's runtime library dependencies.
# Requires binutils, dpkg-dev, and debhelper.
: "${DEB_VERSION:?Set DEB_VERSION to the package version}"
: "${DEB_MAINTAINER:?Set DEB_MAINTAINER to Name <email>}"

repo_root=$(git rev-parse --show-toplevel)
binary=$(realpath "${BINARY:-$repo_root/target/release/rustybgpd}")
output_dir=$(realpath -m "${OUTPUT_DIR:-$repo_root/target/debian}")
architecture=$(dpkg --print-architecture)
dpkg --validate-version "$DEB_VERSION"

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
package_root="$work_dir/debian/rustybgpd"
install -Dm755 "$binary" "$package_root/usr/bin/rustybgpd"
strip --strip-unneeded "$package_root/usr/bin/rustybgpd"
install -Dm644 "$repo_root/LICENSE" "$package_root/usr/share/doc/rustybgpd/copyright"
install -Dm644 "$repo_root/packaging/rustybgpd.service" "$package_root/usr/lib/systemd/system/rustybgpd.service"
install -Dm644 "$repo_root/packaging/rustybgpd.yaml" "$package_root/usr/share/rustybgpd/examples/rustybgpd.yaml"
install -d -m755 "$package_root/etc/rustybgpd"
mkdir -p "$work_dir/debian" "$package_root/DEBIAN" "$output_dir"

# dpkg-shlibdeps expects a source control file in its working directory.
cat > "$work_dir/debian/control" <<EOF
Source: rustybgpd
Section: net
Priority: optional
Maintainer: $DEB_MAINTAINER
Build-Depends: debhelper-compat (= 13)
Rules-Requires-Root: no

Package: rustybgpd
Architecture: any
Description: BGP daemon written in Rust
EOF
# Generate Debian's standard service lifecycle scripts. Initial installation
# leaves the service disabled/stopped; upgrades restart it only if running.
(
    cd "$work_dir"
    export DEB_RULES_REQUIRES_ROOT=no
    dh_installsystemd --no-enable --no-start --restart-after-upgrade
    dh_installdeb
)
dependencies=$(cd "$work_dir" && dpkg-shlibdeps -O -e"$package_root/usr/bin/rustybgpd")
dependencies=${dependencies#shlibs:Depends=}
installed_size=$(du -sk "$package_root/usr" | cut -f1)

cat > "$package_root/DEBIAN/control" <<EOF
Package: rustybgpd
Version: $DEB_VERSION
Section: net
Priority: optional
Architecture: $architecture
Maintainer: $DEB_MAINTAINER
Installed-Size: $installed_size
Depends: init-system-helpers (>= 1.54), $dependencies
Homepage: https://github.com/osrg/rustybgp
Description: BGP daemon written in Rust
 BGP routing daemon with a GoBGP-compatible gRPC interface.
EOF

filename="rustybgpd_${DEB_VERSION}_${architecture}.deb"
dpkg-deb --root-owner-group --build "$package_root" "$output_dir/$filename"
dpkg-deb --info "$output_dir/$filename"
(
    cd "$output_dir"
    sha256sum "$filename" > "$filename.sha256"
)
