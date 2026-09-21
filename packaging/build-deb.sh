#!/usr/bin/env bash
set -euo pipefail

# Package an existing native build. Run on the target distribution so that
# dpkg-shlibdeps selects that distribution's runtime library dependencies.
: "${DEB_VERSION:?Set DEB_VERSION to the package version}"
: "${DEB_MAINTAINER:?Set DEB_MAINTAINER to Name <email>}"

repo_root=$(git rev-parse --show-toplevel)
binary=$(realpath "${BINARY:-$repo_root/target/release/rustybgpd}")
output_dir=$(realpath -m "${OUTPUT_DIR:-$repo_root/target/debian}")
architecture=$(dpkg --print-architecture)
dpkg --validate-version "$DEB_VERSION"

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
package_root="$work_dir/package"
install -Dm755 "$binary" "$package_root/usr/bin/rustybgpd"
strip --strip-unneeded "$package_root/usr/bin/rustybgpd"
install -Dm644 "$repo_root/LICENSE" "$package_root/usr/share/doc/rustybgpd/copyright"
mkdir -p "$work_dir/debian" "$package_root/DEBIAN" "$output_dir"

# dpkg-shlibdeps expects a source control file in its working directory.
cat > "$work_dir/debian/control" <<EOF
Source: rustybgpd
Section: net
Priority: optional
Maintainer: $DEB_MAINTAINER

Package: rustybgpd
Architecture: any
Description: BGP daemon written in Rust
EOF
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
Depends: $dependencies
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
