pkgname=dssd
pkgver=$( awk '$1 == "version" {split($3, x, "\""); print x[2]}' Cargo.toml )
pkgrel=1
arch=(any)
license=(GPL3)
makedepends=(cargo)
depends=(dbus)
provides=("org.freedesktop.secrets")

package() {
    cd "$startdir"
    cargo build --release
    install -D "$startdir"/target/release/dssd "$pkgdir"/usr/bin/dssd
    install -Dm644 "$startdir"/org.freedesktop.secrets.service "$pkgdir"/usr/share/dbus-1/services/org.freedesktop.secrets.service
    install -Dm644 "$startdir"/dssd.service "$pkgdir"/usr/lib/systemd/user/dssd.service
}
