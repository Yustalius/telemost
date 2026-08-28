Name:       telemost
Version:    1.4.9
Release:    0
Summary:    RPM package
License:    GPL-3.0
URL:        https://rustdesk.com
Vendor:     telemost <info@rustdesk.com>
Requires:   gtk3 libxcb libXfixes alsa-lib libva2 gstreamer1-plugins-base
Recommends: libayatana-appindicator-gtk3 libxdo

# https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/

%description
The best open-source remote desktop client software, written in Rust.

%prep
# we have no source, so nothing here

%build
# we have no source, so nothing here

%global __python %{__python3}

%install
mkdir -p %{buildroot}/usr/bin/
mkdir -p %{buildroot}/usr/share/telemost/
mkdir -p %{buildroot}/usr/share/telemost/files/
mkdir -p %{buildroot}/usr/share/icons/hicolor/256x256/apps/
mkdir -p %{buildroot}/usr/share/icons/hicolor/scalable/apps/
install -m 755 $HBB/target/release/telemost %{buildroot}/usr/bin/telemost
install $HBB/libsciter-gtk.so %{buildroot}/usr/share/telemost/libsciter-gtk.so
install $HBB/res/telemost.service %{buildroot}/usr/share/telemost/files/
install $HBB/res/128x128@2x.png %{buildroot}/usr/share/icons/hicolor/256x256/apps/telemost.png
install $HBB/res/scalable.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/telemost.svg
install $HBB/res/telemost.desktop %{buildroot}/usr/share/telemost/files/
install $HBB/res/telemost-link.desktop %{buildroot}/usr/share/telemost/files/

%files
/usr/bin/telemost
/usr/share/telemost/libsciter-gtk.so
/usr/share/telemost/files/telemost.service
/usr/share/icons/hicolor/256x256/apps/telemost.png
/usr/share/icons/hicolor/scalable/apps/telemost.svg
/usr/share/telemost/files/telemost.desktop
/usr/share/telemost/files/telemost-link.desktop
/usr/share/telemost/files/__pycache__/*

%changelog
# let's skip this for now

%pre
# can do something for centos7
case "$1" in
  1)
    # for install
  ;;
  2)
    # for upgrade
    systemctl stop telemost || true
  ;;
esac

%post
cp /usr/share/telemost/files/telemost.service /etc/systemd/system/telemost.service
cp /usr/share/telemost/files/telemost.desktop /usr/share/applications/
cp /usr/share/telemost/files/telemost-link.desktop /usr/share/applications/
systemctl daemon-reload
systemctl enable telemost
systemctl start telemost
update-desktop-database

%preun
case "$1" in
  0)
    # for uninstall
    systemctl stop telemost || true
    systemctl disable telemost || true
    rm /etc/systemd/system/telemost.service || true
  ;;
  1)
    # for upgrade
  ;;
esac

%postun
case "$1" in
  0)
    # for uninstall
    rm /usr/share/applications/telemost.desktop || true
    rm /usr/share/applications/telemost-link.desktop || true
    update-desktop-database
  ;;
  1)
    # for upgrade
  ;;
esac
