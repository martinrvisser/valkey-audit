Name:           percona-valkey-audit
Version:        0.2.2
Release:        1%{?dist}
Summary:        Audit logging module for Valkey

License:        BSD-3-Clause
URL:            https://github.com/martinrvisser/valkey-audit
Source0:        valkey-audit-%{version}.tar.gz

BuildRequires:  cmake >= 3.10
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  git
# valkeymodule.h — provided by Percona Valkey 9.1 experimental repo
BuildRequires:  percona-valkey-devel

Requires:       percona-valkey
Provides:       valkey-audit = %{version}-%{release}
Obsoletes:      valkey-audit < %{version}-%{release}
Conflicts:      valkey-audit < %{version}-%{release}

%description
A Valkey server module that provides comprehensive audit logging. Logs
connections, authentication, configuration changes, key operations, and more
to file, syslog, or TCP in text, JSON, or CSV formats. Supports exclusion
rules by username, IP, command, and custom categories.

%prep
%autosetup -n valkey-audit-%{version}

%build
# Override -march=native with portable flags for distribution
%cmake -DCMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG -mtune=generic -flto" -DBUILD_TESTING=OFF
%cmake_build

%install
# Install module shared library
install -D -m 0755 %{__cmake_builddir}/libvalkeyaudit.so \
    %{buildroot}%{_libdir}/valkey/modules/libvalkeyaudit.so

# Install config snippet
install -D -m 0644 packaging/valkey-audit.conf \
    %{buildroot}%{_sysconfdir}/valkey/valkey.conf.d/valkey-audit.conf

%files
%{_libdir}/valkey/modules/libvalkeyaudit.so
%config(noreplace) %{_sysconfdir}/valkey/valkey.conf.d/valkey-audit.conf

%changelog
* Tue Mar 03 2026 Evgeniy Patlan <evgeniy.patlan@percona.com> - 0.2.2-1
- Initial RPM packaging
- Audit logging module for Valkey with file/syslog/TCP output
- Supports text, JSON, and CSV log formats
- Exclusion rules by username, IP, command, and custom categories
