Name:       suex
Version:    0.2.6
Release:    1%{?dist}
Summary:    Execute commands as another user
License:    MIT

URL:        https://github.com/odedlaz/suex/
Source0:    %{url}archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc-c++
BuildRequires:  cmake
BuildRequires:  ninja-build
BuildRequires:  clang
BuildRequires:  clang-libs
BuildRequires:  clang-devel
BuildRequires:  clang-tools-extra
BuildRequires:  pam-devel
BuildRequires:  re2-devel
BuildRequires:  rubygem-ronn

%description
suex is a utility that is aimed to replace sudo for most ordinary use cases.


%prep
%autosetup -p1 -n %{name}-%{version}


%build
mkdir build && pushd build
export LANG=en_US.utf8
export CC=$(which clang)
export CXX=$(which clang++)
%cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
%ninja_build
popd


%install
pushd build
%ninja_install
popd


%files
%license LICENSE
%doc README.md
%config(noreplace) %{_sysconfdir}/%{name}.conf
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*
%{_mandir}/man5/%{name}.conf.5*
