%global srcname bitlockersetup

Name:      %{srcname}
Version:   0.1
Release:   1%{?dist}
Summary:   Tool for working with BitLocker devices in GNU/Linux

License:   MIT
Url:       https://github.com/vojtechtrefny/thesis
Source0:   %{srcname}-%{version}.tar.gz

BuildArch: noarch

BuildRequires: python3-devel
BuildRequires: python3-pylint
BuildRequires: python3-pycodestyle
BuildRequires: python3-pocketlint
BuildRequires: python3-pycryptodomex
BuildRequires: python3-cryptography

Requires: python3-pycryptodomex
Requires: python3-cryptography
Requires: device-mapper

%description
A small tool for accessing and analysing BitLocker devices using Device Mapper.

%prep
%setup -q

%build
make

%install
make DESTDIR=%{buildroot} PYTHON=%{__python3} install

%check
make check

%files
%{_bindir}/bitlockersetup
%{_mandir}/man8/bitlockersetup.8*
%{python3_sitelib}/%{srcname}*egg*
%{python3_sitelib}/%{srcname}/

%changelog
* Sat Apr 27 2019 Vojtech Trefny - 0.1-1
- Initial packaging of bitlockersetup.
