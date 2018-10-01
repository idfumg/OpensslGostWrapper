%{!?qtc_qmake:%define qtc_qmake %qmake}
%{!?qtc_qmake5:%define qtc_qmake5 %qmake5}
%{!?qtc_make:%define qtc_make make}
%{?qtc_builddir:%define _builddir %qtc_builddir}

Summary: OpenSSL GOST helper library
Name: openssl-helper
Version: 0.1.0
Release: 1
License: Proprietary
Group: System Service
Source0: %{name}-%{version}.tar.bz2
BuildRequires: qt5-qmake
BuildRequires: openssl-devel

%description
A small helper library for the OpenSSL GOST ciphers.

%prep
%setup -q -n %{name}-%{version}

%build
%qtc_qmake5
%qtc_make %{?_smp_mflags}

%install
%qmake5_install
install -D -m 0644 pkgconfig/openssl-helper.pc %{buildroot}%{_libdir}/pkgconfig/openssl-helper.pc

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libopenssl-helper.so*
%{_includedir}/openssl-helper/openssl-helper.h
%{_libdir}/pkgconfig/openssl-helper.pc
