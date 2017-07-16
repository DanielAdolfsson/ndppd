Name: ndppd
Version: 0.2.5       
Release: 1%{?dist}
Summary: A daemon that proxies NDP (Neighbor Discovery Protocol) messages between interfaces.       

Group: Applications/System          
License: GPL3+       
URL: https://github.com/DanielAdolfsson/ndppd            
Source0: %{name}-%{version}.tar.gz       
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
'ndppd', or NDP Proxy Daemon, is a daemon that proxies NDP (Neighbor Discovery Protocol) messages between interfaces.

The Neighbor Discovery Protocol (NDP) is a protocol in the Internet Protocol Suite used with Internet Protocol Version 6 (IPv6). It 
operates in the Link Layer of the Internet model (RFC 1122) and is responsible for address autoconfiguration of nodes, discovery of 
other nodes on the link, determining the Link Layer addresses of other nodes, duplicate address detection, finding available 
routers and Domain Name System (DNS) servers, address prefix discovery, and maintaining reachability information about the paths 
to other active neighbor nodes (RFC 4861). (Wikipedia)

%prep
%setup -q

%build
make all %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT PREFIX=/usr

mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}
mkdir -p %{buildroot}%{_localstatedir}/run/ndppd
mv %{_builddir}/%{name}-%{version}/ndppd.service %{buildroot}%{_unitdir}/
mv %{_builddir}/%{name}-%{version}/ndppd.conf-dist %{buildroot}%{_sysconfdir}/ndppd.conf
touch %{buildroot}%{_localstatedir}/run/ndppd/ndppd.pid

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc
%{_sbindir}/*
%{_mandir}/man*/*
%{_unitdir}/*
%{_sysconfdir}/*
%{_localstatedir}/*

%changelog
* Sun Jul 16 2017 Ward Hus
- Initial Spec-file
