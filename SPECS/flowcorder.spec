%global srcname flowcorder
%global sum Daemons instrumenting transport stacks and exporting statistics over IPFIX
%global unitTCP flowcorder-tcp-exporter.service
%global unitDNS flowcorder-dns-exporter.service
Name:           %{srcname}
Version:        0.8
Release:        3%{?dist}
Summary:        %{sum}

License:        MIT
URL:            https://inl.info.ucl.ac.be/otilmans
Source0:        flowcorder-%{version}.tar.gz
Source1:        flowcorder_config.cfg

BuildArch:      noarch
BuildRequires:  python34-devel python34-pytest
%{?systemd_requires}
BuildRequires: systemd
Requires: python34-setuptools
Requires: python34-pyroute2
Requires: python3-ipfix
Requires: python3-daemons
Requires: python3-radix
Requires: bcc-tools
Requires: kernel-devel
Requires: kernel-headers

%description
TBA

%prep
%autosetup -n %{srcname}-%{version}

%build
%py3_build

%install
%py3_install
mkdir -p %{buildroot}/etc
cp %{_topdir}/SOURCES/flowcorder_config.cfg %{buildroot}/etc

%files
%license LICENSE
%doc README.md
%{python3_sitelib}/*
%{_bindir}/flowcorder_dns_exporter
%{_bindir}/flowcorder_tcp_exporter
%{_unitdir}/%{unitTCP}
%{_unitdir}/%{unitDNS}

%config /etc/flowcorder_config.cfg

%post
%systemd_post %{unitTCP}
%systemd_post %{unitDNS}

%preun
%systemd_preun %{unitTCP} 
%systemd_preun %{unitDNS} 

%postun
%systemd_postun_with_restart %{unitTCP} 
%systemd_postun_with_restart %{unitDNS} 


%changelog
* Sun May 20 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 0.6
- Major rewrite
- Supports MPTCP
* Mon Mar 12 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 0.5
- Track reordering
- Track TCP source process
- Restore UCL dest. prefix
* Thu Feb 22 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 0.2
- Blacklist some destination prefixes
* Fri Jan 12 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 0.1
- Initial import
