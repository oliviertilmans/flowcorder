%global srcname ipfix
%global sum A python module providing an IPFIX implementation.
Name:           python3-%{srcname}
Version:        0.9.8
Release:        1%{?dist}
Summary:        %{sum}

License:        LGPLv3+
URL:            https://pypi.python.org/pypi/%{srcname}
Source0:        python3-ipfix.tar.gz
Source1:        https://codeload.github.com/britram/python-ipfix/tar.gz/master

BuildArch:      noarch
BuildRequires:  python34-devel python34-setuptools

%description
This module provides a Python interface to IPFIX message streams, 
and provides tools for building IPFIX Exporting and Collecting Processes. 
It handles message framing and deframing, encoding and decoding IPFIX data 
records using templates, and a bridge between IPFIX ADTs and appopriate Python data types.

%prep
%autosetup -n python-ipfix-master

%build
%py3_build

%install
%py3_install

%check
%{__python3} setup.py test

%files
%license LICENSE.txt
%doc README.md
%{python3_sitelib}/*
%{_bindir}/ipfix2csv
%{_bindir}/ipfixstat


%changelog
* Fri Jan 12 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 0.9.8
- Initial import
