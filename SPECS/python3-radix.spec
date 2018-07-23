%global srcname radix
%global sum A python module providing an IPFIX implementation.
Name:           python3-%{srcname}
Version:        0.10.0
Release:        1%{?dist}
Summary:        %{sum}

License:        BSD
URL:            https://pypi.python.org/pypi/py-radix
Source0:        https://codeload.github.com/mjschultz/py-radix/tar.gz/master#/python3-radix.tar.gz 

BuildArch:      x86_64
BuildRequires:  python34-devel python34-setuptools

%description
py-radix implements the radix tree data structure for the storage and retrieval 
of IPv4 and IPv6 network prefixes.

The radix tree is commonly used for routing table lookups. It efficiently 
stores network prefixes of varying lengths and allows fast lookups of 
containing networks.

%prep
%autosetup -n py-radix-master

%build
%py3_build

%install
%py3_install

%check
%{__python3} setup.py test

%files
%license LICENSE
%doc README.rst
/usr/lib64/*

%changelog
* Thu Feb 22 2018 Olivier Tilmans <olivier.tilmans@uclouvain.be> - 0.10.0
- Initial import
