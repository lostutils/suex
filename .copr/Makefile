srpm:
	dnf -y install cmake pam-devel elfutils-devel rubygem-ronn gcc-c++
	mkdir -p build && cd build && cmake .. && cd ..
	mv pkg/* ${outdir}
