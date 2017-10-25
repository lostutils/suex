srpm:
	dnf -y install cmake pam-devel elfutils-devel rubygem-ronn gcc-c++
	mkdir -p build && cd build && cmake .. && make package && cd ..
	mv -vf pkg/* ${outdir}
