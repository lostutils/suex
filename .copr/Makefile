srpm:
	dnf -y install cmake pam-devel elfutils-devel rubygem-ronn gcc-c++
	mkdir -p build && cd build && cmake -D SPECFILE=${spec} .. && make package && cd ..
	mv pkg/* ${outdir}
