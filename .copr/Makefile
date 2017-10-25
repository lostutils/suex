srpm:
	dnf -y install cmake pam-devel elfutils-devel rubygem-ronn gcc-c++
	mkdir -vp build ${out_dir} && \
		cd build && \
		cmake -D CPACK_GENERATOR=RPM -D CPACK_OUTPUT_DIR=${outdir} .. \
		&& make package
