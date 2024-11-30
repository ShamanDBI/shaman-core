mkdir -p docs/build/oxy_docs_xml
doxygen
cd docs
make html
