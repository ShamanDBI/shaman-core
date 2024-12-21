mkdir -p docs/build/oxy_docs_xml
doxygen
cd docs
make html
cd  build/html/
git init
git remote add origin git@github.com:ShamanDBI/shamandbi.github.io.git
git add -A
git commit -m "first commit"
git checkout -b main
git push -f origin main
