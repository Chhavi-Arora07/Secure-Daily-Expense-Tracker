#!/usr/bin/env bash
# Compiles the project into the "out" folder. Needs JDK 17+ and the two jars in lib/ (see README).
set -e
cd "$(dirname "$0")"
if ! ls lib/*.jar >/dev/null 2>&1; then
  echo "Put sqlite-jdbc-*.jar and slf4j-api-*.jar into the lib folder first (see lib/README.txt)."; exit 1
fi
rm -rf out && mkdir out
javac --release 17 -cp "lib/*" -d out $(find src/main/java -name '*.java')
cp -r src/main/resources/* out/
javac --release 17 -cp "out:lib/*" -d out $(find src/test/java -name '*.java')
echo "Build OK."
echo "Run the app:    ./run.sh"
echo "Run the checks: ./run.sh check"
