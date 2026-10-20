#!/bin/sh
java -Dlogging.config=/data/userdetails/config/logback.groovy -Dconsolelog=true -Xmx2g -Xms2g -jar /home/bea18c/dev/github/Atlas/userdetails/build/libs/userdetails-3.0.0-SNAPSHOT-exec.war
