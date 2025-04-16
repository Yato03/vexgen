#!/bin/bash

export $(grep -v '^#' .env | xargs)

docker exec --interactive --tty pypi_neo4j gzip -d /backups/pypi_neo4j.cypher.gz  > /dev/null 2>&1
docker exec --interactive --tty pypi_neo4j cypher-shell -u $GRAPH_DB_USER -p $GRAPH_DB_PASSWORD_PYPI -a bolt://localhost:7687 -f /backups/pypi_neo4j.cypher > /dev/null 2>&1
docker exec --interactive --tty pypi_neo4j rm /backups/pypi_neo4j.cypher
echo "PyPI graph database was restored"
docker exec --interactive --tty npm_neo4j gzip -d /backups/npm_neo4j.cypher.gz  > /dev/null 2>&1
docker exec --interactive --tty npm_neo4j cypher-shell -u $GRAPH_DB_USER -p $GRAPH_DB_PASSWORD_NPM -a bolt://localhost:7686 -f /backups/npm_neo4j.cypher > /dev/null 2>&1
docker exec --interactive --tty npm_neo4j rm /backups/npm_neo4j.cypher
echo "NPM graph database was restored"
docker exec --interactive --tty maven_neo4j gzip -d /backups/maven_neo4j.cypher.gz  > /dev/null 2>&1
docker exec --interactive --tty maven_neo4j cypher-shell -u $GRAPH_DB_USER -p $GRAPH_DB_PASSWORD_MAVEN -a bolt://localhost:7685 -f /backups/maven_neo4j.cypher > /dev/null 2>&1
docker exec --interactive --tty maven_neo4j rm /backups/maven_neo4j.cypher
echo "Maven graph database was restored"
docker exec --interactive --tty cargo_neo4j gzip -d /backups/cargo_neo4j.cypher.gz  > /dev/null 2>&1
docker exec --interactive --tty cargo_neo4j cypher-shell -u $GRAPH_DB_USER -p $GRAPH_DB_PASSWORD_CARGO -a bolt://localhost:7684 -f /backups/cargo_neo4j.cypher > /dev/null 2>&1
docker exec --interactive --tty cargo_neo4j rm /backups/cargo_neo4j.cypher
echo "Cargo graph database was restored"
docker exec --interactive --tty nuget_neo4j gzip -d /backups/nuget_neo4j.cypher.gz  > /dev/null 2>&1
docker exec --interactive --tty nuget_neo4j cypher-shell -u $GRAPH_DB_USER -p $GRAPH_DB_PASSWORD_NUGET -a bolt://localhost:7683 -f /backups/nuget_neo4j.cypher > /dev/null 2>&1
docker exec --interactive --tty nuget_neo4j rm /backups/nuget_neo4j.cypher
echo "NuGet graph database was restored"
