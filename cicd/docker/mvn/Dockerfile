FROM nexusprod.corp.intranet:4566/devbaseimages/development_base_images/java11:2020Q4

ARG user=jenkins
ARG group=jenkins
ARG uid=1341
ARG gid=1341
USER root
RUN getent group ${gid} || groupadd -g ${gid} ${group}
RUN useradd -c "Jenkins user" -d /home/${user} -u ${uid} -g ${gid} -m ${user}
RUN usermod -a -G root ${user}

VOLUME /mvn

ENV INSTALL_DIR=${INSTALL_DIR:-/usr}

ARG MAVEN_VERSION=${MAVEN_VERSION:-3.6.0}
ENV MAVEN_VERSION=${MAVEN_VERSION}
ENV MAVEN_HOME=/usr/apache-maven-${MAVEN_VERSION}
ENV PATH=${PATH}:${MAVEN_HOME}/bin
RUN curl -sL http://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
  | gunzip \
  | tar x -C /usr/ \
  && ln -s ${MAVEN_HOME} /usr/maven

ENV PATH=${PATH}:${JAVA_HOME}/bin
