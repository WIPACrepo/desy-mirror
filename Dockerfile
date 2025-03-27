#FROM python:3.13

FROM almalinux:9

RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
    yum install -y https://repo.opensciencegrid.org/osg/24-main/osg-24-main-el9-release-latest.rpm && \
    yum install -y osg-ca-certs && \
    dnf install -y --allowerasing python3.12 python3.12-pip git curl && \
    dnf clean all && yum clean all

RUN useradd -m -U app
RUN mkdir /app

WORKDIR /app

COPY src /app/src
COPY pyproject.toml /app/pyproject.toml

RUN chown -R app:app /app

USER app

ENV VIRTUAL_ENV=/app/venv

RUN python3.12 -m venv $VIRTUAL_ENV

ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN --mount=source=.git,target=.git,type=bind pip install -e .

CMD ["python", "-m", "desy_mirror"]
