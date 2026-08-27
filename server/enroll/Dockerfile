# split-tunnel enrollment service.
#
# openssh-client is the whole reason this is not a scratch image: signing is
# done by `ssh-keygen -s`, the reference implementation, rather than by a
# hand-rolled certificate encoder. Signing bugs here would be silent and awful.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY enroll.py .

# Unprivileged. The CA key and config are mounted read-only, group-owned by
# this GID on the host.
#
# The group is created EXPLICITLY with gid 8023: `useradd --system` picks the
# next free system gid (999 here), so `USER 8023` alone ran as uid 8023 / gid
# 999 and failed the group check on every mounted directory. Both halves of
# USER are pinned for the same reason.
RUN groupadd --system --gid 8023 enroll \
 && useradd --system --uid 8023 --gid 8023 --no-create-home enroll
USER 8023:8023

EXPOSE 8080
CMD ["python", "-u", "enroll.py"]
