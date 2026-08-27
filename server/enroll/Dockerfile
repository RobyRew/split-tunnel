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

# Unprivileged. The CA key is mounted read-only and owned by this uid.
RUN useradd --system --uid 8023 --no-create-home enroll
USER 8023

EXPOSE 8080
CMD ["python", "-u", "enroll.py"]
