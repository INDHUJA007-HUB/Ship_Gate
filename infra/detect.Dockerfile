FROM public.ecr.aws/lambda/python:3.12

# Install dependencies for Lambda runtime
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install semgrep and checkov (PINNED versions)
RUN pip install --no-cache-dir semgrep==1.100.0 checkov==3.2.336

# Install gitleaks (PINNED v8.21.2)
RUN curl -sfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz -o gitleaks.tar.gz \
    && tar -xzf gitleaks.tar.gz gitleaks \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks.tar.gz

# Copy application source
COPY agent/ ./agent/
COPY api/ ./api/

# Configure exact binary paths (bypassing toolchain PATH search)
# Python pip binaries go to /var/lang/bin in this base image.
ENV FIRST_COMMIT_GITLEAKS_BIN=/usr/local/bin/gitleaks
ENV FIRST_COMMIT_SEMGREP_BIN=/var/lang/bin/semgrep
ENV FIRST_COMMIT_CHECKOV_BIN=/var/lang/bin/checkov

# Hard lockdown to prevent telemetry and interactive output
ENV SEMGREP_SEND_METRICS=off
ENV CHECKOV_SKIP_MAPPING=true
ENV NO_COLOR=1

CMD ["api.handlers.pipeline_detect_handler"]
